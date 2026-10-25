// Package bench measures end-to-end admission latency: an in-process admitly
// server with the built-in policies plus signature verification, served over
// real TLS on loopback, driven by concurrent HTTPS clients.
package bench

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"time"

	admissionv1 "k8s.io/api/admission/v1"

	"github.com/SlateGitOrg/admitly/internal/config"
	"github.com/SlateGitOrg/admitly/internal/imageref"
	"github.com/SlateGitOrg/admitly/internal/server"
	"github.com/SlateGitOrg/admitly/internal/signature"
	"github.com/SlateGitOrg/admitly/internal/tlsutil"
)

// Options control a benchmark run.
type Options struct {
	Requests    int // per scenario
	Concurrency int
	Warmup      int // per scenario, not measured
}

// Stats summarises one scenario.
type Stats struct {
	Scenario   string        `json:"scenario"`
	Endpoint   string        `json:"endpoint"`
	Requests   int           `json:"requests"`
	Allowed    bool          `json:"allowed"`
	P50        time.Duration `json:"p50"`
	P90        time.Duration `json:"p90"`
	P99        time.Duration `json:"p99"`
	Max        time.Duration `json:"max"`
	Mean       time.Duration `json:"mean"`
	Throughput float64       `json:"requestsPerSecond"`
}

// Report is the result of Run.
type Report struct {
	GoVersion   string  `json:"goVersion"`
	GOOS        string  `json:"goos"`
	GOARCH      string  `json:"goarch"`
	CPUs        int     `json:"cpus"`
	Concurrency int     `json:"concurrency"`
	Policies    int     `json:"policies"`
	Scenarios   []Stats `json:"scenarios"`
}

const (
	digest      = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	signedImage = "registry.lab.local/team/web@" + digest
)

type scenario struct {
	name, endpoint string
	body           []byte
	wantAllowed    bool
	wantPatch      bool
}

// Run starts a server, runs every scenario and shuts the server down.
func Run(ctx context.Context, opts Options) (*Report, error) {
	if opts.Requests <= 0 || opts.Concurrency <= 0 {
		return nil, errors.New("requests and concurrency must be positive")
	}
	dir, err := os.MkdirTemp("", "admitly-bench-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()

	cfg, bundle, err := setup(dir)
	if err != nil {
		return nil, err
	}
	srv, err := server.New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		return nil, err
	}
	defer func() { _ = srv.Close() }()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	runCtx, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- srv.Run(runCtx, ln) }()
	defer func() {
		stop()
		<-done
	}()

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{RootCAs: bundle.CertPool(), MinVersion: tls.VersionTLS12},
			MaxIdleConnsPerHost: opts.Concurrency,
		},
	}
	base := "https://" + ln.Addr().String()
	rep := &Report{
		GoVersion: runtime.Version(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, CPUs: runtime.NumCPU(),
		Concurrency: opts.Concurrency, Policies: len(srv.Engine.PolicySet().Names),
	}
	for _, sc := range scenarios() {
		if _, err := drive(ctx, client, base, sc, opts.Warmup, opts.Concurrency); err != nil {
			return nil, fmt.Errorf("%s warmup: %w", sc.name, err)
		}
		st, err := drive(ctx, client, base, sc, opts.Requests, opts.Concurrency)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", sc.name, err)
		}
		rep.Scenarios = append(rep.Scenarios, st)
	}
	return rep, nil
}

func setup(dir string) (*config.Config, *tlsutil.Bundle, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	polDir := filepath.Join(dir, "policies")
	if err := os.MkdirAll(polDir, 0o750); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(filepath.Join(polDir, "cosign.pub"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		return nil, nil, err
	}
	verify := `apiVersion: admitly.dev/v1alpha1
kind: ImageVerificationPolicy
metadata: {name: verify-images}
spec:
  match: {resources: [{apiGroups: [""], kinds: [Pod]}]}
  verification:
    rules: [{images: ["registry.lab.local/**"], keyFiles: [cosign.pub]}]
`
	if err := os.WriteFile(filepath.Join(polDir, "verify.yaml"), []byte(verify), 0o600); err != nil {
		return nil, nil, err
	}
	ref, err := imageref.Parse(signedImage)
	if err != nil {
		return nil, nil, err
	}
	sig, err := signature.Sign(priv, ref, nil)
	if err != nil {
		return nil, nil, err
	}
	if err := (signature.DirStore{Root: filepath.Join(dir, "store")}).Put(ref, sig); err != nil {
		return nil, nil, err
	}
	bundle, err := tlsutil.GenerateServing([]string{"127.0.0.1"}, time.Hour)
	if err != nil {
		return nil, nil, err
	}
	if err := bundle.WriteServing(filepath.Join(dir, "certs")); err != nil {
		return nil, nil, err
	}
	cfgPath := filepath.Join(dir, "admitly.yaml")
	cfgYAML := `
tls: {certFile: certs/tls.crt, keyFile: certs/tls.key}
policies: {builtin: true, dirs: [policies], reloadInterval: 0s}
signatures: {storeDir: store}
audit: {file: ""}
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		return nil, nil, err
	}
	cfg, err := config.Load(cfgPath)
	return cfg, bundle, err
}

func container(name, image string, limits bool, sc map[string]any) map[string]any {
	c := map[string]any{"name": name, "image": image}
	if limits {
		c["resources"] = map[string]any{"limits": map[string]any{"cpu": "500m", "memory": "256Mi"}}
	}
	if sc != nil {
		c["securityContext"] = sc
	}
	return c
}

func review(uid string, obj map[string]any) []byte {
	apiVersion, _ := obj["apiVersion"].(string)
	group, version := "", apiVersion
	if i := bytes.IndexByte([]byte(apiVersion), '/'); i >= 0 {
		group, version = apiVersion[:i], apiVersion[i+1:]
	}
	kind, _ := obj["kind"].(string)
	meta, _ := obj["metadata"].(map[string]any)
	body, err := json.Marshal(map[string]any{
		"apiVersion": "admission.k8s.io/v1",
		"kind":       "AdmissionReview",
		"request": map[string]any{
			"uid":       uid,
			"kind":      map[string]any{"group": group, "version": version, "kind": kind},
			"resource":  map[string]any{"group": group, "version": version, "resource": "x"},
			"name":      meta["name"],
			"namespace": "shop",
			"operation": "CREATE",
			"userInfo":  map[string]any{"username": "bench"},
			"object":    obj,
		},
	})
	if err != nil {
		panic(err) // static, JSON-safe input
	}
	return body
}

func pod(name string, labels map[string]any, containers ...any) map[string]any {
	return map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": name, "namespace": "shop", "labels": labels},
		"spec":     map[string]any{"containers": containers},
	}
}

func scenarios() []scenario {
	labels := map[string]any{"app.kubernetes.io/name": "web", "team": "payments"}
	good := pod("web", labels, container("app", signedImage, true, nil), container("sidecar", signedImage, true, nil))
	bad := pod("bad", map[string]any{}, container("app", "docker.io/library/nginx:1.27", false, map[string]any{"privileged": true}))
	deploy := map[string]any{
		"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": map[string]any{"name": "web", "namespace": "shop", "labels": labels},
		"spec": map[string]any{"template": map[string]any{
			"metadata": map[string]any{"labels": labels},
			"spec":     map[string]any{"containers": []any{container("app", signedImage, true, nil)}},
		}},
	}
	return []scenario{
		{"compliant pod (6 policies incl. signature)", "validate", review("b-1", good), true, false},
		{"violating pod (5 policies deny)", "validate", review("b-2", bad), false, false},
		{"deployment template", "validate", review("b-3", deploy), true, false},
		{"pod securityContext defaults", "mutate", review("b-4", good), true, true},
	}
}

// drive sends n requests with c workers and returns latency statistics.
func drive(ctx context.Context, client *http.Client, base string, sc scenario, n, c int) (Stats, error) {
	st := Stats{Scenario: sc.name, Endpoint: sc.endpoint, Requests: n, Allowed: sc.wantAllowed}
	if n == 0 {
		return st, nil
	}
	lat := make([]time.Duration, n)
	jobs := make(chan int)
	var (
		wg       sync.WaitGroup
		once     sync.Once
		firstErr error
	)
	start := time.Now()
	for range c {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				t0 := time.Now()
				err := call(ctx, client, base+"/"+sc.endpoint, sc)
				lat[i] = time.Since(t0)
				if err != nil {
					once.Do(func() { firstErr = err })
				}
			}
		}()
	}
	for i := range n {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	wall := time.Since(start)
	if firstErr != nil {
		return st, firstErr
	}
	slices.Sort(lat)
	var sum time.Duration
	for _, d := range lat {
		sum += d
	}
	st.P50, st.P90, st.P99 = percentile(lat, 0.50), percentile(lat, 0.90), percentile(lat, 0.99)
	st.Max = lat[len(lat)-1]
	st.Mean = sum / time.Duration(n)
	st.Throughput = float64(n) / wall.Seconds()
	return st, nil
}

// percentile uses the nearest-rank method on a sorted slice.
func percentile(sorted []time.Duration, p float64) time.Duration {
	rank := int(p*float64(len(sorted))+0.999999) - 1
	rank = max(0, min(rank, len(sorted)-1))
	return sorted[rank]
}

func call(ctx context.Context, client *http.Client, url string, sc scenario) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url+"?timeout=10s", bytes.NewReader(sc.body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, raw)
	}
	var out admissionv1.AdmissionReview
	if err := json.Unmarshal(raw, &out); err != nil {
		return err
	}
	if out.Response.Allowed != sc.wantAllowed || (len(out.Response.Patch) > 0) != sc.wantPatch {
		return fmt.Errorf("unexpected decision: allowed=%v patch=%dB", out.Response.Allowed, len(out.Response.Patch))
	}
	return nil
}

// Print writes a human-readable table.
func (r *Report) Print(w io.Writer) {
	fmt.Fprintf(w, "admitly end-to-end latency (HTTPS on loopback, %d policies, concurrency %d)\n", r.Policies, r.Concurrency)
	fmt.Fprintf(w, "%s %s/%s, %d CPUs\n\n", r.GoVersion, r.GOOS, r.GOARCH, r.CPUs)
	fmt.Fprintf(w, "%-44s %-8s %7s %9s %9s %9s %9s %10s\n", "scenario", "endpoint", "n", "p50", "p90", "p99", "max", "req/s")
	for _, s := range r.Scenarios {
		fmt.Fprintf(w, "%-44s %-8s %7d %9s %9s %9s %9s %10.0f\n", s.Scenario, s.Endpoint, s.Requests,
			round(s.P50), round(s.P90), round(s.P99), round(s.Max), s.Throughput)
	}
}

func round(d time.Duration) string {
	return d.Round(time.Microsecond).String()
}
