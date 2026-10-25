package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admission/v1"

	"github.com/SlateGitOrg/admitly/internal/admission"
	"github.com/SlateGitOrg/admitly/internal/audit"
	"github.com/SlateGitOrg/admitly/internal/config"
	"github.com/SlateGitOrg/admitly/internal/tlsutil"
)

func goldenRequest(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "golden", name+".request.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func post(t *testing.T, client *http.Client, url string, body []byte) (*admissionv1.AdmissionReview, int, string) {
	t.Helper()
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, string(raw)
	}
	var r admissionv1.AdmissionReview
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	return &r, resp.StatusCode, string(raw)
}

const slowPolicy = `apiVersion: admitly.dev/v1alpha1
kind: ValidationPolicy
metadata: {name: slow}
spec:
  match: {resources: [{kinds: [Pod]}]}
  validations:
    - expression: lists.range(4000).all(i, lists.range(4000).all(j, i + j >= 0))
`

// slowConfig returns a config whose only policy takes far longer than the
// configured timeout, to exercise the global failure mode.
func slowConfig(t *testing.T, mode admission.FailureMode) *config.Config {
	t.Helper()
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "slow.yaml"), []byte(slowPolicy))
	cfg, err := config.Parse([]byte(`
failureMode: ` + string(mode) + `
timeout: 50ms
cel: {costLimit: 100000000000}
policies: {builtin: false, dirs: [` + dir + `], reloadInterval: 0s}
`))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestFailClosedAndFailOpenOnDeadline(t *testing.T) {
	for _, mode := range []admission.FailureMode{admission.FailClosed, admission.FailOpen} {
		t.Run(string(mode), func(t *testing.T) {
			srv := httptest.NewServer(newServer(t, slowConfig(t, mode)).Mux)
			defer srv.Close()
			start := time.Now()
			r, code, body := post(t, srv.Client(), srv.URL+"/validate", goldenRequest(t, "validate-compliant-pod"))
			if code != http.StatusOK {
				t.Fatalf("HTTP %d %s", code, body)
			}
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Fatalf("deadline not enforced: took %v", elapsed)
			}
			resp := r.Response
			if resp.AuditAnnotations[admission.AnnotationFailure] == "" {
				t.Fatalf("missing failure annotation: %+v", resp)
			}
			switch mode {
			case admission.FailClosed:
				if resp.Allowed || resp.Result == nil || resp.Result.Code != 500 || !strings.Contains(resp.Result.Message, "failureMode=Closed") {
					t.Fatalf("fail-closed response wrong: %+v %+v", resp, resp.Result)
				}
			case admission.FailOpen:
				if !resp.Allowed || len(resp.Warnings) != 1 || !strings.Contains(resp.Warnings[0], "failureMode=Open") {
					t.Fatalf("fail-open response wrong: %+v", resp)
				}
			}
		})
	}
}

func TestAPIServerTimeoutParameterShortensDeadline(t *testing.T) {
	cfg := slowConfig(t, admission.FailClosed)
	cfg.Timeout.Duration = 20 * time.Second
	srv := httptest.NewServer(newServer(t, cfg).Mux)
	defer srv.Close()
	start := time.Now()
	r, _, _ := post(t, srv.Client(), srv.URL+"/validate?timeout=100ms", goldenRequest(t, "validate-compliant-pod"))
	if time.Since(start) > 3*time.Second {
		t.Fatalf("?timeout= was not honoured: %v", time.Since(start))
	}
	if r.Response.Allowed {
		t.Fatal("fail-closed request must be denied")
	}
}

func TestUndecodableObjectUsesFailureMode(t *testing.T) {
	for _, mode := range []admission.FailureMode{admission.FailClosed, admission.FailOpen} {
		cfg, _ := fixture(t)
		cfg.FailureMode = mode
		srv := httptest.NewServer(newServer(t, cfg).Mux)
		var review map[string]any
		_ = json.Unmarshal(goldenRequest(t, "validate-compliant-pod"), &review)
		review["request"].(map[string]any)["object"] = []any{1, 2}
		body, _ := json.Marshal(review)
		r, code, raw := post(t, srv.Client(), srv.URL+"/validate", body)
		srv.Close()
		if code != http.StatusOK {
			t.Fatalf("%s: HTTP %d %s", mode, code, raw)
		}
		if r.Response.Allowed != (mode == admission.FailOpen) {
			t.Fatalf("%s: allowed=%v", mode, r.Response.Allowed)
		}
		if !strings.Contains(r.Response.AuditAnnotations[admission.AnnotationFailure], "undecodable") {
			t.Fatalf("%s: annotations %v", mode, r.Response.AuditAnnotations)
		}
	}
}

func TestHTTPErrors(t *testing.T) {
	cfg, _ := fixture(t)
	cfg.MaxRequestBytes = 4096
	srv := httptest.NewServer(newServer(t, cfg).Mux)
	defer srv.Close()
	c := srv.Client()

	do := func(method, path, ctype string, body []byte) (int, string) {
		req, _ := http.NewRequest(method, srv.URL+path, bytes.NewReader(body))
		if ctype != "" {
			req.Header.Set("Content-Type", ctype)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(raw)
	}
	review := goldenRequest(t, "validate-compliant-pod")
	cases := []struct {
		name, method, path, ctype string
		body                      []byte
		want                      int
	}{
		{"ok", "POST", "/validate", "application/json", review, 200},
		{"charset ok", "POST", "/mutate", "application/json; charset=utf-8", review, 200},
		{"wrong content type", "POST", "/validate", "text/plain", review, 415},
		{"no content type", "POST", "/validate", "", review, 415},
		{"bad json", "POST", "/validate", "application/json", []byte("{"), 400},
		{"v1beta1", "POST", "/validate", "application/json", bytes.Replace(review, []byte("admission.k8s.io/v1"), []byte("admission.k8s.io/v1beta1"), 1), 400},
		{"missing request", "POST", "/validate", "application/json", []byte(`{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview"}`), 400},
		{"missing uid", "POST", "/validate", "application/json", bytes.Replace(review, []byte(`"uid": "11111111-0000-0000-0000-000000000001"`), []byte(`"uid": ""`), 1), 400},
		{"too large", "POST", "/validate", "application/json", append(bytes.Repeat([]byte(" "), 5000), review...), 413},
		{"get validate", "GET", "/validate", "", nil, 405},
		{"healthz", "GET", "/healthz", "", nil, 200},
		{"readyz", "GET", "/readyz", "", nil, 200},
		{"unknown", "GET", "/nope", "", nil, 404},
	}
	for _, tc := range cases {
		if code, body := do(tc.method, tc.path, tc.ctype, tc.body); code != tc.want {
			t.Errorf("%s: HTTP %d, want %d (%s)", tc.name, code, tc.want, body)
		}
	}
	code, metrics := do("GET", "/metrics", "", nil)
	if code != 200 {
		t.Fatalf("metrics HTTP %d", code)
	}
	for _, want := range []string{
		`admitly_admission_requests_total{decision="allowed",endpoint="validate"} 1`,
		`admitly_bad_requests_total{reason="content_type"} 2`,
		`admitly_bad_requests_total{reason="too_large"} 1`,
		`admitly_policy_set_generation 1`,
		`admitly_policy_evaluations_total{outcome="mutated",policy="default-security-context"} 1`,
	} {
		if !strings.Contains(metrics, want) {
			t.Errorf("metrics missing %q", want)
		}
	}
}

func TestAuditLogRecords(t *testing.T) {
	cfg, dir := fixture(t)
	s := newServer(t, cfg)
	srv := httptest.NewServer(s.Mux)
	post(t, srv.Client(), srv.URL+"/validate", goldenRequest(t, "validate-privileged-pod"))
	post(t, srv.Client(), srv.URL+"/validate", goldenRequest(t, "validate-audit-latest-tag"))
	post(t, srv.Client(), srv.URL+"/mutate", goldenRequest(t, "mutate-pod-defaults"))
	srv.Close()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var recs []audit.Record
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var r audit.Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		recs = append(recs, r)
	}
	if len(recs) != 3 {
		t.Fatalf("got %d records", len(recs))
	}
	if recs[0].Decision != admission.DecisionDenied || recs[0].Allowed || len(recs[0].Violations) != 1 || recs[0].User != "alice@lab.local" {
		t.Errorf("record 0: %+v", recs[0])
	}
	if recs[1].Decision != admission.DecisionAllowed || len(recs[1].Violations) != 1 || recs[1].Violations[0].Mode != "Audit" {
		t.Errorf("record 1: %+v", recs[1])
	}
	if recs[2].Endpoint != "mutate" || recs[2].PatchOps != 3 || recs[2].Time.IsZero() {
		t.Errorf("record 2: %+v", recs[2])
	}
}

func TestPolicyHotReload(t *testing.T) {
	cfg, dir := fixture(t)
	s := newServer(t, cfg)
	gen := s.Engine.PolicySet().Generation
	if changed, err := s.Reload(false); err != nil || changed {
		t.Fatalf("unchanged sources reloaded: %v %v", changed, err)
	}
	polDir := filepath.Join(dir, "policies")
	mustWrite(t, filepath.Join(polDir, "extra.yaml"), []byte(strings.Replace(slowPolicy, "name: slow", "name: extra", 1)))
	if changed, err := s.Reload(false); err != nil || !changed {
		t.Fatalf("new file not picked up: %v %v", changed, err)
	}
	if s.Engine.PolicySet().Generation != gen+1 {
		t.Fatal("generation not bumped")
	}
	mustWrite(t, filepath.Join(polDir, "broken.yaml"), []byte(strings.Replace(slowPolicy, "lists.range", "nosuchfn", 1)))
	if _, err := s.Reload(false); err == nil {
		t.Fatal("broken policy must fail to load")
	}
	if s.Engine.PolicySet().Generation != gen+1 {
		t.Fatal("failed reload must keep the previous set")
	}
	if changed, err := s.Reload(false); err != nil || changed {
		t.Fatalf("a broken fingerprint must not be retried every tick: %v %v", changed, err)
	}
	if err := os.Remove(filepath.Join(polDir, "broken.yaml")); err != nil {
		t.Fatal(err)
	}
	if changed, err := s.Reload(false); err != nil || !changed {
		t.Fatalf("recovery reload: %v %v", changed, err)
	}
}

func TestNewFailsOnBrokenPolicies(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "bad.yaml"), []byte(strings.Replace(slowPolicy, "lists.range", "nosuchfn", 1)))
	cfg, err := config.Parse([]byte("policies: {builtin: false, dirs: [" + dir + "]}\naudit: {file: " + filepath.Join(dir, "a.log") + "}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(cfg, quietLogger()); err == nil {
		t.Fatal("want error")
	}
	cfg, _ = config.Parse([]byte("audit: {file: " + filepath.Join(dir, "missing", "a.log") + "}\n"))
	if _, err := New(cfg, quietLogger()); err == nil {
		t.Fatal("want audit open error")
	}
}

// tlsFixture writes a serving certificate for 127.0.0.1 into dir.
func tlsFixture(t *testing.T, dir string) *tlsutil.Bundle {
	t.Helper()
	b, err := tlsutil.GenerateServing([]string{"127.0.0.1", "localhost"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.WriteServing(filepath.Join(dir, "certs")); err != nil {
		t.Fatal(err)
	}
	return b
}

func runTLS(t *testing.T, s *Server) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, ln) }()
	return "https://" + ln.Addr().String(), func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	}
}

func TestServeTLSAndMTLS(t *testing.T) {
	cfg, dir := fixture(t)
	bundle := tlsFixture(t, dir)
	cfg.TLS.CertFile = filepath.Join(dir, "certs", "tls.crt")
	cfg.TLS.KeyFile = filepath.Join(dir, "certs", "tls.key")
	cfg.Policies.ReloadInterval.Duration = 50 * time.Millisecond
	url, stop := runTLS(t, newServer(t, cfg))

	trusting := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: bundle.CertPool(), MinVersion: tls.VersionTLS12}}}
	r, code, body := post(t, trusting, url+"/validate", goldenRequest(t, "validate-privileged-pod"))
	if code != 200 || r.Response.Allowed {
		t.Fatalf("HTTPS validate: %d %s", code, body)
	}
	untrusting := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}}
	if resp, err := untrusting.Get(url + "/healthz"); err == nil {
		_ = resp.Body.Close()
		t.Fatal("client without the CA must fail TLS verification")
	}
	stop()

	// Mutual TLS: the server requires a client certificate signed by its client CA.
	clientCA, err := tlsutil.GenerateCA("apiserver-client-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	clientCert, err := clientCA.Issue("kube-apiserver", nil, true, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(dir, "client-ca.crt"), clientCA.CACert)
	cfg.TLS.ClientCAFile = filepath.Join(dir, "client-ca.crt")
	url, stop = runTLS(t, newServer(t, cfg))
	defer stop()
	if resp, err := trusting.Get(url + "/healthz"); err == nil {
		_ = resp.Body.Close()
		t.Fatal("mTLS server must reject a client without a certificate")
	}
	pair, err := clientCert.TLSCertificate()
	if err != nil {
		t.Fatal(err)
	}
	withCert := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: bundle.CertPool(), Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12,
	}}}
	resp, err := withCert.Get(url + "/healthz")
	if err != nil {
		t.Fatalf("mTLS client rejected: %v", err)
	}
	_ = resp.Body.Close()
}

func TestRunFailsWithoutCertificates(t *testing.T) {
	cfg, dir := fixture(t)
	cfg.TLS.CertFile = filepath.Join(dir, "missing.crt")
	cfg.TLS.KeyFile = filepath.Join(dir, "missing.key")
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer func() { _ = ln.Close() }()
	if err := newServer(t, cfg).Run(context.Background(), ln); err == nil {
		t.Fatal("want TLS load error")
	}
	cfg.TLS.CertFile, cfg.TLS.KeyFile = "", ""
	tlsFixture(t, dir)
	cfg.TLS.CertFile = filepath.Join(dir, "certs", "tls.crt")
	cfg.TLS.KeyFile = filepath.Join(dir, "certs", "tls.key")
	cfg.TLS.ClientCAFile = filepath.Join(dir, "certs", "tls.key") // not a certificate
	if err := newServer(t, cfg).Run(context.Background(), ln); err == nil || errors.Is(err, net.ErrClosed) {
		t.Fatalf("want client CA error, got %v", err)
	}
}
