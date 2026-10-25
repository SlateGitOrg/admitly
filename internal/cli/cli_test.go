package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(context.Background(), args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestUsageAndVersion(t *testing.T) {
	if code, _, stderr := runCLI(t); code != 2 || !strings.Contains(stderr, "Commands:") {
		t.Fatalf("no args: %d %s", code, stderr)
	}
	if code, _, _ := runCLI(t, "help"); code != 0 {
		t.Fatal("help should exit 0")
	}
	if code, _, stderr := runCLI(t, "frobnicate"); code != 2 || !strings.Contains(stderr, "unknown command") {
		t.Fatalf("unknown: %d %s", code, stderr)
	}
	if code, out, _ := runCLI(t, "version"); code != 0 || !strings.HasPrefix(out, "admitly ") {
		t.Fatalf("version: %d %q", code, out)
	}
	if code, _, _ := runCLI(t, "eval", "-h"); code != 0 {
		t.Fatal("-h should exit 0")
	}
	if code, _, _ := runCLI(t, "eval", "--nope"); code != 2 {
		t.Fatal("bad flag should exit 2")
	}
	if code, _, _ := runCLI(t, "serve"); code != 2 {
		t.Fatal("serve without --config should exit 2")
	}
}

func TestKeygenSignVerify(t *testing.T) {
	dir := t.TempDir()
	if code, out, stderr := runCLI(t, "keygen", "--out", dir); code != 0 || !strings.Contains(out, "key id sha256:") {
		t.Fatalf("keygen: %d %s %s", code, out, stderr)
	}
	if code, _, stderr := runCLI(t, "keygen", "--out", dir); code != 1 || !strings.Contains(stderr, "exists") {
		t.Fatalf("keygen twice must refuse: %d %s", code, stderr)
	}
	if st, _ := os.Stat(filepath.Join(dir, "cosign.key")); st.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode %v", st.Mode())
	}
	store := filepath.Join(dir, "store")
	img := "registry.lab.local/app@sha256:" + strings.Repeat("c", 64)
	if code, out, stderr := runCLI(t, "sign", "--key", filepath.Join(dir, "cosign.key"), "--store", store, img); code != 0 || !strings.Contains(out, "signed") {
		t.Fatalf("sign: %d %s %s", code, out, stderr)
	}
	code, out, _ := runCLI(t, "verify", "--key", filepath.Join(dir, "cosign.pub"), "--store", store, img,
		"registry.lab.local/app@sha256:"+strings.Repeat("d", 64), "BAD//ref")
	if code != 1 || !strings.Contains(out, "OK   registry.lab.local/app@") || strings.Count(out, "FAIL") != 2 {
		t.Fatalf("verify: %d %s", code, out)
	}
	for _, args := range [][]string{
		{"sign", "--store", store},
		{"sign", "--key", filepath.Join(dir, "missing"), "--store", store, img},
		{"sign", "--key", filepath.Join(dir, "cosign.pub"), "--store", store, img},
		{"sign", "--key", filepath.Join(dir, "cosign.key"), "--store", store, "nginx:latest"},
		{"verify", "--store", store},
		{"verify", "--key", filepath.Join(dir, "cosign.key"), "--store", store, img},
	} {
		if code, _, _ := runCLI(t, args...); code == 0 {
			t.Errorf("%v: want failure", args)
		}
	}
}

func TestCerts(t *testing.T) {
	dir := t.TempDir()
	if code, out, _ := runCLI(t, "certs", "--hosts", "127.0.0.1,admitly.svc", "--out", dir, "--days", "2"); code != 0 || !strings.Contains(out, "caBundle") {
		t.Fatalf("certs: %d %s", code, out)
	}
	for _, f := range []string{"ca.crt", "tls.crt", "tls.key"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Error(err)
		}
	}
	if code, _, _ := runCLI(t, "certs", "--hosts", "", "--out", dir); code != 2 {
		t.Fatal("empty hosts should be a usage error")
	}
}

func TestEvalManifests(t *testing.T) {
	manifests := filepath.Join("..", "..", "examples", "manifests", "pods.yaml")
	code, out, stderr := runCLI(t, "eval", manifests)
	if code != 1 {
		t.Fatalf("eval should exit 1 when something is denied: %d %s", code, stderr)
	}
	for _, want := range []string{
		"Pod shop/checkout (CREATE)", "validate: ALLOWED",
		"deny  [disallow-privileged] privileged containers are not allowed: shell",
		"deny  [disallow-privileged] sharing host namespaces is not allowed: hostPID",
		"Deployment shop/storefront (CREATE)", "memory limit above 4Gi: web",
		"4 object(s): 2 allowed, 2 denied",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n%s", want, out)
		}
	}
	if code, _, _ := runCLI(t, "eval", "--fail-on-deny=false", manifests); code != 0 {
		t.Fatal("--fail-on-deny=false should exit 0")
	}
	code, out, _ = runCLI(t, "eval", "--output", "json", "--no-mutate", "--operation", "update", "--fail-on-deny=false", manifests)
	if code != 0 {
		t.Fatal("json eval failed")
	}
	var reports []evalReport
	if err := json.Unmarshal([]byte(out), &reports); err != nil {
		t.Fatal(err)
	}
	if len(reports) != 4 || reports[0].Mutate != nil || !strings.Contains(reports[0].Object, "(UPDATE)") {
		t.Fatalf("reports = %+v", reports[0])
	}
}

func TestEvalWithStoreAndPolicies(t *testing.T) {
	dir := t.TempDir()
	runCLI(t, "keygen", "--out", dir)
	img := "registry.lab.local/shop/checkout@sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
	store := filepath.Join(dir, "store")
	runCLI(t, "sign", "--key", filepath.Join(dir, "cosign.key"), "--store", store, img)
	pol := filepath.Join(dir, "policies")
	_ = os.MkdirAll(pol, 0o755)
	data, _ := os.ReadFile(filepath.Join(dir, "cosign.pub"))
	_ = os.WriteFile(filepath.Join(pol, "cosign.pub"), data, 0o600)
	_ = os.WriteFile(filepath.Join(pol, "verify.yaml"), []byte(`apiVersion: admitly.dev/v1alpha1
kind: ImageVerificationPolicy
metadata: {name: verify-images}
spec:
  match: {resources: [{kinds: [Pod]}]}
  verification: {rules: [{images: ["registry.lab.local/**"], keyFiles: [cosign.pub]}]}
`), 0o600)
	manifests := filepath.Join("..", "..", "examples", "manifests", "pods.yaml")
	_, out, _ := runCLI(t, "eval", "--policies", pol, "--store", store, manifests)
	if !strings.Contains(out, "[verify-images] image signature verification failed: registry.lab.local/shop/unsigned@") {
		t.Fatalf("unsigned image not denied:\n%s", out)
	}
	if strings.Count(out, "verify-images") != 1 {
		t.Fatalf("signed image must verify:\n%s", out)
	}
	if code, out, _ := runCLI(t, "lint", "--store", store, pol); code != 0 || !strings.Contains(out, "7 policies compiled") {
		t.Fatalf("lint: %d %s", code, out)
	}
	if code, _, stderr := runCLI(t, "lint", pol); code != 1 || !strings.Contains(stderr, "no signature store") {
		t.Fatalf("lint without store: %d %s", code, stderr)
	}
	cfgPath := filepath.Join(dir, "admitly.yaml")
	_ = os.WriteFile(cfgPath, []byte("policies: {builtin: true, dirs: [policies]}\nsignatures: {storeDir: store}\n"), 0o600)
	if code, out, _ := runCLI(t, "lint", "--config", cfgPath); code != 0 || !strings.Contains(out, "7 policies compiled") {
		t.Fatalf("lint --config: %d %s", code, out)
	}
	_, out, _ = runCLI(t, "eval", "--config", cfgPath, "--fail-on-deny=false", manifests)
	if !strings.Contains(out, "4 object(s): 1 allowed, 3 denied") {
		t.Fatalf("eval --config:\n%s", out)
	}
}

func TestEvalInputErrors(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		_ = os.WriteFile(p, []byte(body), 0o600)
		return p
	}
	cases := map[string][]string{
		"no files":        {"eval"},
		"bad output":      {"eval", "--output", "xml", write("a.yaml", "apiVersion: v1\nkind: Pod\nmetadata: {name: a}\n")},
		"bad operation":   {"eval", "--operation", "DELETE", write("b.yaml", "apiVersion: v1\nkind: Pod\nmetadata: {name: a}\n")},
		"missing file":    {"eval", filepath.Join(dir, "nope.yaml")},
		"empty file":      {"eval", write("c.yaml", "---\n")},
		"no kind":         {"eval", write("d.yaml", "metadata: {name: x}\n")},
		"bad yaml":        {"eval", write("e.yaml", "kind: [\n")},
		"bad review":      {"eval", write("f.json", `{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview"}`)},
		"bad policy dir":  {"eval", "--policies", filepath.Join(dir, "none"), write("g.yaml", "apiVersion: v1\nkind: Pod\nmetadata: {name: a}\n")},
		"bad config":      {"eval", "--config", filepath.Join(dir, "none.yaml"), write("h.yaml", "apiVersion: v1\nkind: Pod\nmetadata: {name: a}\n")},
		"bench bad flags": {"bench", "--requests", "0"},
	}
	for name, args := range cases {
		if code, _, _ := runCLI(t, args...); code == 0 {
			t.Errorf("%s: want non-zero exit", name)
		}
	}
}

func TestBenchSmall(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "bench.json")
	code, stdout, stderr := runCLI(t, "bench", "--requests", "20", "--concurrency", "2", "--warmup", "5", "--json", out)
	if code != 0 {
		t.Fatalf("bench: %d %s", code, stderr)
	}
	if !strings.Contains(stdout, "p99") || !strings.Contains(stdout, "pod securityContext defaults") {
		t.Fatalf("bench output:\n%s", stdout)
	}
	data, err := os.ReadFile(out)
	if err != nil || !strings.Contains(string(data), `"scenarios"`) {
		t.Fatalf("bench json: %v %s", err, data)
	}
}

func TestServeStartsAndStops(t *testing.T) {
	dir := t.TempDir()
	runCLI(t, "certs", "--hosts", "127.0.0.1", "--out", filepath.Join(dir, "certs"))
	cfg := filepath.Join(dir, "admitly.yaml")
	_ = os.WriteFile(cfg, []byte("listen: 127.0.0.1:0\ntls: {certFile: certs/tls.crt, keyFile: certs/tls.key}\naudit: {file: ''}\nlogLevel: warn\n"), 0o600)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	var out, errOut bytes.Buffer
	if code := run(ctx, []string{"serve", "--config", cfg}, &out, &errOut); code != 0 {
		t.Fatalf("serve exit %d: %s", code, errOut.String())
	}
	if code := run(context.Background(), []string{"serve", "--config", cfg, "--listen", "256.0.0.1:1"}, &out, &errOut); code != 1 {
		t.Fatal("bad listen address must fail")
	}
	if code := run(context.Background(), []string{"serve", "--config", filepath.Join(dir, "none")}, &out, &errOut); code != 1 {
		t.Fatal("missing config must fail")
	}
	if newLogger("debug", &out) == nil || newLogger("error", &out) == nil || newLogger("warn", &out) == nil {
		t.Fatal("logger")
	}
}
