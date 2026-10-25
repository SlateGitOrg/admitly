package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SlateGitOrg/admitly/internal/admission"
	"github.com/SlateGitOrg/admitly/internal/policy"
)

func TestDefaultsAndParse(t *testing.T) {
	cfg, err := Parse([]byte("listen: ':9443'\ntimeout: 2s\nfailureMode: Open\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":9443" || cfg.Timeout.Duration != 2*time.Second || cfg.FailureMode != admission.FailOpen {
		t.Fatalf("got %+v", cfg)
	}
	if !cfg.Policies.Builtin || cfg.MaxRequestBytes != 3<<20 || cfg.Signatures.CacheTTL.Duration != 5*time.Minute {
		t.Fatalf("defaults lost: %+v", cfg)
	}
	b, _ := cfg.Timeout.MarshalJSON()
	if string(b) != `"2s"` {
		t.Fatalf("marshal = %s", b)
	}
}

func TestParseErrors(t *testing.T) {
	for name, doc := range map[string]string{
		"unknown field":    "bogus: 1\n",
		"case mismatch":    "Listen: ':1'\n",
		"bad duration":     "timeout: soon\n",
		"numeric duration": "timeout: 5\n",
		"timeout too big":  "timeout: 1m\n",
		"bad failure mode": "failureMode: Sideways\n",
		"small body":       "maxRequestBytes: 10\n",
		"bad log level":    "logLevel: loud\n",
		"bad override":     "policies: {overrides: {x: {mode: Loud, failurePolicy: Maybe}}}\n",
		"bad yaml":         "listen: [\n",
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestLoadResolvesRelativePaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "admitly.yaml")
	if err := os.WriteFile(path, []byte("tls: {certFile: certs/tls.crt}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Resolve(cfg.TLS.CertFile); got != filepath.Join(dir, "certs", "tls.crt") {
		t.Fatalf("resolve = %s", got)
	}
	for _, p := range []string{"", "-", "/abs/x"} {
		if cfg.Resolve(p) != p {
			t.Errorf("Resolve(%q) changed", p)
		}
	}
	if _, err := Load(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Fatal("want read error")
	}
	if err := os.WriteFile(path, []byte("bogus: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("error should name the file: %v", err)
	}
}

func TestLoadPoliciesWithOverrides(t *testing.T) {
	cfg, err := Parse([]byte(`
policies:
  builtin: true
  overrides:
    registry-allowlist:
      mode: Audit
      params: {allowedImages: ["quay.io/**"]}
      excludeNamespaces: [ci]
    require-labels:
      mode: Disabled
      failurePolicy: Ignore
`))
	if err != nil {
		t.Fatal(err)
	}
	ps, fp, err := cfg.LoadPolicies()
	if err != nil {
		t.Fatal(err)
	}
	if fp == "" {
		t.Fatal("empty fingerprint")
	}
	byName := map[string]*policy.Policy{}
	for _, p := range ps {
		byName[p.Metadata.Name] = p
	}
	ra := byName["registry-allowlist"]
	if ra.EffectiveMode() != policy.ModeAudit || ra.Spec.Params["allowedImages"].([]any)[0] != "quay.io/**" {
		t.Fatalf("override not applied: %+v", ra.Spec)
	}
	if ex := ra.Spec.Match.ExcludeNamespaces; len(ex) != 2 || ex[1] != "ci" {
		t.Fatalf("excludeNamespaces = %v", ex)
	}
	if rl := byName["require-labels"]; rl.EffectiveMode() != policy.ModeDisabled || rl.EffectiveFailurePolicy() != policy.FailurePolicyIgnore {
		t.Fatalf("require-labels = %+v", rl.Spec)
	}
	fp2, err := cfg.Fingerprint()
	if err != nil || fp2 != fp {
		t.Fatalf("Fingerprint %q != LoadPolicies fingerprint %q (%v)", fp2, fp, err)
	}
}

func TestLoadPoliciesErrors(t *testing.T) {
	cfg, _ := Parse([]byte("policies: {overrides: {nope: {mode: Audit}}}\n"))
	if _, _, err := cfg.LoadPolicies(); err == nil || !strings.Contains(err.Error(), `no policy named "nope"`) {
		t.Fatalf("got %v", err)
	}
	cfg, _ = Parse([]byte("policies: {overrides: {default-security-context: {mode: Audit}}}\n"))
	if _, _, err := cfg.LoadPolicies(); err == nil {
		t.Fatal("Audit on a MutationPolicy must be rejected")
	}
	cfg, _ = Parse([]byte("policies: {builtin: false, dirs: [/nonexistent-admitly-dir]}\n"))
	if _, _, err := cfg.LoadPolicies(); err == nil {
		t.Fatal("missing dir must fail")
	}
	if _, err := cfg.Fingerprint(); err == nil {
		t.Fatal("missing dir must fail fingerprint")
	}
	dir := t.TempDir()
	doc := "apiVersion: admitly.dev/v1alpha1\nkind: ValidationPolicy\nmetadata: {name: require-labels}\nspec:\n  match: {resources: [{kinds: [Pod]}]}\n  validations: [{expression: 'true'}]\n"
	if err := os.WriteFile(filepath.Join(dir, "dup.yaml"), []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, _ = Parse([]byte("policies: {builtin: true, dirs: [" + dir + "]}\n"))
	if _, _, err := cfg.LoadPolicies(); err == nil {
		t.Fatal("duplicate with a built-in must fail")
	}
	if err := os.WriteFile(filepath.Join(dir, "dup.yaml"), []byte("kind: ["), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, _ = Parse([]byte("policies: {builtin: false, dirs: [" + dir + "]}\n"))
	if _, _, err := cfg.LoadPolicies(); err == nil {
		t.Fatal("parse error must surface")
	}
}
