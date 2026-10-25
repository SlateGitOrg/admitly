package policy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SlateGitOrg/admitly/policies"
)

const validDoc = `
apiVersion: admitly.dev/v1alpha1
kind: ValidationPolicy
metadata:
  name: p1
spec:
  match:
    resources:
      - kinds: [Pod]
  validations:
    - expression: "true"
`

func TestParseMultiDoc(t *testing.T) {
	data := validDoc + "\n---\n# comment only\n---\n" + strings.Replace(validDoc, "name: p1", "name: p2", 1)
	ps, err := Parse([]byte(data), "test.yaml", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 2 || ps[0].Metadata.Name != "p1" || ps[1].Metadata.Name != "p2" {
		t.Fatalf("got %d policies", len(ps))
	}
	if ps[0].Source != "test.yaml" || ps[0].EffectiveMode() != ModeEnforce || ps[0].EffectiveFailurePolicy() != FailurePolicyFail {
		t.Fatalf("defaults wrong: %+v", ps[0])
	}
}

func TestParseJSON(t *testing.T) {
	doc := `{"apiVersion":"admitly.dev/v1alpha1","kind":"ValidationPolicy","metadata":{"name":"j"},
	"spec":{"mode":"Audit","failurePolicy":"Ignore","match":{"resources":[{"kinds":["Pod"]}]},"validations":[{"expression":"true"}]}}`
	ps, err := Parse([]byte(doc), "x.json", "")
	if err != nil {
		t.Fatal(err)
	}
	if ps[0].EffectiveMode() != ModeAudit || ps[0].EffectiveFailurePolicy() != FailurePolicyIgnore {
		t.Fatalf("got %+v", ps[0].Spec)
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"unknown field":      strings.Replace(validDoc, "  validations:", "  bogus: 1\n  validations:", 1),
		"bad apiVersion":     strings.Replace(validDoc, "v1alpha1", "v9", 1),
		"bad kind":           strings.Replace(validDoc, "kind: ValidationPolicy", "kind: Nope", 1),
		"bad name":           strings.Replace(validDoc, "name: p1", "name: Bad_Name", 1),
		"bad mode":           strings.Replace(validDoc, "spec:\n", "spec:\n  mode: Loud\n", 1),
		"bad failurePolicy":  strings.Replace(validDoc, "spec:\n", "spec:\n  failurePolicy: Maybe\n", 1),
		"no resources":       strings.Replace(validDoc, "      - kinds: [Pod]\n", "", 1),
		"empty kinds":        strings.Replace(validDoc, "kinds: [Pod]", "kinds: []", 1),
		"bad operation":      strings.Replace(validDoc, "kinds: [Pod]", "kinds: [Pod]\n        operations: [PATCH]", 1),
		"no validations":     strings.Replace(validDoc, "  validations:\n    - expression: \"true\"\n", "", 1),
		"empty expression":   strings.Replace(validDoc, `expression: "true"`, `expression: " "`, 1),
		"bad reason":         strings.Replace(validDoc, `expression: "true"`, "expression: \"true\"\n      reason: Teapot", 1),
		"bad variable name":  strings.Replace(validDoc, "  validations:", "  variables:\n    - name: 1x\n      expression: '1'\n  validations:", 1),
		"dup variable":       strings.Replace(validDoc, "  validations:", "  variables:\n    - {name: a, expression: '1'}\n    - {name: a, expression: '2'}\n  validations:", 1),
		"mutation on valid.": strings.Replace(validDoc, "  validations:", "  mutation:\n    podSecurityContext: {runAsNonRoot: true}\n  validations:", 1),
		"malformed yaml":     "apiVersion: [",
	}
	for name, doc := range cases {
		if _, err := Parse([]byte(doc), name, ""); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestMutationValidation(t *testing.T) {
	base := `
apiVersion: admitly.dev/v1alpha1
kind: MutationPolicy
metadata: {name: m}
spec:
  match: {resources: [{kinds: [Pod]}]}
`
	ok := base + "  mutation:\n    podSecurityContext: {runAsNonRoot: true}\n    containerSecurityContext: {capabilities: {drop: [ALL]}}\n"
	if _, err := Parse([]byte(ok), "m", ""); err != nil {
		t.Fatalf("valid mutation rejected: %v", err)
	}
	for name, doc := range map[string]string{
		"typo field":   base + "  mutation:\n    podSecurityContext: {runAsNonroot: true}\n",
		"wrong type":   base + "  mutation:\n    containerSecurityContext: {privileged: \"yes\"}\n",
		"empty":        base + "  mutation: {}\n",
		"missing":      base,
		"audit mode":   strings.Replace(ok, "spec:\n", "spec:\n  mode: Audit\n", 1),
		"validations":  ok + "  validations: [{expression: 'true'}]\n",
		"verification": ok + "  verification: {rules: []}\n",
	} {
		if _, err := Parse([]byte(doc), name, ""); !errors.Is(err, ErrInvalidPolicy) {
			t.Errorf("%s: want ErrInvalidPolicy, got %v", name, err)
		}
	}
}

func TestVerificationKeyFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "k.pub"), []byte("PEMDATA"), 0o600); err != nil {
		t.Fatal(err)
	}
	doc := `
apiVersion: admitly.dev/v1alpha1
kind: ImageVerificationPolicy
metadata: {name: v}
spec:
  match: {resources: [{kinds: [Pod]}]}
  verification:
    rules:
      - images: ["registry.lab.local/**"]
        keyFiles: [k.pub]
`
	path := filepath.Join(dir, "v.yaml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	ps, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r := ps[0].Spec.Verification.Rules[0]
	if len(r.PublicKeys) != 1 || r.PublicKeys[0] != "PEMDATA" || r.KeyFiles != nil {
		t.Fatalf("key file not resolved: %+v", r)
	}
	if _, err := Parse([]byte(doc), "embedded", ""); err == nil {
		t.Error("keyFiles in embedded policy must fail")
	}
	missing := strings.Replace(doc, "k.pub", "nope.pub", 1)
	if _, err := Parse([]byte(missing), "m", dir); err == nil {
		t.Error("missing key file must fail")
	}
	for name, d := range map[string]string{
		"no rules":  strings.SplitAfter(doc, "  verification:\n")[0] + "    rules: []\n",
		"no images": strings.Replace(doc, `images: ["registry.lab.local/**"]`, "images: []", 1),
		"no keys":   strings.Replace(doc, "        keyFiles: [k.pub]\n", "", 1),
	} {
		if _, err := Parse([]byte(d), name, dir); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestLoadDirAndUnique(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("b.yaml", strings.Replace(validDoc, "name: p1", "name: b", 1))
	write("a.yml", strings.Replace(validDoc, "name: p1", "name: a", 1))
	write("README.md", "ignored")
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	ps, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 2 || ps[0].Metadata.Name != "a" {
		t.Fatalf("got %v", ps)
	}
	if err := CheckUnique(ps); err != nil {
		t.Fatal(err)
	}
	write("c.yaml", strings.Replace(validDoc, "name: p1", "name: a", 1))
	ps, _ = LoadDir(dir)
	if err := CheckUnique(ps); err == nil {
		t.Fatal("want duplicate error")
	}
	SortByName(ps)
	if ps[0].Metadata.Name != "a" || ps[2].Metadata.Name != "b" {
		t.Fatal("not sorted")
	}
	if _, err := LoadDir(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("want error for missing dir")
	}
	write("bad.yaml", "kind: [")
	if _, err := LoadDir(dir); err == nil {
		t.Fatal("want parse error")
	}
	if _, err := LoadFile(filepath.Join(dir, "nope.yaml")); err == nil {
		t.Fatal("want read error")
	}
}

func TestBuiltinPoliciesLoad(t *testing.T) {
	ps, err := LoadFS(policies.Builtin(), "builtin")
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckUnique(ps); err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, p := range ps {
		names[p.Metadata.Name] = true
	}
	for _, want := range []string{"disallow-privileged", "require-labels", "require-resource-limits", "registry-allowlist", "require-image-digest", "default-security-context"} {
		if !names[want] {
			t.Errorf("built-in %q missing", want)
		}
	}
}

func TestMatch(t *testing.T) {
	m := Match{
		Resources: []ResourceRule{
			{APIGroups: []string{""}, Kinds: []string{"Pod"}, Subresources: []string{"", "ephemeralcontainers"}},
			{APIGroups: []string{"apps"}, Kinds: []string{"Deployment"}, Operations: []string{"CREATE"}},
		},
		ExcludeNamespaces: []string{"kube-*"},
	}
	cases := []struct {
		r    Request
		want bool
	}{
		{Request{Group: "", Kind: "Pod", Operation: "CREATE", Namespace: "default"}, true},
		{Request{Group: "", Kind: "Pod", Operation: "update", Namespace: "default"}, true},
		{Request{Group: "", Kind: "Pod", Operation: "DELETE", Namespace: "default"}, false},
		{Request{Group: "", Kind: "Pod", Operation: "UPDATE", Namespace: "default", SubResource: "ephemeralcontainers"}, true},
		{Request{Group: "", Kind: "Pod", Operation: "UPDATE", Namespace: "default", SubResource: "status"}, false},
		{Request{Group: "", Kind: "Pod", Operation: "CREATE", Namespace: "kube-system"}, false},
		{Request{Group: "apps", Kind: "Deployment", Operation: "CREATE", Namespace: "x"}, true},
		{Request{Group: "apps", Kind: "Deployment", Operation: "UPDATE", Namespace: "x"}, false},
		{Request{Group: "extensions", Kind: "Deployment", Operation: "CREATE", Namespace: "x"}, false},
		{Request{Group: "", Kind: "Service", Operation: "CREATE", Namespace: "x"}, false},
	}
	for i, tc := range cases {
		if got := m.Matches(tc.r); got != tc.want {
			t.Errorf("case %d %+v: got %v want %v", i, tc.r, got, tc.want)
		}
	}
	ns := Match{Resources: []ResourceRule{{Kinds: []string{"*"}, Operations: []string{"*"}, Subresources: []string{"*"}}}, Namespaces: []string{"team-*"}}
	if !ns.Matches(Request{Group: "x", Kind: "Y", Operation: "DELETE", Namespace: "team-a", SubResource: "s"}) {
		t.Error("wildcards should match")
	}
	if ns.Matches(Request{Kind: "Y", Operation: "CREATE", Namespace: "other"}) {
		t.Error("namespace allow-list should not match")
	}
	if ns.Matches(Request{Kind: "Namespace", Operation: "CREATE"}) {
		t.Error("namespace allow-list must not match cluster-scoped objects")
	}
}
