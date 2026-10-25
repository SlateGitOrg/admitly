package engine

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"

	"github.com/archit2501/admitly/internal/imageref"
	"github.com/archit2501/admitly/internal/policy"
	"github.com/archit2501/admitly/internal/signature"
	"github.com/archit2501/admitly/policies"
)

const digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

var quietLog = slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))

func request(t testing.TB, op admissionv1.Operation, objYAML string) *admissionv1.AdmissionRequest {
	t.Helper()
	raw, err := yaml.YAMLToJSON([]byte(objYAML))
	if err != nil {
		t.Fatal(err)
	}
	var tm struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Metadata   struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
	}
	if err := yaml.Unmarshal(raw, &tm); err != nil {
		t.Fatal(err)
	}
	group, version, ok := strings.Cut(tm.APIVersion, "/")
	if !ok {
		group, version = "", tm.APIVersion
	}
	ns := tm.Metadata.Namespace
	if ns == "" {
		ns = "default"
	}
	req := &admissionv1.AdmissionRequest{
		UID:       "uid-1",
		Kind:      metav1.GroupVersionKind{Group: group, Version: version, Kind: tm.Kind},
		Resource:  metav1.GroupVersionResource{Group: group, Version: version, Resource: strings.ToLower(tm.Kind) + "s"},
		Name:      tm.Metadata.Name,
		Namespace: ns,
		Operation: op,
		UserInfo:  newUserInfo(),
	}
	if op == admissionv1.Delete {
		req.OldObject = runtime.RawExtension{Raw: raw}
	} else {
		req.Object = runtime.RawExtension{Raw: raw}
	}
	return req
}

func input(t *testing.T, op admissionv1.Operation, objYAML string) *Input {
	t.Helper()
	in, err := NewInput(request(t, op, objYAML))
	if err != nil {
		t.Fatal(err)
	}
	return in
}

func builtinEngine(t testing.TB, opts Options, extra ...*policy.Policy) *Engine {
	t.Helper()
	ps, err := policy.LoadFS(policies.Builtin(), "builtin")
	if err != nil {
		t.Fatal(err)
	}
	if opts.Logger == nil {
		opts.Logger = quietLog
	}
	e, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Load(append(ps, extra...)); err != nil {
		t.Fatal(err)
	}
	return e
}

func parsePolicy(t *testing.T, doc string) *policy.Policy {
	t.Helper()
	ps, err := policy.Parse([]byte(doc), "inline", "")
	if err != nil {
		t.Fatal(err)
	}
	return ps[0]
}

// goodPod complies with every built-in policy.
const goodPod = `
apiVersion: v1
kind: Pod
metadata:
  name: web
  labels: {app.kubernetes.io/name: web, team: payments}
spec:
  containers:
    - name: app
      image: registry.lab.local/team/web@` + digest + `
      resources: {limits: {cpu: 500m, memory: 256Mi}}
`

func violationsByPolicy(r *Result) map[string][]string {
	out := map[string][]string{}
	for _, v := range r.Violations {
		out[v.Policy] = append(out[v.Policy], v.Message)
	}
	return out
}

func TestBuiltinValidationMatrix(t *testing.T) {
	e := builtinEngine(t, Options{})
	cases := []struct {
		name string
		op   admissionv1.Operation
		obj  string
		want map[string]string // policy -> message substring
	}{
		{"compliant pod", admissionv1.Create, goodPod, nil},
		{"privileged", admissionv1.Create, strings.Replace(goodPod, "      resources:", "      securityContext: {privileged: true}\n      resources:", 1),
			map[string]string{"disallow-privileged": "privileged containers are not allowed: app"}},
		{"host network", admissionv1.Create, strings.Replace(goodPod, "spec:\n", "spec:\n  hostNetwork: true\n  hostPID: true\n", 1),
			map[string]string{"disallow-privileged": "sharing host namespaces is not allowed: hostPID, hostNetwork"}},
		{"missing labels", admissionv1.Create, strings.Replace(goodPod, ", team: payments", "", 1),
			map[string]string{"require-labels": "missing required labels: team"}},
		{"empty label value", admissionv1.Create, strings.Replace(goodPod, "team: payments", "team: ''", 1),
			map[string]string{"require-labels": "missing required labels: team"}},
		{"no limits", admissionv1.Create, strings.Replace(goodPod, "      resources: {limits: {cpu: 500m, memory: 256Mi}}\n", "", 1),
			map[string]string{"require-resource-limits": "containers must set cpu and memory limits: app"}},
		{"over memory", admissionv1.Create, strings.Replace(goodPod, "256Mi", "8Gi", 1),
			map[string]string{"require-resource-limits": "memory limit above 4Gi: app"}},
		// Quantities whose milli-value overflows int64 must not wrap around
		// to a negative number and slip under maxMemory.
		{"over memory 10Pi", admissionv1.Create, strings.Replace(goodPod, "256Mi", "10Pi", 1),
			map[string]string{"require-resource-limits": "memory limit above 4Gi: app"}},
		{"over memory 9e18", admissionv1.Create, strings.Replace(goodPod, "256Mi", "\"9000000000000000000\"", 1),
			map[string]string{"require-resource-limits": "memory limit above 4Gi: app"}},
		{"over memory 8Ei", admissionv1.Create, strings.Replace(goodPod, "256Mi", "8Ei", 1),
			map[string]string{"require-resource-limits": "memory limit above 4Gi: app"}},
		{"memory exactly 4Gi", admissionv1.Create, strings.Replace(goodPod, "256Mi", "4Gi", 1), nil},
		{"bad registry", admissionv1.Create, strings.Replace(goodPod, "registry.lab.local/", "docker.io/", 1),
			map[string]string{"registry-allowlist": "images from unapproved registries: docker.io/team/web@"}},
		{"lookalike registry", admissionv1.Create, strings.Replace(goodPod, "registry.lab.local/", "registry.lab.local.evil.io/", 1),
			map[string]string{"registry-allowlist": "unapproved registries"}},
		{"unpinned", admissionv1.Create, strings.Replace(goodPod, "@"+digest, ":v1", 1),
			map[string]string{"require-image-digest": "images must be pinned by digest: registry.lab.local/team/web:v1"}},
		{"kube-system exempt", admissionv1.Create, strings.Replace(goodPod, "  name: web\n", "  name: web\n  namespace: kube-system\n", 1) + "      securityContext: {privileged: true}\n", nil},
		{"delete not matched", admissionv1.Delete, strings.Replace(goodPod, "registry.lab.local/", "docker.io/", 1), nil},
		{"service not matched", admissionv1.Create, "apiVersion: v1\nkind: Service\nmetadata: {name: s}\nspec: {}\n", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := e.Validate(context.Background(), input(t, tc.op, tc.obj))
			if err != nil {
				t.Fatal(err)
			}
			got := violationsByPolicy(res)
			if len(got) != len(tc.want) {
				t.Fatalf("violations = %v, want policies %v", got, tc.want)
			}
			for p, sub := range tc.want {
				msgs := got[p]
				if len(msgs) == 0 || !strings.Contains(strings.Join(msgs, "|"), sub) {
					t.Errorf("policy %s messages %v do not contain %q", p, msgs, sub)
				}
			}
		})
	}
}

func TestWorkloadKinds(t *testing.T) {
	e := builtinEngine(t, Options{})
	podTemplate := `
      metadata:
        labels: {app.kubernetes.io/name: web}
      spec:
        initContainers:
          - {name: init, image: busybox, securityContext: {privileged: true}}
        containers:
          - {name: app, image: "registry.lab.local/web@` + digest + `"}`
	deploy := "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: d\n  labels: {app.kubernetes.io/name: d, team: t}\nspec:\n  template:" + podTemplate + "\n"
	cron := "apiVersion: batch/v1\nkind: CronJob\nmetadata:\n  name: c\n  labels: {app.kubernetes.io/name: c, team: t}\nspec:\n  jobTemplate:\n    spec:\n      template:" +
		strings.ReplaceAll(podTemplate, "\n      ", "\n          ") + "\n"
	for name, obj := range map[string]string{"deployment": deploy, "cronjob": cron} {
		in := input(t, admissionv1.Create, obj)
		if in.PodSpec == nil {
			t.Fatalf("%s: pod spec not located", name)
		}
		res, err := e.Validate(context.Background(), in)
		if err != nil {
			t.Fatal(err)
		}
		got := violationsByPolicy(res)
		for _, p := range []string{"disallow-privileged", "registry-allowlist", "require-image-digest", "require-resource-limits"} {
			if len(got[p]) == 0 {
				t.Errorf("%s: expected violation from %s, got %v", name, p, got)
			}
		}
		if len(got["require-labels"]) != 0 {
			t.Errorf("%s: labels are on the workload itself and should pass: %v", name, got)
		}
	}
	wantPath := map[string]string{"deployment": "/spec/template/spec", "cronjob": "/spec/jobTemplate/spec/template/spec"}
	if in := input(t, admissionv1.Create, cron); in.PodSpecPath != wantPath["cronjob"] || in.PodMeta == nil {
		t.Errorf("cronjob path %q meta %v", in.PodSpecPath, in.PodMeta)
	}
	if in := input(t, admissionv1.Create, deploy); in.PodSpecPath != wantPath["deployment"] {
		t.Errorf("deployment path %q", in.PodSpecPath)
	}
	// A malformed workload (template is not an object) has no pod spec.
	bad := input(t, admissionv1.Create, "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: x}\nspec: {template: 3}\n")
	if bad.PodSpec != nil {
		t.Error("malformed template must yield nil pod spec")
	}
}

func TestEphemeralContainersSubresource(t *testing.T) {
	e := builtinEngine(t, Options{})
	pod := strings.Replace(goodPod, "spec:\n", "spec:\n  ephemeralContainers:\n    - {name: debug, image: busybox, securityContext: {privileged: true}}\n", 1)
	req := request(t, admissionv1.Update, pod)
	req.SubResource = "ephemeralcontainers"
	in, err := NewInput(req)
	if err != nil {
		t.Fatal(err)
	}
	res, err := e.Validate(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	got := violationsByPolicy(res)
	for _, p := range []string{"disallow-privileged", "registry-allowlist", "require-image-digest"} {
		if len(got[p]) == 0 {
			t.Errorf("debug container must be checked by %s: %v", p, got)
		}
	}
	if len(got["require-labels"]) != 0 || len(got["require-resource-limits"]) != 0 {
		t.Errorf("policies without the subresource must not match: %v", got)
	}
}

const failingPolicy = `
apiVersion: admitly.dev/v1alpha1
kind: ValidationPolicy
metadata: {name: broken}
spec:
  mode: MODE
  failurePolicy: FP
  match: {resources: [{kinds: [Pod]}]}
  validations:
    - expression: object.metadata.annotations["missing"] == "x"
`

func TestFailurePolicy(t *testing.T) {
	for _, tc := range []struct {
		mode, fp     string
		wantViolated bool
		wantIgnored  bool
		wantMode     policy.Mode
	}{
		{"Enforce", "Fail", true, false, policy.ModeEnforce},
		{"Audit", "Fail", true, false, policy.ModeAudit},
		{"Enforce", "Ignore", false, true, ""},
	} {
		doc := strings.NewReplacer("MODE", tc.mode, "FP", tc.fp).Replace(failingPolicy)
		e := builtinEngine(t, Options{}, parsePolicy(t, doc))
		res, err := e.Validate(context.Background(), input(t, admissionv1.Create, goodPod))
		if err != nil {
			t.Fatal(err)
		}
		vs := violationsByPolicy(res)["broken"]
		if (len(vs) > 0) != tc.wantViolated {
			t.Errorf("%s/%s: violations %v", tc.mode, tc.fp, vs)
		}
		if (len(res.Ignored) > 0) != tc.wantIgnored {
			t.Errorf("%s/%s: ignored %v", tc.mode, tc.fp, res.Ignored)
		}
		if tc.wantViolated {
			if !res.Violations[0].EvalError || res.Violations[0].Mode != tc.wantMode || res.Violations[0].Reason != "InternalError" {
				t.Errorf("%s/%s: bad violation %+v", tc.mode, tc.fp, res.Violations[0])
			}
			if (len(res.Enforced()) > 0) != (tc.wantMode == policy.ModeEnforce) || (len(res.Audited()) > 0) != (tc.wantMode == policy.ModeAudit) {
				t.Errorf("%s/%s: Enforced/Audited split wrong", tc.mode, tc.fp)
			}
		}
	}
}

func TestMatchConditionsVariablesAndMessages(t *testing.T) {
	doc := `
apiVersion: admitly.dev/v1alpha1
kind: ValidationPolicy
metadata: {name: custom}
spec:
  mode: Audit
  match: {resources: [{kinds: [Pod]}]}
  matchConditions:
    - name: notDryRun
      expression: '!request.dryRun'
    - name: notAdmin
      expression: '!("system:masters" in request.userInfo.groups)'
  params: {maxContainers: 1}
  variables:
    # "n" would be read by YAML 1.1 as the boolean false, hence "count".
    - {name: count, expression: size(containers)}
    - {name: tooMany, expression: variables.count > params.maxContainers}
  validations:
    - expression: '!variables.tooMany'
      messageExpression: '"too many containers: " + string(variables.count)'
    - expression: 'object.metadata.name != "web"'
      message: static message
    - expression: 'object.metadata.name.size() > 100'
    - expression: 'object.metadata.name.size() > 100'
      message: fallback used
      messageExpression: 'object.metadata.nope'
`
	e := builtinEngine(t, Options{}, parsePolicy(t, doc))
	two := strings.Replace(goodPod, "  containers:\n", "  containers:\n    - {name: side, image: \"registry.lab.local/s@"+digest+"\", resources: {limits: {cpu: 1, memory: 1Mi}}}\n", 1)
	res, err := e.Validate(context.Background(), input(t, admissionv1.Create, two))
	if err != nil {
		t.Fatal(err)
	}
	got := violationsByPolicy(res)["custom"]
	want := []string{"too many containers: 2", "static message", "failed expression: object.metadata.name.size() > 100", "fallback used"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("messages = %q\nwant %q", got, want)
	}
	if len(res.Enforced()) != 0 || len(res.Audited()) != 4 {
		t.Fatalf("audit split wrong: %+v", res.Violations)
	}

	// Dry-run requests are excluded by the match condition.
	req := request(t, admissionv1.Create, two)
	dry := true
	req.DryRun = &dry
	in, _ := NewInput(req)
	res, _ = e.Validate(context.Background(), in)
	if len(violationsByPolicy(res)["custom"]) != 0 {
		t.Fatal("matchCondition should exclude dry-run")
	}
	for _, m := range res.Matched {
		if m == "custom" {
			t.Fatal("custom must not be reported as matched")
		}
	}
}

func TestMatchConditionError(t *testing.T) {
	doc := strings.Replace(failingPolicy, "  validations:", "  matchConditions:\n    - {name: boom, expression: 'object.nope == 1'}\n  validations:", 1)
	doc = strings.NewReplacer("MODE", "Enforce", "FP", "Fail").Replace(doc)
	e := builtinEngine(t, Options{}, parsePolicy(t, doc))
	res, _ := e.Validate(context.Background(), input(t, admissionv1.Create, goodPod))
	vs := violationsByPolicy(res)["broken"]
	if len(vs) != 1 || !strings.Contains(vs[0], `matchCondition "boom"`) {
		t.Fatalf("got %v", vs)
	}
}

func writeKey(t *testing.T, dir string) (*ecdsa.PrivateKey, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	path := filepath.Join(dir, "cosign.pub")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return k, path
}

func verifyPolicy(t *testing.T, dir, fp string) *policy.Policy {
	t.Helper()
	doc := `
apiVersion: admitly.dev/v1alpha1
kind: ImageVerificationPolicy
metadata: {name: verify-images}
spec:
  failurePolicy: ` + fp + `
  match: {resources: [{kinds: [Pod]}]}
  verification:
    rules:
      - images: ["registry.lab.local/**"]
        keyFiles: [cosign.pub]
`
	path := filepath.Join(dir, "verify.yaml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	ps, err := policy.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return ps[0]
}

func TestImageVerification(t *testing.T) {
	dir := t.TempDir()
	key, _ := writeKey(t, dir)
	store := signature.DirStore{Root: filepath.Join(dir, "store")}
	signed, _ := imageref.Parse("registry.lab.local/team/web@" + digest)
	sig, err := signature.Sign(key, signed, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(signed, sig); err != nil {
		t.Fatal(err)
	}
	e := builtinEngine(t, Options{Verifier: signature.NewVerifier(store, 16, time.Minute)}, verifyPolicy(t, dir, "Fail"))

	res, _ := e.Validate(context.Background(), input(t, admissionv1.Create, goodPod))
	if vs := violationsByPolicy(res)["verify-images"]; len(vs) != 0 {
		t.Fatalf("signed image rejected: %v", vs)
	}
	unsigned := strings.Replace(goodPod, "team/web@", "team/other@", 1)
	res, _ = e.Validate(context.Background(), input(t, admissionv1.Create, unsigned))
	if vs := violationsByPolicy(res)["verify-images"]; len(vs) != 1 || !strings.Contains(vs[0], "no signatures found") {
		t.Fatalf("unsigned image: %v", vs)
	}
	tagged := strings.Replace(goodPod, "@"+digest, ":v1", 1)
	res, _ = e.Validate(context.Background(), input(t, admissionv1.Create, tagged))
	if vs := violationsByPolicy(res)["verify-images"]; len(vs) != 1 || !strings.Contains(vs[0], "not pinned") {
		t.Fatalf("tagged image: %v", vs)
	}
	outOfScope := strings.Replace(goodPod, "registry.lab.local/", "quay.io/", 1)
	res, _ = e.Validate(context.Background(), input(t, admissionv1.Create, outOfScope))
	if vs := violationsByPolicy(res)["verify-images"]; len(vs) != 0 {
		t.Fatalf("image outside rule scope must be ignored: %v", vs)
	}
	invalid := strings.Replace(goodPod, "registry.lab.local/team/web@"+digest, "INVALID//", 1)
	res, _ = e.Validate(context.Background(), input(t, admissionv1.Create, invalid))
	if vs := violationsByPolicy(res)["verify-images"]; len(vs) != 1 || !strings.Contains(vs[0], "cannot be verified") {
		t.Fatalf("invalid image: %v", vs)
	}
}

func TestImageVerificationStoreFailure(t *testing.T) {
	for _, fp := range []string{"Fail", "Ignore"} {
		dir := t.TempDir()
		writeKey(t, dir)
		root := filepath.Join(dir, "store")
		ref, _ := imageref.Parse("registry.lab.local/team/web@" + digest)
		path, _ := signature.DirStore{Root: root}.Path(ref)
		_ = os.MkdirAll(filepath.Dir(path), 0o755)
		_ = os.WriteFile(path, []byte("{corrupt"), 0o600)
		e := builtinEngine(t, Options{Verifier: signature.NewVerifier(signature.DirStore{Root: root}, 0, 0)}, verifyPolicy(t, dir, fp))
		res, _ := e.Validate(context.Background(), input(t, admissionv1.Create, goodPod))
		vs := violationsByPolicy(res)["verify-images"]
		if fp == "Fail" && (len(vs) != 1 || !res.Violations[0].EvalError) {
			t.Errorf("Fail: want eval-error violation, got %+v", res.Violations)
		}
		if fp == "Ignore" && (len(vs) != 0 || len(res.Ignored) != 1) {
			t.Errorf("Ignore: want ignored error, got %+v / %+v", res.Violations, res.Ignored)
		}
	}
}

func TestVerificationNeedsStore(t *testing.T) {
	dir := t.TempDir()
	writeKey(t, dir)
	e, _ := New(Options{Logger: quietLog})
	if _, err := e.Load([]*policy.Policy{verifyPolicy(t, dir, "Fail")}); err == nil || !strings.Contains(err.Error(), "no signature store") {
		t.Fatalf("got %v", err)
	}
}

func TestMutate(t *testing.T) {
	e := builtinEngine(t, Options{})
	res, err := e.Mutate(context.Background(), input(t, admissionv1.Create, goodPod))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Patch) != 2 || res.Patch[0].Path != "/spec/securityContext" || res.Patch[1].Path != "/spec/containers/0/securityContext" {
		t.Fatalf("patch = %+v", res.Patch)
	}
	if len(res.Matched) != 1 || res.Matched[0] != "default-security-context" {
		t.Fatalf("matched = %v", res.Matched)
	}
	// UPDATE is not mutated by the built-in policy.
	res, _ = e.Mutate(context.Background(), input(t, admissionv1.Update, goodPod))
	if len(res.Patch) != 0 {
		t.Fatalf("update mutated: %+v", res.Patch)
	}
	// Non-workload kinds produce nothing.
	res, _ = e.Mutate(context.Background(), input(t, admissionv1.Create, "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c}\n"))
	if len(res.Patch) != 0 {
		t.Fatal("configmap mutated")
	}
}

func TestMutationPolicyMatchingNonPodKind(t *testing.T) {
	doc := `
apiVersion: admitly.dev/v1alpha1
kind: MutationPolicy
metadata: {name: everything}
spec:
  match: {resources: [{kinds: ["*"]}]}
  mutation:
    podSecurityContext: {runAsNonRoot: true}
`
	e, _ := New(Options{Logger: quietLog})
	if _, err := e.Load([]*policy.Policy{parsePolicy(t, doc)}); err != nil {
		t.Fatal(err)
	}
	res, err := e.Mutate(context.Background(), input(t, admissionv1.Create, "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c}\n"))
	if err != nil || len(res.Patch) != 0 || len(res.Violations) != 0 {
		t.Fatalf("got %+v %v", res, err)
	}
}

func TestIncompleteOnDeadline(t *testing.T) {
	e := builtinEngine(t, Options{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := e.Validate(ctx, input(t, admissionv1.Create, goodPod))
	if err != nil || !res.Incomplete {
		t.Fatalf("validate: %+v %v", res, err)
	}
	res, err = e.Mutate(ctx, input(t, admissionv1.Create, goodPod))
	if err != nil || !res.Incomplete {
		t.Fatalf("mutate: %+v %v", res, err)
	}
}

func TestSlowPolicyInterruptedByDeadline(t *testing.T) {
	doc := `
apiVersion: admitly.dev/v1alpha1
kind: ValidationPolicy
metadata: {name: slow}
spec:
  match: {resources: [{kinds: [Pod]}]}
  validations:
    - expression: lists.range(3000).all(i, lists.range(3000).all(j, i + j >= 0))
`
	e, _ := New(Options{Logger: quietLog, CostLimit: 1 << 62})
	if _, err := e.Load([]*policy.Policy{parsePolicy(t, doc)}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	res, err := e.Validate(ctx, input(t, admissionv1.Create, goodPod))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Incomplete || len(res.Violations) != 0 {
		t.Fatalf("deadline must mark the result incomplete, not blame the policy: %+v", res)
	}
}

func TestCostLimitIsPolicyError(t *testing.T) {
	doc := `
apiVersion: admitly.dev/v1alpha1
kind: ValidationPolicy
metadata: {name: costly}
spec:
  match: {resources: [{kinds: [Pod]}]}
  validations:
    - expression: lists.range(5000).all(i, i >= 0)
`
	e, _ := New(Options{Logger: quietLog, CostLimit: 10_000})
	if _, err := e.Load([]*policy.Policy{parsePolicy(t, doc)}); err != nil {
		t.Fatal(err)
	}
	res, _ := e.Validate(context.Background(), input(t, admissionv1.Create, goodPod))
	if len(res.Violations) != 1 || !strings.Contains(res.Violations[0].Message, "cost limit") {
		t.Fatalf("got %+v", res.Violations)
	}
}

func TestLoadErrorsAndGeneration(t *testing.T) {
	e := builtinEngine(t, Options{})
	gen := e.PolicySet().Generation
	bad := `
apiVersion: admitly.dev/v1alpha1
kind: ValidationPolicy
metadata: {name: bad}
spec:
  match: {resources: [{kinds: [Pod]}]}
  matchConditions: [{name: m, expression: "1"}]
  variables: [{name: v, expression: "nope("}]
  validations:
    - expression: '"not bool"'
      messageExpression: '1'
`
	_, err := e.Load([]*policy.Policy{parsePolicy(t, bad)})
	if err == nil {
		t.Fatal("want compile error")
	}
	for _, frag := range []string{"matchConditions[0]", "variables[0]", "validations[0].expression", "validations[0].messageExpression"} {
		if !strings.Contains(err.Error(), frag) {
			t.Errorf("error %q lacks %q", err, frag)
		}
	}
	if e.PolicySet().Generation != gen {
		t.Fatal("failed load must keep the previous set")
	}
	disabled := strings.Replace(failingPolicy, "MODE", "Disabled", 1)
	disabled = strings.Replace(disabled, "FP", "Fail", 1)
	set, err := e.Load([]*policy.Policy{parsePolicy(t, disabled)})
	if err != nil {
		t.Fatal(err)
	}
	if set.Generation != gen+1 || len(set.Names) != 0 {
		t.Fatalf("set = %+v", set)
	}
	dup := parsePolicy(t, strings.NewReplacer("MODE", "Audit", "FP", "Fail").Replace(failingPolicy))
	if _, err := e.Load([]*policy.Policy{dup, dup}); err == nil {
		t.Fatal("duplicate names must fail")
	}
	keyed := `
apiVersion: admitly.dev/v1alpha1
kind: ImageVerificationPolicy
metadata: {name: k}
spec:
  match: {resources: [{kinds: [Pod]}]}
  verification: {rules: [{images: ["**"], publicKeys: ["not a pem"]}]}
`
	if _, err := e.Load([]*policy.Policy{parsePolicy(t, keyed)}); err == nil || !strings.Contains(err.Error(), "publicKeys[0]") {
		t.Fatalf("want key error, got %v", err)
	}
}

func TestNoPolicies(t *testing.T) {
	e, _ := New(Options{})
	if _, err := e.Validate(context.Background(), &Input{}); !errors.Is(err, ErrNoPolicies) {
		t.Fatal(err)
	}
	if _, err := e.Mutate(context.Background(), &Input{}); !errors.Is(err, ErrNoPolicies) {
		t.Fatal(err)
	}
	if _, err := NewInput(nil); err == nil {
		t.Fatal("nil request must fail")
	}
	req := request(t, admissionv1.Create, goodPod)
	req.Object.Raw = []byte("{bad")
	if _, err := NewInput(req); err == nil {
		t.Fatal("bad object must fail")
	}
	req = request(t, admissionv1.Delete, goodPod)
	req.OldObject.Raw = []byte("[")
	if _, err := NewInput(req); err == nil {
		t.Fatal("bad oldObject must fail")
	}
}

func TestObserverAndConcurrency(t *testing.T) {
	var mu sync.Mutex
	counts := map[Outcome]int{}
	e := builtinEngine(t, Options{Observer: func(_ string, o Outcome, _ time.Duration) {
		mu.Lock()
		counts[o]++
		mu.Unlock()
	}})
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			obj := goodPod
			if i%2 == 0 {
				obj = strings.Replace(goodPod, "@"+digest, ":v1", 1)
			}
			in, _ := NewInput(request(t, admissionv1.Create, obj))
			if _, err := e.Validate(context.Background(), in); err != nil {
				t.Error(err)
			}
			if _, err := e.Mutate(context.Background(), in); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if counts[OutcomeViolation] != 16 || counts[OutcomeMutated] != 32 || counts[OutcomePass] == 0 {
		t.Fatalf("counts = %v", counts)
	}
}

func newUserInfo() authenticationv1.UserInfo {
	return authenticationv1.UserInfo{Username: "alice", Groups: []string{"dev", "system:authenticated"}}
}
