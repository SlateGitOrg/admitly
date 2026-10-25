package mutate

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"reflect"
	"testing"

	jsonpatch "gopkg.in/evanphx/json-patch.v4"
)

var defaults = SecurityContextDefaults{
	Pod: map[string]any{
		"runAsNonRoot":   true,
		"seccompProfile": map[string]any{"type": "RuntimeDefault"},
	},
	Container: map[string]any{
		"allowPrivilegeEscalation": false,
		"capabilities":             map[string]any{"drop": []any{"ALL"}},
	},
}

func decode(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestEscapePointer(t *testing.T) {
	if got := EscapePointer("a/b~c"); got != "a~1b~0c" {
		t.Errorf("got %q", got)
	}
}

func TestApplySecurityContextEmptyPod(t *testing.T) {
	pod := decode(t, `{"spec":{"containers":[{"name":"a","image":"x"}]}}`)
	spec := pod["spec"].(map[string]any)
	ops := ApplySecurityContext(spec, "/spec", defaults)
	want := []Op{
		{Op: "add", Path: "/spec/securityContext", Value: map[string]any{"runAsNonRoot": true, "seccompProfile": map[string]any{"type": "RuntimeDefault"}}},
		{Op: "add", Path: "/spec/containers/0/securityContext", Value: map[string]any{"allowPrivilegeEscalation": false, "capabilities": map[string]any{"drop": []any{"ALL"}}}},
	}
	if !reflect.DeepEqual(ops, want) {
		t.Fatalf("ops = %#v\nwant %#v", ops, want)
	}
}

func TestApplySecurityContextRespectsExisting(t *testing.T) {
	pod := decode(t, `{"spec":{
		"securityContext":{"runAsNonRoot":false},
		"initContainers":[{"name":"i","securityContext":{"capabilities":{"add":["NET_ADMIN"]}}}],
		"containers":[{"name":"a","securityContext":{"allowPrivilegeEscalation":true}},{"name":"b","securityContext":null}]}}`)
	spec := pod["spec"].(map[string]any)
	ops := ApplySecurityContext(spec, "/spec", defaults)
	got := map[string]any{}
	for _, op := range ops {
		got[op.Path] = op.Value
	}
	want := map[string]any{
		"/spec/securityContext/seccompProfile":                            map[string]any{"type": "RuntimeDefault"},
		"/spec/initContainers/0/securityContext/allowPrivilegeEscalation": false,
		"/spec/initContainers/0/securityContext/capabilities/drop":        []any{"ALL"},
		"/spec/containers/0/securityContext/capabilities":                 map[string]any{"drop": []any{"ALL"}},
		"/spec/containers/1/securityContext":                              map[string]any{"allowPrivilegeEscalation": false, "capabilities": map[string]any{"drop": []any{"ALL"}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v\nwant %#v", got, want)
	}
}

func TestPrivilegedContainerSkipsAllowPrivilegeEscalation(t *testing.T) {
	for _, sc := range []string{`{"privileged":true}`, `{"capabilities":{"add":["SYS_ADMIN"]}}`, `{"capabilities":{"add":["CAP_SYS_ADMIN"]}}`} {
		pod := decode(t, `{"spec":{"containers":[{"name":"a","securityContext":`+sc+`}]}}`)
		ops := ApplySecurityContext(pod["spec"].(map[string]any), "/spec", SecurityContextDefaults{Container: defaults.Container})
		for _, op := range ops {
			if op.Path == "/spec/containers/0/securityContext/allowPrivilegeEscalation" {
				t.Errorf("%s: allowPrivilegeEscalation must not be defaulted", sc)
			}
		}
	}
}

func TestWindowsPodSkipped(t *testing.T) {
	pod := decode(t, `{"spec":{"os":{"name":"windows"},"containers":[{"name":"a"}]}}`)
	if ops := ApplySecurityContext(pod["spec"].(map[string]any), "/spec", defaults); len(ops) != 0 {
		t.Fatalf("want no ops for windows pod, got %v", ops)
	}
	if ops := ApplySecurityContext(nil, "/spec", defaults); ops != nil {
		t.Fatal("nil pod spec must yield nil")
	}
}

func TestSetDefaultsEscapesKeys(t *testing.T) {
	obj := map[string]any{}
	ops := SetDefaults(obj, "/metadata/annotations", map[string]any{"admitly.dev/mutated": "true"})
	if len(ops) != 1 || ops[0].Path != "/metadata/annotations/admitly.dev~1mutated" {
		t.Fatalf("ops = %v", ops)
	}
}

// randomPod builds a pod-like structure with a random mix of present, absent
// and null securityContext fields.
func randomPod(r *rand.Rand) map[string]any {
	pick := func() bool { return r.IntN(2) == 0 }
	sc := func() any {
		switch r.IntN(4) {
		case 0:
			return nil
		case 1:
			return map[string]any{}
		case 2:
			m := map[string]any{}
			if pick() {
				m["allowPrivilegeEscalation"] = pick()
			}
			if pick() {
				m["privileged"] = pick()
			}
			if pick() {
				m["capabilities"] = map[string]any{"add": []any{"NET_ADMIN"}}
			}
			return m
		default:
			return "absent"
		}
	}
	spec := map[string]any{}
	if v := sc(); v != "absent" {
		spec["securityContext"] = v
	}
	for _, field := range []string{"initContainers", "containers"} {
		n := r.IntN(4)
		if n == 0 && pick() {
			continue
		}
		list := make([]any, n)
		for i := range list {
			c := map[string]any{"name": fmt.Sprintf("c%d", i)}
			if v := sc(); v != "absent" {
				c["securityContext"] = v
			}
			list[i] = c
		}
		spec[field] = list
	}
	return map[string]any{"spec": spec}
}

// TestPropertyPatchMatchesInPlaceAndIsIdempotent checks, over random pods,
// that (1) applying the emitted JSON Patch with an independent RFC 6902
// implementation yields exactly the in-place result, and (2) running the
// defaults a second time emits no operations.
func TestPropertyPatchMatchesInPlaceAndIsIdempotent(t *testing.T) {
	r := rand.New(rand.NewPCG(34, 2026))
	for i := range 2000 {
		pod := randomPod(r)
		orig, err := json.Marshal(pod)
		if err != nil {
			t.Fatal(err)
		}
		ops := ApplySecurityContext(pod["spec"].(map[string]any), "/spec", defaults)
		patchJSON, err := json.Marshal(ops)
		if err != nil {
			t.Fatal(err)
		}
		if len(ops) == 0 {
			patchJSON = []byte("[]")
		}
		patch, err := jsonpatch.DecodePatch(patchJSON)
		if err != nil {
			t.Fatalf("case %d: decode patch: %v", i, err)
		}
		patched, err := patch.Apply(orig)
		if err != nil {
			t.Fatalf("case %d: apply patch %s to %s: %v", i, patchJSON, orig, err)
		}
		inPlace, _ := json.Marshal(pod)
		var a, b any
		_ = json.Unmarshal(patched, &a)
		_ = json.Unmarshal(inPlace, &b)
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("case %d: patch result differs from in-place result\npatched %s\ninplace %s", i, patched, inPlace)
		}
		if again := ApplySecurityContext(pod["spec"].(map[string]any), "/spec", defaults); len(again) != 0 {
			t.Fatalf("case %d: second application not idempotent: %v", i, again)
		}
	}
}
