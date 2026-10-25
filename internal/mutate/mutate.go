// Package mutate computes RFC 6902 JSON Patch operations that apply
// "set if absent" defaults to Kubernetes pod specs.
//
// The patch generator never overwrites a value the user set, so applying the
// same defaults twice yields an empty second patch (idempotency is property-
// tested). Operations are generated in a deterministic order (sorted keys,
// container index order) so responses are byte-for-byte reproducible.
package mutate

import (
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Op is a JSON Patch operation. Only "add" is generated.
type Op struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value"`
}

// EscapePointer escapes one JSON Pointer reference token (RFC 6901).
func EscapePointer(token string) string {
	return strings.ReplaceAll(strings.ReplaceAll(token, "~", "~0"), "/", "~1")
}

// SetDefaults walks defaults and, for every key absent (or null) in target,
// sets it on target and records an "add" operation at path/key. Nested maps
// present on both sides are merged recursively; any other present value is
// left untouched. Lists are treated as leaf values. target is modified in
// place so subsequent calls observe earlier defaults.
func SetDefaults(target map[string]any, path string, defaults map[string]any) []Op {
	var ops []Op
	setDefaults(target, path, defaults, &ops)
	return ops
}

func setDefaults(target map[string]any, path string, defaults map[string]any, ops *[]Op) {
	keys := make([]string, 0, len(defaults))
	for k := range defaults {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		dv := defaults[k]
		childPath := path + "/" + EscapePointer(k)
		cur, exists := target[k]
		if !exists || cur == nil {
			v := deepCopy(dv)
			target[k] = v
			*ops = append(*ops, Op{Op: "add", Path: childPath, Value: v})
			continue
		}
		dm, dIsMap := dv.(map[string]any)
		cm, cIsMap := cur.(map[string]any)
		if dIsMap && cIsMap {
			setDefaults(cm, childPath, dm, ops)
		}
	}
}

func deepCopy(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[k] = deepCopy(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = deepCopy(val)
		}
		return out
	case []string:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = val
		}
		return out
	default:
		return v
	}
}

// SecurityContextDefaults holds pod- and container-level securityContext defaults.
type SecurityContextDefaults struct {
	Pod       map[string]any
	Container map[string]any
}

// ApplySecurityContext applies the defaults to podSpec, which lives at the
// JSON Pointer podSpecPath inside the admitted object. podSpec is modified in
// place. Windows pods are skipped because Linux-only securityContext fields
// (seccompProfile, runAsNonRoot semantics, capabilities) are rejected or
// meaningless there.
func ApplySecurityContext(podSpec map[string]any, podSpecPath string, d SecurityContextDefaults) []Op {
	if podSpec == nil || isWindows(podSpec) {
		return nil
	}
	var ops []Op
	if len(d.Pod) > 0 {
		setDefaults(podSpec, podSpecPath, map[string]any{"securityContext": d.Pod}, &ops)
	}
	if len(d.Container) > 0 {
		for _, field := range []string{"initContainers", "containers"} {
			list, _ := podSpec[field].([]any)
			for i, item := range list {
				c, ok := item.(map[string]any)
				if !ok {
					continue
				}
				defaults := containerDefaults(c, d.Container)
				path := podSpecPath + "/" + field + "/" + strconv.Itoa(i)
				setDefaults(c, path, map[string]any{"securityContext": defaults}, &ops)
			}
		}
	}
	return ops
}

// containerDefaults removes defaults that the API server would reject in
// combination with the container's explicit settings: it refuses
// allowPrivilegeEscalation=false together with privileged=true or
// CAP_SYS_ADMIN. Without this, mutating a privileged pod would make the API
// server fail it with a validation error instead of letting the validating
// policies deny it with a clear message.
func containerDefaults(c map[string]any, defaults map[string]any) map[string]any {
	sc, _ := c["securityContext"].(map[string]any)
	if sc == nil {
		return defaults
	}
	conflict := sc["privileged"] == true
	if caps, ok := sc["capabilities"].(map[string]any); ok {
		if add, ok := caps["add"].([]any); ok {
			conflict = conflict || slices.ContainsFunc(add, func(v any) bool {
				s, _ := v.(string)
				return s == "SYS_ADMIN" || s == "CAP_SYS_ADMIN"
			})
		}
	}
	if !conflict {
		return defaults
	}
	if _, has := defaults["allowPrivilegeEscalation"]; !has {
		return defaults
	}
	out := make(map[string]any, len(defaults))
	for k, v := range defaults {
		if k != "allowPrivilegeEscalation" {
			out[k] = v
		}
	}
	return out
}

func isWindows(podSpec map[string]any) bool {
	osField, _ := podSpec["os"].(map[string]any)
	name, _ := osField["name"].(string)
	return strings.EqualFold(name, "windows")
}
