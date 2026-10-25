package engine

import (
	"fmt"

	admissionv1 "k8s.io/api/admission/v1"
	kjson "sigs.k8s.io/json"

	"github.com/SlateGitOrg/admitly/internal/celenv"
	"github.com/SlateGitOrg/admitly/internal/policy"
)

// Input is the decoded form of one admission request, shared by every policy
// evaluated for it. It is not safe for concurrent use: Mutate modifies Object
// (and therefore PodSpec) in place as defaults are applied.
type Input struct {
	Request *admissionv1.AdmissionRequest
	// Object and OldObject are the decoded JSON objects (nil when absent).
	Object    map[string]any
	OldObject map[string]any
	// PodSpec is the pod spec inside Object for Pods and workload kinds, else nil.
	PodSpec map[string]any
	// PodSpecPath is the JSON Pointer of PodSpec within Object.
	PodSpecPath string
	// PodMeta is the metadata belonging to PodSpec (template metadata for workloads).
	PodMeta map[string]any
	// Containers lists init, regular and ephemeral containers of PodSpec.
	Containers []any

	requestVal map[string]any
	match      policy.Request
}

// podSpecPaths maps group/kind to the location of the embedded pod spec.
var podSpecPaths = map[string][]string{
	"/Pod":                   {"spec"},
	"/ReplicationController": {"spec", "template", "spec"},
	"apps/Deployment":        {"spec", "template", "spec"},
	"apps/StatefulSet":       {"spec", "template", "spec"},
	"apps/DaemonSet":         {"spec", "template", "spec"},
	"apps/ReplicaSet":        {"spec", "template", "spec"},
	"batch/Job":              {"spec", "template", "spec"},
	"batch/CronJob":          {"spec", "jobTemplate", "spec", "template", "spec"},
}

// NewInput decodes req. Objects are decoded the way the API server decodes
// them: case-sensitive field names, integers preserved as int64.
func NewInput(req *admissionv1.AdmissionRequest) (*Input, error) {
	if req == nil {
		return nil, fmt.Errorf("admission request is missing")
	}
	in := &Input{Request: req}
	var err error
	if in.Object, err = decodeObject(req.Object.Raw); err != nil {
		return nil, fmt.Errorf("decoding object: %w", err)
	}
	if in.OldObject, err = decodeObject(req.OldObject.Raw); err != nil {
		return nil, fmt.Errorf("decoding oldObject: %w", err)
	}
	in.locatePodSpec()
	in.match = policy.Request{
		Group:       req.Kind.Group,
		Kind:        req.Kind.Kind,
		Operation:   string(req.Operation),
		Namespace:   req.Namespace,
		SubResource: req.SubResource,
	}
	in.requestVal = requestValue(req)
	return in, nil
}

func decodeObject(raw []byte) (map[string]any, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var m map[string]any
	if err := kjson.UnmarshalCaseSensitivePreserveInts(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func (in *Input) locatePodSpec() {
	if in.Object == nil {
		return
	}
	path, ok := podSpecPaths[in.Request.Kind.Group+"/"+in.Request.Kind.Kind]
	if !ok {
		return
	}
	var node any = in.Object
	pointer := ""
	parent := in.Object
	for i, seg := range path {
		m, ok := node.(map[string]any)
		if !ok {
			return
		}
		if i == len(path)-1 {
			parent = m
		}
		node = m[seg]
		pointer += "/" + seg
	}
	spec, ok := node.(map[string]any)
	if !ok {
		return
	}
	in.PodSpec = spec
	in.PodSpecPath = pointer
	if meta, ok := parent["metadata"].(map[string]any); ok {
		in.PodMeta = meta
	}
	for _, field := range []string{"initContainers", "containers", "ephemeralContainers"} {
		if list, ok := spec[field].([]any); ok {
			in.Containers = append(in.Containers, list...)
		}
	}
}

func requestValue(req *admissionv1.AdmissionRequest) map[string]any {
	groups := make([]any, len(req.UserInfo.Groups))
	for i, g := range req.UserInfo.Groups {
		groups[i] = g
	}
	dryRun := req.DryRun != nil && *req.DryRun
	return map[string]any{
		"uid":         string(req.UID),
		"operation":   string(req.Operation),
		"namespace":   req.Namespace,
		"name":        req.Name,
		"subResource": req.SubResource,
		"dryRun":      dryRun,
		"kind": map[string]any{
			"group": req.Kind.Group, "version": req.Kind.Version, "kind": req.Kind.Kind,
		},
		"resource": map[string]any{
			"group": req.Resource.Group, "version": req.Resource.Version, "resource": req.Resource.Resource,
		},
		"userInfo": map[string]any{
			"username": req.UserInfo.Username,
			"uid":      req.UserInfo.UID,
			"groups":   groups,
		},
	}
}

// activation builds the CEL variable bindings for one policy.
func (in *Input) activation(params map[string]any, vars map[string]any) map[string]any {
	var obj, old, podSpec, podMeta any
	if in.Object != nil {
		obj = in.Object
	}
	if in.OldObject != nil {
		old = in.OldObject
	}
	if in.PodSpec != nil {
		podSpec = in.PodSpec
	}
	if in.PodMeta != nil {
		podMeta = in.PodMeta
	}
	containers := in.Containers
	if containers == nil {
		containers = []any{}
	}
	var p any = map[string]any{}
	if params != nil {
		p = params
	}
	return map[string]any{
		celenv.VarObject:     obj,
		celenv.VarOldObject:  old,
		celenv.VarRequest:    in.requestVal,
		celenv.VarParams:     p,
		celenv.VarVariables:  vars,
		celenv.VarPodSpec:    podSpec,
		celenv.VarPodMeta:    podMeta,
		celenv.VarContainers: containers,
	}
}
