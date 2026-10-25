// Package policy defines admitly's CRD-like policy documents, loads them from
// YAML and validates them structurally. Compilation of CEL expressions happens
// in package engine; this package never evaluates anything.
package policy

import (
	"slices"
	"strings"

	"github.com/archit2501/admitly/internal/imageref"
)

// APIVersion is the only accepted apiVersion for policy documents.
const APIVersion = "admitly.dev/v1alpha1"

// Kind identifies the policy document type.
type Kind string

// Supported policy kinds.
const (
	KindValidation        Kind = "ValidationPolicy"
	KindMutation          Kind = "MutationPolicy"
	KindImageVerification Kind = "ImageVerificationPolicy"
)

// Mode selects what happens when a validating policy finds a violation.
type Mode string

// Policy modes.
const (
	// ModeEnforce denies the request.
	ModeEnforce Mode = "Enforce"
	// ModeAudit admits the request but returns a warning and an audit annotation.
	ModeAudit Mode = "Audit"
	// ModeDisabled skips the policy entirely.
	ModeDisabled Mode = "Disabled"
)

// FailurePolicy selects what happens when a policy cannot be evaluated
// (CEL runtime error, cost limit, signature store failure).
type FailurePolicy string

// Failure policies, named after the Kubernetes webhook field they mirror.
const (
	// FailurePolicyFail treats an evaluation error as a violation.
	FailurePolicyFail FailurePolicy = "Fail"
	// FailurePolicyIgnore drops the error (it is still logged and counted).
	FailurePolicyIgnore FailurePolicy = "Ignore"
)

// Policy is one policy document.
type Policy struct {
	APIVersion string   `json:"apiVersion"`
	Kind       Kind     `json:"kind"`
	Metadata   Metadata `json:"metadata"`
	Spec       Spec     `json:"spec"`

	// Source records where the policy was loaded from (file path or "builtin:<file>").
	// It is not part of the document.
	Source string `json:"-"`
}

// Metadata is the subset of Kubernetes object metadata a policy carries.
type Metadata struct {
	Name        string            `json:"name"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// Spec is the union of the fields of all policy kinds. Validate rejects
// fields that do not belong to the document's kind.
type Spec struct {
	Mode            Mode              `json:"mode,omitempty"`
	FailurePolicy   FailurePolicy     `json:"failurePolicy,omitempty"`
	Severity        string            `json:"severity,omitempty"`
	Description     string            `json:"description,omitempty"`
	Match           Match             `json:"match"`
	MatchConditions []NamedExpression `json:"matchConditions,omitempty"`
	Params          map[string]any    `json:"params,omitempty"`
	Variables       []NamedExpression `json:"variables,omitempty"`

	// ValidationPolicy only.
	Validations []Validation `json:"validations,omitempty"`
	// MutationPolicy only.
	Mutation *MutationSpec `json:"mutation,omitempty"`
	// ImageVerificationPolicy only.
	Verification *VerificationSpec `json:"verification,omitempty"`
}

// Match selects the requests a policy applies to. All non-empty criteria must match.
type Match struct {
	Resources []ResourceRule `json:"resources"`
	// Namespaces is an allow-list of namespace globs; empty means every
	// namespace. A non-empty list never matches cluster-scoped objects.
	Namespaces []string `json:"namespaces,omitempty"`
	// ExcludeNamespaces is a deny-list of namespace globs.
	ExcludeNamespaces []string `json:"excludeNamespaces,omitempty"`
}

// ResourceRule matches requests by API group, kind and operation.
type ResourceRule struct {
	// APIGroups lists groups; "" is the core group, "*" matches all. Empty means all.
	APIGroups []string `json:"apiGroups,omitempty"`
	// Kinds lists kinds such as "Pod" or "Deployment"; "*" matches all.
	Kinds []string `json:"kinds"`
	// Operations lists CREATE, UPDATE, DELETE, CONNECT or "*". Empty means CREATE and UPDATE.
	Operations []string `json:"operations,omitempty"`
	// Subresources lists the sub-resources the rule also applies to, such as
	// "ephemeralcontainers"; "" is the main resource and "*" matches all.
	// Empty means the main resource only.
	Subresources []string `json:"subresources,omitempty"`
}

// NamedExpression is a named CEL expression (matchConditions, variables).
type NamedExpression struct {
	Name       string `json:"name"`
	Expression string `json:"expression"`
}

// Validation is one CEL check. The expression must evaluate to true for the
// request to comply.
type Validation struct {
	Expression        string `json:"expression"`
	Message           string `json:"message,omitempty"`
	MessageExpression string `json:"messageExpression,omitempty"`
	// Reason is a Kubernetes StatusReason: Forbidden (default), Invalid or Unauthorized.
	Reason string `json:"reason,omitempty"`
}

// MutationSpec describes "set if absent" defaults applied to pod specs.
// Values that the incoming object already sets are never overwritten.
type MutationSpec struct {
	// PodSecurityContext defaults for spec.securityContext of the pod (template).
	PodSecurityContext map[string]any `json:"podSecurityContext,omitempty"`
	// ContainerSecurityContext defaults for every init and regular container.
	ContainerSecurityContext map[string]any `json:"containerSecurityContext,omitempty"`
}

// VerificationSpec configures image signature verification.
type VerificationSpec struct {
	Rules []VerificationRule `json:"rules"`
}

// VerificationRule requires images whose repository name matches one of
// Images to carry a valid signature by one of the keys.
type VerificationRule struct {
	// Images are globs over the normalised repository name, e.g. "registry.lab.local/**".
	Images []string `json:"images"`
	// PublicKeys are inline PEM-encoded public keys.
	PublicKeys []string `json:"publicKeys,omitempty"`
	// KeyFiles are paths to PEM public keys, relative to the policy file.
	KeyFiles []string `json:"keyFiles,omitempty"`
}

// EffectiveMode returns the mode with its default applied.
func (p *Policy) EffectiveMode() Mode {
	if p.Spec.Mode == "" {
		return ModeEnforce
	}
	return p.Spec.Mode
}

// EffectiveFailurePolicy returns the failure policy with its default applied.
func (p *Policy) EffectiveFailurePolicy() FailurePolicy {
	if p.Spec.FailurePolicy == "" {
		return FailurePolicyFail
	}
	return p.Spec.FailurePolicy
}

// Request is the slice of an admission request that matching needs.
type Request struct {
	Group       string
	Kind        string
	Operation   string
	Namespace   string
	SubResource string
}

// Matches reports whether the policy's match block selects the request.
// Sub-resource requests (pods/ephemeralcontainers, ...) match only rules that
// list the sub-resource explicitly.
func (m *Match) Matches(r Request) bool {
	if !slices.ContainsFunc(m.Resources, func(rr ResourceRule) bool { return rr.matches(r) }) {
		return false
	}
	if len(m.Namespaces) > 0 {
		if r.Namespace == "" || !anyGlob(m.Namespaces, r.Namespace) {
			return false
		}
	}
	if r.Namespace != "" && anyGlob(m.ExcludeNamespaces, r.Namespace) {
		return false
	}
	return true
}

func (rr *ResourceRule) matches(r Request) bool {
	if len(rr.APIGroups) > 0 && !slices.Contains(rr.APIGroups, "*") && !slices.Contains(rr.APIGroups, r.Group) {
		return false
	}
	if !slices.Contains(rr.Kinds, "*") && !slices.Contains(rr.Kinds, r.Kind) {
		return false
	}
	subs := rr.Subresources
	if len(subs) == 0 {
		subs = []string{""}
	}
	if !slices.Contains(subs, "*") && !slices.Contains(subs, r.SubResource) {
		return false
	}
	ops := rr.Operations
	if len(ops) == 0 {
		ops = []string{"CREATE", "UPDATE"}
	}
	return slices.Contains(ops, "*") || slices.Contains(ops, strings.ToUpper(r.Operation))
}

func anyGlob(patterns []string, s string) bool {
	return slices.ContainsFunc(patterns, func(p string) bool { return imageref.MatchGlob(p, s) })
}
