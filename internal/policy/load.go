package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	kjson "sigs.k8s.io/json"
)

// ErrInvalidPolicy is wrapped by every structural validation failure.
var ErrInvalidPolicy = errors.New("invalid policy")

var (
	nameRe  = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)
	identRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

var validReasons = []string{"Forbidden", "Invalid", "Unauthorized"}

var validOperations = []string{"CREATE", "UPDATE", "DELETE", "CONNECT", "*"}

// maxDocumentBytes bounds a single YAML document to keep a malformed or
// hostile policy file from exhausting memory.
const maxDocumentBytes = 1 << 20

// Parse decodes every YAML (or JSON) document in data. Empty documents are
// skipped. source is recorded on each policy and used in error messages.
// Each policy is validated; key files are resolved relative to baseDir.
func Parse(data []byte, source, baseDir string) ([]*Policy, error) {
	dec := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	var out []*Policy
	for i := 0; ; i++ {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("%s: document %d: %w", source, i, err)
		}
		trimmed := bytes.TrimSpace(raw)
		if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
			continue
		}
		if len(raw) > maxDocumentBytes {
			return nil, fmt.Errorf("%s: document %d: %w: larger than %d bytes", source, i, ErrInvalidPolicy, maxDocumentBytes)
		}
		var p Policy
		if err := decodeStrict(raw, &p); err != nil {
			return nil, fmt.Errorf("%s: document %d: %w: %w", source, i, ErrInvalidPolicy, err)
		}
		p.Source = source
		if err := p.Validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", source, err)
		}
		if err := p.resolveKeyFiles(baseDir); err != nil {
			return nil, fmt.Errorf("%s: %w", source, err)
		}
		out = append(out, &p)
	}
	return out, nil
}

// LoadFile parses one policy file.
func LoadFile(path string) ([]*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy file: %w", err)
	}
	return Parse(data, path, filepath.Dir(path))
}

// LoadDir loads every *.yaml, *.yml and *.json file directly inside dir, in
// lexical order.
func LoadDir(dir string) ([]*Policy, error) {
	return loadFS(os.DirFS(dir), dir, dir)
}

func loadFS(fsys fs.FS, label, baseDir string) ([]*Policy, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("reading policy directory %s: %w", label, err)
	}
	var out []*Policy
	for _, e := range entries {
		if e.IsDir() || !isPolicyFile(e.Name()) {
			continue
		}
		data, err := fs.ReadFile(fsys, e.Name())
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", e.Name(), err)
		}
		ps, err := Parse(data, filepath.Join(label, e.Name()), baseDir)
		if err != nil {
			return nil, err
		}
		out = append(out, ps...)
	}
	return out, nil
}

// LoadFS loads policies from the root of an fs.FS (used for embedded built-ins).
// Embedded policies cannot reference key files.
func LoadFS(fsys fs.FS, label string) ([]*Policy, error) {
	return loadFS(fsys, label, "")
}

func isPolicyFile(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return ext == ".yaml" || ext == ".yml" || ext == ".json"
}

// CheckUnique returns an error if two policies share a name.
func CheckUnique(ps []*Policy) error {
	seen := make(map[string]string, len(ps))
	for _, p := range ps {
		if prev, ok := seen[p.Metadata.Name]; ok {
			return fmt.Errorf("%w: duplicate policy name %q (in %s and %s)", ErrInvalidPolicy, p.Metadata.Name, prev, p.Source)
		}
		seen[p.Metadata.Name] = p.Source
	}
	return nil
}

// SortByName orders policies by name so evaluation and output are deterministic.
func SortByName(ps []*Policy) {
	sort.SliceStable(ps, func(i, j int) bool { return ps[i].Metadata.Name < ps[j].Metadata.Name })
}

// Validate checks the document structurally. It does not compile CEL.
func (p *Policy) Validate() error {
	var errs []string
	add := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }

	if p.APIVersion != APIVersion {
		add("apiVersion must be %q, got %q", APIVersion, p.APIVersion)
	}
	if len(p.Metadata.Name) > 63 || !nameRe.MatchString(p.Metadata.Name) {
		add("metadata.name %q must be a lowercase DNS label of at most 63 characters", p.Metadata.Name)
	}
	switch p.Spec.Mode {
	case "", ModeEnforce, ModeAudit, ModeDisabled:
	default:
		add("spec.mode must be Enforce, Audit or Disabled, got %q", p.Spec.Mode)
	}
	switch p.Spec.FailurePolicy {
	case "", FailurePolicyFail, FailurePolicyIgnore:
	default:
		add("spec.failurePolicy must be Fail or Ignore, got %q", p.Spec.FailurePolicy)
	}
	p.validateMatch(add)
	validateNamed("spec.matchConditions", p.Spec.MatchConditions, add)
	validateNamed("spec.variables", p.Spec.Variables, add)

	switch p.Kind {
	case KindValidation:
		p.validateValidation(add)
	case KindMutation:
		p.validateMutation(add)
	case KindImageVerification:
		p.validateVerification(add)
	default:
		add("kind must be one of %s, %s, %s; got %q", KindValidation, KindMutation, KindImageVerification, p.Kind)
	}
	if len(errs) > 0 {
		return fmt.Errorf("%w %q: %s", ErrInvalidPolicy, p.Metadata.Name, strings.Join(errs, "; "))
	}
	return nil
}

func (p *Policy) validateMatch(add func(string, ...any)) {
	if len(p.Spec.Match.Resources) == 0 {
		add("spec.match.resources must not be empty")
	}
	for i, rr := range p.Spec.Match.Resources {
		if len(rr.Kinds) == 0 {
			add("spec.match.resources[%d].kinds must not be empty", i)
		}
		for _, op := range rr.Operations {
			if !slices.Contains(validOperations, op) {
				add("spec.match.resources[%d].operations: unknown operation %q", i, op)
			}
		}
	}
}

func validateNamed(field string, exprs []NamedExpression, add func(string, ...any)) {
	seen := map[string]bool{}
	for i, ne := range exprs {
		if !identRe.MatchString(ne.Name) {
			add("%s[%d].name %q must be a CEL identifier", field, i, ne.Name)
		}
		if seen[ne.Name] {
			add("%s[%d].name %q is duplicated", field, i, ne.Name)
		}
		seen[ne.Name] = true
		if strings.TrimSpace(ne.Expression) == "" {
			add("%s[%d].expression must not be empty", field, i)
		}
	}
}

func (p *Policy) validateValidation(add func(string, ...any)) {
	if p.Spec.Mutation != nil || p.Spec.Verification != nil {
		add("ValidationPolicy must not set spec.mutation or spec.verification")
	}
	if len(p.Spec.Validations) == 0 {
		add("spec.validations must not be empty")
	}
	for i, v := range p.Spec.Validations {
		if strings.TrimSpace(v.Expression) == "" {
			add("spec.validations[%d].expression must not be empty", i)
		}
		if v.Reason != "" && !slices.Contains(validReasons, v.Reason) {
			add("spec.validations[%d].reason must be one of %v", i, validReasons)
		}
	}
}

func (p *Policy) validateMutation(add func(string, ...any)) {
	if len(p.Spec.Validations) > 0 || p.Spec.Verification != nil {
		add("MutationPolicy must not set spec.validations or spec.verification")
	}
	if p.Spec.Mode == ModeAudit {
		add("MutationPolicy does not support mode Audit (use Enforce or Disabled)")
	}
	m := p.Spec.Mutation
	if m == nil || (len(m.PodSecurityContext) == 0 && len(m.ContainerSecurityContext) == 0) {
		add("spec.mutation must set podSecurityContext and/or containerSecurityContext")
		return
	}
	// Strict-decode the defaults into the real Kubernetes types so typos such
	// as "runAsNonroot" are rejected instead of silently patched into pods.
	if err := strictInto(m.PodSecurityContext, &corev1.PodSecurityContext{}); err != nil {
		add("spec.mutation.podSecurityContext: %v", err)
	}
	if err := strictInto(m.ContainerSecurityContext, &corev1.SecurityContext{}); err != nil {
		add("spec.mutation.containerSecurityContext: %v", err)
	}
}

func strictInto(m map[string]any, into any) error {
	if len(m) == 0 {
		return nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return decodeStrict(b, into)
}

// decodeStrict decodes JSON the way the Kubernetes API server does: field
// names are case-sensitive, unknown and duplicate fields are errors and
// integers stay int64 (so CEL sees int, not double, for params).
func decodeStrict(data []byte, into any) error {
	strictErrs, err := kjson.UnmarshalStrict(data, into)
	if err != nil {
		return err
	}
	return errors.Join(strictErrs...)
}

func (p *Policy) validateVerification(add func(string, ...any)) {
	if len(p.Spec.Validations) > 0 || p.Spec.Mutation != nil {
		add("ImageVerificationPolicy must not set spec.validations or spec.mutation")
	}
	v := p.Spec.Verification
	if v == nil || len(v.Rules) == 0 {
		add("spec.verification.rules must not be empty")
		return
	}
	for i, r := range v.Rules {
		if len(r.Images) == 0 {
			add("spec.verification.rules[%d].images must not be empty", i)
		}
		if len(r.PublicKeys) == 0 && len(r.KeyFiles) == 0 {
			add("spec.verification.rules[%d] needs publicKeys or keyFiles", i)
		}
	}
}

// resolveKeyFiles reads keyFiles into PublicKeys so a loaded policy is
// self-contained. Relative paths are resolved against baseDir.
func (p *Policy) resolveKeyFiles(baseDir string) error {
	if p.Spec.Verification == nil {
		return nil
	}
	for i := range p.Spec.Verification.Rules {
		r := &p.Spec.Verification.Rules[i]
		for _, kf := range r.KeyFiles {
			if baseDir == "" {
				return fmt.Errorf("%w %q: keyFiles are not supported in embedded policies", ErrInvalidPolicy, p.Metadata.Name)
			}
			path := kf
			if !filepath.IsAbs(path) {
				path = filepath.Join(baseDir, kf)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("%w %q: reading key file: %w", ErrInvalidPolicy, p.Metadata.Name, err)
			}
			r.PublicKeys = append(r.PublicKeys, string(data))
		}
		r.KeyFiles = nil
	}
	return nil
}
