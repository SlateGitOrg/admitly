// Package engine evaluates compiled admitly policies against admission
// requests. It knows nothing about HTTP or AdmissionReview responses; it
// returns violations, patches and errors, and package admission turns those
// into a decision.
package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync/atomic"
	"time"

	"github.com/SlateGitOrg/admitly/internal/celenv"
	"github.com/SlateGitOrg/admitly/internal/imageref"
	"github.com/SlateGitOrg/admitly/internal/mutate"
	"github.com/SlateGitOrg/admitly/internal/policy"
	"github.com/SlateGitOrg/admitly/internal/signature"
)

// ErrNoPolicies is returned by Validate/Mutate before any set was loaded.
var ErrNoPolicies = errors.New("no policy set loaded")

// Outcome of evaluating one policy against one request.
type Outcome string

// Policy outcomes, used for metrics.
const (
	OutcomePass      Outcome = "pass"
	OutcomeViolation Outcome = "violation"
	OutcomeError     Outcome = "error"
	OutcomeMutated   Outcome = "mutated"
)

// Observer receives one call per evaluated policy. It must be cheap and safe
// for concurrent use.
type Observer func(policyName string, outcome Outcome, d time.Duration)

// Options configure an Engine.
type Options struct {
	// CostLimit bounds each CEL expression's runtime cost (0 = default).
	CostLimit uint64
	// Verifier checks image signatures. Required only for ImageVerificationPolicy.
	Verifier *signature.Verifier
	// Logger receives evaluation errors. Defaults to slog.Default().
	Logger *slog.Logger
	// Observer, when set, is called for every evaluated policy.
	Observer Observer
}

// Engine compiles and evaluates policies. It is safe for concurrent use.
type Engine struct {
	env      *celenv.Env
	verifier *signature.Verifier
	log      *slog.Logger
	observe  Observer
	set      atomic.Pointer[PolicySet]
	gen      atomic.Uint64
}

// New returns an Engine with no policies loaded.
func New(opts Options) (*Engine, error) {
	env, err := celenv.New(opts.CostLimit)
	if err != nil {
		return nil, err
	}
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	observe := opts.Observer
	if observe == nil {
		observe = func(string, Outcome, time.Duration) {}
	}
	return &Engine{env: env, verifier: opts.Verifier, log: log, observe: observe}, nil
}

// Compile type-checks ps without installing them.
func (e *Engine) Compile(ps []*policy.Policy) (*PolicySet, error) {
	set, err := compile(e.env, ps)
	if err != nil {
		return nil, err
	}
	for _, cp := range set.validating {
		if len(cp.rules) > 0 && e.verifier == nil {
			return nil, fmt.Errorf("policy %q verifies image signatures but no signature store is configured", cp.name())
		}
	}
	return set, nil
}

// Load compiles ps and atomically replaces the active set. On error the
// previous set stays active.
func (e *Engine) Load(ps []*policy.Policy) (*PolicySet, error) {
	set, err := e.Compile(ps)
	if err != nil {
		return nil, err
	}
	set.Generation = e.gen.Add(1)
	e.set.Store(set)
	return set, nil
}

// PolicySet returns the active set, or nil before the first Load.
func (e *Engine) PolicySet() *PolicySet { return e.set.Load() }

// Violation is one reason a request does not comply.
type Violation struct {
	Policy   string      `json:"policy"`
	Mode     policy.Mode `json:"mode"`
	Severity string      `json:"severity,omitempty"`
	Reason   string      `json:"reason"`
	Message  string      `json:"message"`
	// EvalError marks a violation synthesised from an evaluation error under failurePolicy Fail.
	EvalError bool `json:"evalError,omitempty"`
}

// PolicyError is an evaluation error dropped because of failurePolicy Ignore.
type PolicyError struct {
	Policy string `json:"policy"`
	Error  string `json:"error"`
}

// Result is the outcome of Validate or Mutate.
type Result struct {
	// Matched lists the policies whose match block and matchConditions selected the request.
	Matched    []string      `json:"matched"`
	Violations []Violation   `json:"violations,omitempty"`
	Ignored    []PolicyError `json:"ignoredErrors,omitempty"`
	// Patch holds JSON Patch operations (Mutate only).
	Patch []mutate.Op `json:"patch,omitempty"`
	// MutatedBy lists the policies that contributed at least one operation.
	MutatedBy []string `json:"mutatedBy,omitempty"`
	// Incomplete is set when ctx expired before every policy was evaluated;
	// the caller must apply its global failure mode.
	Incomplete bool `json:"incomplete,omitempty"`
	// Generation of the policy set used.
	Generation uint64 `json:"generation"`
}

// Enforced returns the violations from Enforce-mode policies.
func (r *Result) Enforced() []Violation {
	return slices.DeleteFunc(slices.Clone(r.Violations), func(v Violation) bool { return v.Mode != policy.ModeEnforce })
}

// Audited returns the violations from Audit-mode policies.
func (r *Result) Audited() []Violation {
	return slices.DeleteFunc(slices.Clone(r.Violations), func(v Violation) bool { return v.Mode != policy.ModeAudit })
}

// Validate evaluates every validating policy (CEL and image verification).
func (e *Engine) Validate(ctx context.Context, in *Input) (*Result, error) {
	set := e.set.Load()
	if set == nil {
		return nil, ErrNoPolicies
	}
	res := &Result{Generation: set.Generation}
	for _, cp := range set.validating {
		if ctx.Err() != nil {
			res.Incomplete = true
			break
		}
		e.evalPolicy(ctx, cp, in, res, e.validateOne)
	}
	if ctx.Err() != nil {
		res.Incomplete = true
	}
	return res, nil
}

// Mutate evaluates every mutating policy in name order. Each policy sees the
// defaults applied by the ones before it.
func (e *Engine) Mutate(ctx context.Context, in *Input) (*Result, error) {
	set := e.set.Load()
	if set == nil {
		return nil, ErrNoPolicies
	}
	res := &Result{Generation: set.Generation}
	for _, cp := range set.mutating {
		if ctx.Err() != nil {
			res.Incomplete = true
			break
		}
		e.evalPolicy(ctx, cp, in, res, e.mutateOne)
	}
	if ctx.Err() != nil {
		res.Incomplete = true
	}
	return res, nil
}

// evalFunc evaluates the body of a matched policy. It returns violations or
// an error; mutations append directly to res.Patch.
type evalFunc func(ctx context.Context, cp *compiledPolicy, in *Input, act map[string]any, res *Result) ([]Violation, error)

func (e *Engine) evalPolicy(ctx context.Context, cp *compiledPolicy, in *Input, res *Result, body evalFunc) {
	start := time.Now()
	outcome := OutcomePass
	defer func() { e.observe(cp.name(), outcome, time.Since(start)) }()

	if !cp.policy.Spec.Match.Matches(in.match) {
		return
	}
	patchLen := len(res.Patch)
	violations, matched, err := e.runGuarded(ctx, cp, in, res, body)
	if !matched && err == nil {
		return
	}
	res.Matched = append(res.Matched, cp.name())
	if err != nil {
		if ctx.Err() != nil {
			// Deadline errors are the caller's global concern, not this policy's.
			res.Incomplete = true
			outcome = OutcomeError
			return
		}
		outcome = OutcomeError
		e.log.Warn("policy evaluation failed", "policy", cp.name(), "uid", in.Request.UID, "error", err)
		if cp.policy.EffectiveFailurePolicy() == policy.FailurePolicyIgnore {
			res.Ignored = append(res.Ignored, PolicyError{Policy: cp.name(), Error: err.Error()})
			return
		}
		res.Violations = append(res.Violations, Violation{
			Policy:    cp.name(),
			Mode:      cp.policy.EffectiveMode(),
			Severity:  cp.policy.Spec.Severity,
			Reason:    "InternalError",
			Message:   "policy could not be evaluated: " + err.Error(),
			EvalError: true,
		})
		return
	}
	if len(violations) > 0 {
		outcome = OutcomeViolation
		res.Violations = append(res.Violations, violations...)
	} else if len(res.Patch) > patchLen {
		outcome = OutcomeMutated
		res.MutatedBy = append(res.MutatedBy, cp.name())
	}
}

// runGuarded evaluates matchConditions and variables, then body, converting
// panics into errors so one faulty policy cannot crash the webhook.
func (e *Engine) runGuarded(ctx context.Context, cp *compiledPolicy, in *Input, res *Result, body evalFunc) (vs []Violation, matched bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic during evaluation: %v", r)
		}
	}()
	vars := make(map[string]any, len(cp.variables))
	act := in.activation(cp.policy.Spec.Params, vars)
	for _, mc := range cp.matchConditions {
		ok, err := mc.prg.EvalBool(ctx, act)
		if err != nil {
			return nil, true, fmt.Errorf("matchCondition %q: %w", mc.name, err)
		}
		if !ok {
			return nil, false, nil
		}
	}
	for _, v := range cp.variables {
		val, err := v.prg.Eval(ctx, act)
		if err != nil {
			return nil, true, fmt.Errorf("variable %q: %w", v.name, err)
		}
		vars[v.name] = val
	}
	vs, err = body(ctx, cp, in, act, res)
	return vs, true, err
}

func (e *Engine) validateOne(ctx context.Context, cp *compiledPolicy, in *Input, act map[string]any, _ *Result) ([]Violation, error) {
	if len(cp.rules) > 0 {
		return e.verifyImages(ctx, cp, in)
	}
	var out []Violation
	for i, v := range cp.validations {
		ok, err := v.expr.EvalBool(ctx, act)
		if err != nil {
			return nil, fmt.Errorf("validations[%d]: %w", i, err)
		}
		if ok {
			continue
		}
		out = append(out, cp.violation(v.reason, e.message(ctx, cp, v, act)))
	}
	return out, nil
}

func (e *Engine) message(ctx context.Context, cp *compiledPolicy, v compiledValidation, act map[string]any) string {
	if v.messageExpr != nil {
		msg, err := v.messageExpr.EvalString(ctx, act)
		if err == nil && msg != "" {
			return msg
		}
		if err != nil {
			e.log.Warn("messageExpression failed; using static message", "policy", cp.name(), "error", err)
		}
	}
	if v.message != "" {
		return v.message
	}
	return "failed expression: " + v.expr.Source
}

func (cp *compiledPolicy) violation(reason, msg string) Violation {
	return Violation{
		Policy:   cp.name(),
		Mode:     cp.policy.EffectiveMode(),
		Severity: cp.policy.Spec.Severity,
		Reason:   reason,
		Message:  msg,
	}
}

// verifyImages checks every distinct container image against each matching
// rule. Trust failures become violations; store failures become an error so
// the policy's failurePolicy decides.
func (e *Engine) verifyImages(ctx context.Context, cp *compiledPolicy, in *Input) ([]Violation, error) {
	var out []Violation
	seen := map[string]bool{}
	for _, c := range in.Containers {
		cm, _ := c.(map[string]any)
		image, _ := cm["image"].(string)
		if seen[image] {
			continue
		}
		seen[image] = true
		ref, err := imageref.Parse(image)
		if err != nil {
			out = append(out, cp.violation("Forbidden", fmt.Sprintf("image %q cannot be verified: %v", image, err)))
			continue
		}
		for _, rule := range cp.rules {
			if !slices.ContainsFunc(rule.images, func(g string) bool { return imageref.MatchGlob(g, ref.Name()) }) {
				continue
			}
			if _, err := e.verifier.Verify(ctx, ref, rule.keys); err != nil {
				if !signature.IsTrustFailure(err) {
					return nil, err
				}
				out = append(out, cp.violation("Forbidden", "image signature verification failed: "+err.Error()))
			}
		}
	}
	return out, nil
}

func (e *Engine) mutateOne(_ context.Context, cp *compiledPolicy, in *Input, _ map[string]any, res *Result) ([]Violation, error) {
	if in.PodSpec == nil {
		return nil, nil
	}
	ops := mutate.ApplySecurityContext(in.PodSpec, in.PodSpecPath, cp.defaults)
	res.Patch = append(res.Patch, ops...)
	return nil, nil
}
