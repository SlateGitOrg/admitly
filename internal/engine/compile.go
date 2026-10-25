package engine

import (
	"errors"
	"fmt"

	"github.com/SlateGitOrg/admitly/internal/celenv"
	"github.com/SlateGitOrg/admitly/internal/mutate"
	"github.com/SlateGitOrg/admitly/internal/policy"
	"github.com/SlateGitOrg/admitly/internal/signature"
)

// PolicySet is an immutable, compiled set of policies. It is swapped
// atomically on reload, so in-flight requests finish against the set they
// started with.
type PolicySet struct {
	validating []*compiledPolicy // ValidationPolicy and ImageVerificationPolicy
	mutating   []*compiledPolicy
	// Generation increases by one on every successful load.
	Generation uint64
	// Names lists every compiled (non-disabled) policy, sorted.
	Names []string
}

type namedProgram struct {
	name string
	prg  *celenv.Program
}

type compiledValidation struct {
	expr        *celenv.Program
	message     string
	messageExpr *celenv.Program
	reason      string
}

type compiledRule struct {
	images []string
	keys   []*signature.PublicKey
}

type compiledPolicy struct {
	policy          *policy.Policy
	matchConditions []namedProgram
	variables       []namedProgram
	validations     []compiledValidation
	defaults        mutate.SecurityContextDefaults
	rules           []compiledRule
}

func (cp *compiledPolicy) name() string { return cp.policy.Metadata.Name }

// compile type-checks every expression of every policy. All errors are
// collected so a broken policy file reports every problem at once.
func compile(env *celenv.Env, ps []*policy.Policy) (*PolicySet, error) {
	if err := policy.CheckUnique(ps); err != nil {
		return nil, err
	}
	sorted := append([]*policy.Policy(nil), ps...)
	policy.SortByName(sorted)

	set := &PolicySet{}
	var errs []error
	for _, p := range sorted {
		if p.EffectiveMode() == policy.ModeDisabled {
			continue
		}
		cp, err := compilePolicy(env, p)
		if err != nil {
			errs = append(errs, fmt.Errorf("policy %q (%s): %w", p.Metadata.Name, p.Source, err))
			continue
		}
		if p.Kind == policy.KindMutation {
			set.mutating = append(set.mutating, cp)
		} else {
			set.validating = append(set.validating, cp)
		}
		set.Names = append(set.Names, p.Metadata.Name)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return set, nil
}

func compilePolicy(env *celenv.Env, p *policy.Policy) (*compiledPolicy, error) {
	cp := &compiledPolicy{policy: p}
	var errs []error
	for i, mc := range p.Spec.MatchConditions {
		prg, err := env.Compile(mc.Expression, celenv.BoolType)
		if err != nil {
			errs = append(errs, fmt.Errorf("spec.matchConditions[%d] (%s): %w", i, mc.Name, err))
			continue
		}
		cp.matchConditions = append(cp.matchConditions, namedProgram{name: mc.Name, prg: prg})
	}
	for i, v := range p.Spec.Variables {
		prg, err := env.Compile(v.Expression, celenv.DynType)
		if err != nil {
			errs = append(errs, fmt.Errorf("spec.variables[%d] (%s): %w", i, v.Name, err))
			continue
		}
		cp.variables = append(cp.variables, namedProgram{name: v.Name, prg: prg})
	}
	for i, v := range p.Spec.Validations {
		cv := compiledValidation{message: v.Message, reason: v.Reason}
		if cv.reason == "" {
			cv.reason = "Forbidden"
		}
		prg, err := env.Compile(v.Expression, celenv.BoolType)
		if err != nil {
			errs = append(errs, fmt.Errorf("spec.validations[%d].expression: %w", i, err))
		}
		cv.expr = prg
		if v.MessageExpression != "" {
			mprg, err := env.Compile(v.MessageExpression, celenv.StringType)
			if err != nil {
				errs = append(errs, fmt.Errorf("spec.validations[%d].messageExpression: %w", i, err))
			}
			cv.messageExpr = mprg
		}
		cp.validations = append(cp.validations, cv)
	}
	if m := p.Spec.Mutation; m != nil {
		cp.defaults = mutate.SecurityContextDefaults{Pod: m.PodSecurityContext, Container: m.ContainerSecurityContext}
	}
	if v := p.Spec.Verification; v != nil {
		for i, r := range v.Rules {
			cr := compiledRule{images: r.Images}
			for j, pemKey := range r.PublicKeys {
				k, err := signature.ParsePublicKey([]byte(pemKey))
				if err != nil {
					errs = append(errs, fmt.Errorf("spec.verification.rules[%d].publicKeys[%d]: %w", i, j, err))
					continue
				}
				cr.keys = append(cr.keys, k)
			}
			cp.rules = append(cp.rules, cr)
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return cp, nil
}
