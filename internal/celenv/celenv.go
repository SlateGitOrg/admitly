// Package celenv builds the CEL environment that admitly policies are written
// against and compiles expressions into cost-bounded programs.
//
// Every expression sees the same set of top-level variables:
//
//	object      the incoming object (null for DELETE)
//	oldObject   the existing object (null for CREATE)
//	request     admission request attributes (operation, namespace, userInfo, ...)
//	params      the policy's spec.params
//	variables   values of the policy's spec.variables, in declaration order
//	podSpec     the pod spec of a Pod or workload template, or null
//	podMeta     the pod template metadata (the object's own metadata for a Pod), or null
//	containers  all containers of podSpec: init, regular and ephemeral
//
// Custom functions added on top of the standard library and the strings,
// sets, lists and math extensions:
//
//	parseImage(string) -> map(string, string)   keys: registry, repository, name, tag, digest
//	string.matchesGlob(string) -> bool          anchored "/"-component glob, see imageref.MatchGlob
//	quantityMilli(string|int|double) -> int     Kubernetes quantity in milli-units
package celenv

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/archit2501/admitly/internal/imageref"
)

// Variable names exposed to policy expressions.
const (
	VarObject     = "object"
	VarOldObject  = "oldObject"
	VarRequest    = "request"
	VarParams     = "params"
	VarVariables  = "variables"
	VarPodSpec    = "podSpec"
	VarPodMeta    = "podMeta"
	VarContainers = "containers"
)

// DefaultCostLimit bounds the runtime cost of a single expression. The value
// matches the per-expression limit Kubernetes uses for ValidatingAdmissionPolicy.
const DefaultCostLimit uint64 = 1_000_000

// maxExpressionLength bounds expression source size at compile time.
const maxExpressionLength = 10_000

// ErrCompile is wrapped by every compilation failure.
var ErrCompile = errors.New("cel compile error")

// Env is an immutable, shareable CEL environment.
type Env struct {
	env       *cel.Env
	costLimit uint64 // 0 disables cost tracking (benchmarks only)
}

// New returns the admitly CEL environment. costLimit 0 selects DefaultCostLimit.
func New(costLimit uint64) (*Env, error) {
	if costLimit == 0 {
		costLimit = DefaultCostLimit
	}
	return newEnvWithLimit(costLimit)
}

func newEnvWithLimit(costLimit uint64) (*Env, error) {
	env, err := cel.NewEnv(
		cel.Variable(VarObject, cel.DynType),
		cel.Variable(VarOldObject, cel.DynType),
		cel.Variable(VarRequest, cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable(VarParams, cel.DynType),
		cel.Variable(VarVariables, cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable(VarPodSpec, cel.DynType),
		cel.Variable(VarPodMeta, cel.DynType),
		cel.Variable(VarContainers, cel.ListType(cel.DynType)),
		cel.OptionalTypes(),
		cel.CrossTypeNumericComparisons(true),
		cel.ParserExpressionSizeLimit(maxExpressionLength),
		ext.Strings(),
		ext.Sets(),
		ext.Lists(),
		ext.Math(),
		cel.Function("parseImage",
			cel.Overload("parse_image_string", []*cel.Type{cel.StringType},
				cel.MapType(cel.StringType, cel.StringType),
				cel.UnaryBinding(parseImage))),
		cel.Function("matchesGlob",
			cel.MemberOverload("string_matches_glob_string", []*cel.Type{cel.StringType, cel.StringType},
				cel.BoolType, cel.BinaryBinding(matchesGlob))),
		cel.Function("quantityMilli",
			cel.Overload("quantity_milli_string", []*cel.Type{cel.StringType}, cel.IntType,
				cel.UnaryBinding(quantityMilli)),
			cel.Overload("quantity_milli_int", []*cel.Type{cel.IntType}, cel.IntType,
				cel.UnaryBinding(quantityMilli)),
			cel.Overload("quantity_milli_double", []*cel.Type{cel.DoubleType}, cel.IntType,
				cel.UnaryBinding(quantityMilli))),
	)
	if err != nil {
		return nil, fmt.Errorf("building CEL environment: %w", err)
	}
	return &Env{env: env, costLimit: costLimit}, nil
}

// Program is a compiled, checked expression ready for evaluation.
type Program struct {
	Source string
	prg    cel.Program
}

// Compile parses and type-checks src and requires its result type to be
// assignable to want (cel.DynType accepts anything).
func (e *Env) Compile(src string, want *cel.Type) (*Program, error) {
	if strings.TrimSpace(src) == "" {
		return nil, fmt.Errorf("%w: empty expression", ErrCompile)
	}
	ast, iss := e.env.Compile(src)
	if iss.Err() != nil {
		return nil, fmt.Errorf("%w: %w", ErrCompile, iss.Err())
	}
	out := ast.OutputType()
	if want != cel.DynType && out != cel.DynType && !want.IsAssignableType(out) {
		return nil, fmt.Errorf("%w: expression must evaluate to %s, got %s", ErrCompile, want, out)
	}
	opts := []cel.ProgramOption{cel.InterruptCheckFrequency(100), cel.EvalOptions(cel.OptOptimize)}
	if e.costLimit > 0 {
		opts = append(opts, cel.CostLimit(e.costLimit))
	}
	prg, err := e.env.Program(ast, opts...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCompile, err)
	}
	return &Program{Source: src, prg: prg}, nil
}

// Eval runs the program. Cancellation of ctx interrupts long comprehensions.
func (p *Program) Eval(ctx context.Context, activation map[string]any) (ref.Val, error) {
	val, _, err := p.prg.ContextEval(ctx, activation)
	if err != nil {
		return nil, err
	}
	return val, nil
}

// EvalBool runs a boolean program.
func (p *Program) EvalBool(ctx context.Context, activation map[string]any) (bool, error) {
	val, err := p.Eval(ctx, activation)
	if err != nil {
		return false, err
	}
	b, ok := val.Value().(bool)
	if !ok {
		return false, fmt.Errorf("expression returned %s, want bool", val.Type().TypeName())
	}
	return b, nil
}

// EvalString runs a string program.
func (p *Program) EvalString(ctx context.Context, activation map[string]any) (string, error) {
	val, err := p.Eval(ctx, activation)
	if err != nil {
		return "", err
	}
	s, ok := val.Value().(string)
	if !ok {
		return "", fmt.Errorf("expression returned %s, want string", val.Type().TypeName())
	}
	return s, nil
}

// Types re-exported so callers do not import cel directly for the common cases.
var (
	BoolType   = cel.BoolType
	StringType = cel.StringType
	DynType    = cel.DynType
)

func parseImage(v ref.Val) ref.Val {
	s, ok := v.Value().(string)
	if !ok {
		return types.NewErr("parseImage: want string, got %s", v.Type().TypeName())
	}
	r, err := imageref.Parse(s)
	if err != nil {
		return types.WrapErr(err)
	}
	return types.DefaultTypeAdapter.NativeToValue(map[string]string{
		"registry":   r.Registry,
		"repository": r.Repository,
		"name":       r.Name(),
		"tag":        r.Tag,
		"digest":     r.Digest,
	})
}

func matchesGlob(name, pattern ref.Val) ref.Val {
	n, ok1 := name.Value().(string)
	p, ok2 := pattern.Value().(string)
	if !ok1 || !ok2 {
		return types.NewErr("matchesGlob: want (string, string)")
	}
	return types.Bool(imageref.MatchGlob(p, n))
}

func quantityMilli(v ref.Val) ref.Val {
	switch x := v.Value().(type) {
	case int64:
		return types.Int(x * 1000)
	case float64:
		return types.Int(int64(x * 1000))
	case string:
		q, err := resource.ParseQuantity(x)
		if err != nil {
			return types.NewErr("quantityMilli: invalid quantity %q: %v", x, err)
		}
		return types.Int(q.MilliValue())
	default:
		return types.NewErr("quantityMilli: unsupported type %s", v.Type().TypeName())
	}
}
