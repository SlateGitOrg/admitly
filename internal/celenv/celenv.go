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
//	quantityMilli(string|int|double) -> int     Kubernetes quantity in milli-units; an error
//	                                            (not a wrapped value) when that exceeds int64
//	quantityCompare(q1, q2) -> int              -1, 0 or 1; exact for quantities of any size
//	                                            (q1, q2: string, int or double)
//
// Policies that compare quantities against a limit should use quantityCompare:
// it never overflows, so a huge value such as "10Pi" compares as larger, not
// as a wrapped negative number.
package celenv

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"
	"gopkg.in/inf.v0"
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
		cel.Function("quantityCompare",
			cel.Overload("quantity_compare_dyn_dyn", []*cel.Type{cel.DynType, cel.DynType}, cel.IntType,
				cel.BinaryBinding(quantityCompare))),
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

// toQuantity converts a CEL string, int or double into a Kubernetes quantity.
// Doubles must be finite.
func toQuantity(fn string, v ref.Val) (resource.Quantity, ref.Val) {
	switch x := v.Value().(type) {
	case int64:
		return *resource.NewQuantity(x, resource.DecimalSI), nil
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return resource.Quantity{}, types.NewErr("%s: non-finite quantity %v", fn, x)
		}
		q, err := resource.ParseQuantity(strconv.FormatFloat(x, 'g', -1, 64))
		if err != nil {
			return resource.Quantity{}, types.NewErr("%s: invalid quantity %v: %v", fn, x, err)
		}
		return q, nil
	case string:
		q, err := resource.ParseQuantity(x)
		if err != nil {
			return resource.Quantity{}, types.NewErr("%s: invalid quantity %q: %v", fn, x, err)
		}
		return q, nil
	default:
		return resource.Quantity{}, types.NewErr("%s: unsupported type %s", fn, v.Type().TypeName())
	}
}

var thousand = inf.NewDec(1000, 0)

// quantityMilli returns the quantity in milli-units, rounded away from zero
// like resource.Quantity.MilliValue. Unlike MilliValue it does not wrap
// around on int64 overflow (MilliValue("10Pi") is negative): a value that does
// not fit is an evaluation error, so the policy's failurePolicy decides.
func quantityMilli(v ref.Val) ref.Val {
	q, errVal := toQuantity("quantityMilli", v)
	if errVal != nil {
		return errVal
	}
	m := new(inf.Dec).Mul(q.AsDec(), thousand)
	m.Round(m, 0, inf.RoundUp)
	u, ok := m.Unscaled()
	if !ok {
		return types.NewErr("quantityMilli: quantity %s overflows int64 milli-units; use quantityCompare", q.String())
	}
	return types.Int(u)
}

// quantityCompare compares two quantities exactly (resource.Quantity.Cmp).
func quantityCompare(a, b ref.Val) ref.Val {
	qa, errVal := toQuantity("quantityCompare", a)
	if errVal != nil {
		return errVal
	}
	qb, errVal := toQuantity("quantityCompare", b)
	if errVal != nil {
		return errVal
	}
	return types.Int(qa.Cmp(qb))
}
