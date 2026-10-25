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
//	quantityCompare(q1, q2) -> int              -1, 0 or 1; exact up to magnitude 10^1000, larger
//	                                            values compare as +/-infinity (q1, q2: string,
//	                                            int or double)
//
// Quantity strings longer than 128 characters are an evaluation error, and
// decimal exponents far outside +/-1000 are decided without big-number
// arithmetic, so each quantity call costs microseconds (see maxQuantityLen).
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

	"github.com/SlateGitOrg/admitly/internal/imageref"
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

// Bounds that keep quantity arithmetic cheap. resource.ParseQuantity accepts
// decimal exponents up to the int32 range, and both Quantity.Cmp and inf.Dec
// rounding rescale to a common scale with math/big: "1e100000000" builds a
// ~10^100000000 integer (tens of seconds, hundreds of MB) inside one native
// CEL call, which neither the cost limit nor the evaluation deadline can
// interrupt. Parsing "1e-100000000" is just as slow (ParseQuantity rounds it up
// to 1n the same way). So:
//   - strings longer than maxQuantityLen are rejected, which bounds the
//     mantissa digits (no real quantity comes close);
//   - a decimal-exponent value whose order of magnitude is beyond
//     maxQuantityMagnitude never reaches ParseQuantity: above it saturates to
//     +/-infinity, below it is +/-1n (exactly what ParseQuantity returns for any
//     non-zero value under 1n), and a zero mantissa is 0.
//
// Everything that does reach math/big has |scale| <= maxQuantityMagnitude +
// maxQuantityLen, so each call costs microseconds.
const (
	maxQuantityLen       = 128
	maxQuantityMagnitude = 1000
)

// quantity is a parsed Kubernetes quantity. inf is +1 or -1 when the value's
// magnitude is 10^(maxQuantityMagnitude+1) or more: it then compares as
// +/-infinity (two such values of the same sign compare equal) and q is unset.
type quantity struct {
	q   resource.Quantity
	inf int
}

// toQuantity converts a CEL string, int or double into a quantity. Doubles
// must be finite.
func toQuantity(fn string, v ref.Val) (quantity, ref.Val) {
	switch x := v.Value().(type) {
	case int64:
		return quantity{q: *resource.NewQuantity(x, resource.DecimalSI)}, nil
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return quantity{}, types.NewErr("%s: non-finite quantity %v", fn, x)
		}
		q, err := parseQuantity(strconv.FormatFloat(x, 'g', -1, 64))
		if err != nil {
			return quantity{}, types.NewErr("%s: invalid quantity %v: %v", fn, x, err)
		}
		return q, nil
	case string:
		q, err := parseQuantity(x)
		if err != nil {
			return quantity{}, types.NewErr("%s: invalid quantity %q: %v", fn, truncate(x, 40), err)
		}
		return q, nil
	default:
		return quantity{}, types.NewErr("%s: unsupported type %s", fn, v.Type().TypeName())
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// parseQuantity is resource.ParseQuantity with the cost bounds described at
// maxQuantityMagnitude.
func parseQuantity(s string) (quantity, error) {
	if len(s) > maxQuantityLen {
		return quantity{}, fmt.Errorf("longer than %d characters", maxQuantityLen)
	}
	if q, ok := outOfRangeExponent(s); ok {
		return q, nil
	}
	q, err := resource.ParseQuantity(s)
	if err != nil {
		return quantity{}, err
	}
	return quantity{q: q}, nil
}

// outOfRangeExponent decides decimal-exponent quantities ("<number>e<int>")
// whose order of magnitude is beyond +/-maxQuantityMagnitude without big-number
// arithmetic. It follows ParseQuantity's grammar, including its truncation of
// the exponent to int32 ("1e4294967297" is 10). ok is false for every other
// input, which ParseQuantity then parses or rejects at bounded cost.
func outOfRangeExponent(s string) (q quantity, ok bool) {
	i := 0
	neg := false
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		neg = s[i] == '-'
		i++
	}
	// mag = floor(log10(|mantissa|)) once a non-zero digit has been seen.
	mag, nonzero, intDigits := 0, false, 0
	for ; i < len(s) && isDigit(s[i]); i++ {
		if nonzero || s[i] != '0' {
			nonzero = true
			intDigits++
		}
	}
	if nonzero {
		mag = intDigits - 1
	}
	if i < len(s) && s[i] == '.' {
		i++
		for j := 0; i < len(s) && isDigit(s[i]); i, j = i+1, j+1 {
			if !nonzero && s[i] != '0' {
				nonzero = true
				mag = -(j + 1)
			}
		}
	}
	if len(s)-i < 2 || (s[i] != 'e' && s[i] != 'E') {
		return quantity{}, false
	}
	parsed, err := strconv.ParseInt(s[i+1:], 10, 64)
	if err != nil {
		return quantity{}, false
	}
	exp := int64(int32(parsed)) //nolint:gosec // mirrors ParseQuantity's own int32 truncation
	total := int64(mag) + exp
	switch {
	case !nonzero && exp >= -maxQuantityMagnitude && exp <= maxQuantityMagnitude:
		return quantity{}, false // zero with a small exponent: ParseQuantity is cheap
	case !nonzero:
		return quantity{}, true // zero
	case total >= -maxQuantityMagnitude && total <= maxQuantityMagnitude:
		return quantity{}, false
	case total > maxQuantityMagnitude && neg:
		return quantity{inf: -1}, true
	case total > maxQuantityMagnitude:
		return quantity{inf: 1}, true
	case neg:
		return quantity{q: *resource.NewScaledQuantity(-1, resource.Nano)}, true
	default:
		return quantity{q: *resource.NewScaledQuantity(1, resource.Nano)}, true
	}
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

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
	if q.inf != 0 {
		return types.NewErr("quantityMilli: quantity overflows int64 milli-units; use quantityCompare")
	}
	m := new(inf.Dec).Mul(q.q.AsDec(), thousand)
	m.Round(m, 0, inf.RoundUp)
	u, ok := m.Unscaled()
	if !ok {
		return types.NewErr("quantityMilli: quantity %s overflows int64 milli-units; use quantityCompare", truncate(q.q.String(), 40))
	}
	return types.Int(u)
}

// quantityCompare compares two quantities: exactly (resource.Quantity.Cmp) up
// to a magnitude of 10^1000, with larger magnitudes treated as +/-infinity.
func quantityCompare(a, b ref.Val) ref.Val {
	qa, errVal := toQuantity("quantityCompare", a)
	if errVal != nil {
		return errVal
	}
	qb, errVal := toQuantity("quantityCompare", b)
	if errVal != nil {
		return errVal
	}
	if qa.inf != 0 || qb.inf != 0 {
		return types.Int(cmpInt(qa.inf, qb.inf))
	}
	return types.Int(qa.q.Cmp(qb.q))
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
