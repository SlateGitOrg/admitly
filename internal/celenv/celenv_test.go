package celenv

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/cel-go/common/types"
	"k8s.io/apimachinery/pkg/api/resource"
)

func newEnv(t *testing.T, limit uint64) *Env {
	t.Helper()
	e, err := New(limit)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func baseActivation() map[string]any {
	return map[string]any{
		VarObject:     map[string]any{"metadata": map[string]any{"name": "p", "labels": map[string]any{"app": "x"}}},
		VarOldObject:  nil,
		VarRequest:    map[string]any{"operation": "CREATE"},
		VarParams:     map[string]any{"registries": []any{"registry.lab.local"}, "max": int64(2)},
		VarVariables:  map[string]any{},
		VarPodSpec:    nil,
		VarPodMeta:    nil,
		VarContainers: []any{},
	}
}

func TestCompileAndEvalBool(t *testing.T) {
	e := newEnv(t, 0)
	cases := []struct {
		expr string
		want bool
	}{
		{`object.metadata.name == "p"`, true},
		{`has(object.metadata.labels.app)`, true},
		{`object.?metadata.?annotations.?foo.orValue("none") == "none"`, true},
		{`parseImage("nginx").registry == "docker.io"`, true},
		{`parseImage("nginx").name == "docker.io/library/nginx"`, true},
		{`parseImage("registry.lab.local/app@sha256:` + strings.Repeat("a", 64) + `").digest != ""`, true},
		{`parseImage("registry.lab.local/app:v1").registry in params.registries`, true},
		{`parseImage("registry.lab.local.evil.io/app").registry in params.registries`, false},
		{`"registry.lab.local/team/app".matchesGlob("registry.lab.local/**")`, true},
		{`quantityMilli("500m") == 500`, true},
		{`quantityMilli("1Gi") == 1073741824000`, true},
		{`quantityMilli(2) == 2000`, true},
		{`quantityMilli(0.5) == 500`, true},
		{`params.max > 1.5`, true},
		{`["a","b"].all(x, x.size() == 1)`, true},
		{`"Hello".lowerAscii() == "hello"`, true},
	}
	for _, tc := range cases {
		p, err := e.Compile(tc.expr, BoolType)
		if err != nil {
			t.Errorf("Compile(%q): %v", tc.expr, err)
			continue
		}
		got, err := p.EvalBool(context.Background(), baseActivation())
		if err != nil {
			t.Errorf("Eval(%q): %v", tc.expr, err)
			continue
		}
		if got != tc.want {
			t.Errorf("Eval(%q) = %v, want %v", tc.expr, got, tc.want)
		}
	}
}

func TestCompileErrors(t *testing.T) {
	e := newEnv(t, 0)
	for _, src := range []string{
		"",
		"   ",
		"object.",
		"unknownVar == 1",
		"1 + 'a'",
		strings.Repeat("1 + ", 5000) + "1",
	} {
		if _, err := e.Compile(src, BoolType); !errors.Is(err, ErrCompile) {
			t.Errorf("Compile(%q) err = %v, want ErrCompile", src[:min(len(src), 30)], err)
		}
	}
	if _, err := e.Compile(`"a string"`, BoolType); err == nil || !strings.Contains(err.Error(), "must evaluate to bool") {
		t.Errorf("want output type error, got %v", err)
	}
	if _, err := e.Compile(`object.metadata.name`, StringType); err != nil {
		t.Errorf("dyn result must be accepted for string: %v", err)
	}
}

func TestRuntimeErrors(t *testing.T) {
	e := newEnv(t, 0)
	for _, src := range []string{
		`parseImage("UPPER/x").registry == ""`,
		`quantityMilli("12 apples") > 0`,
		`object.metadata.missing == "x"`,
	} {
		p, err := e.Compile(src, BoolType)
		if err != nil {
			t.Fatalf("Compile(%q): %v", src, err)
		}
		if _, err := p.EvalBool(context.Background(), baseActivation()); err == nil {
			t.Errorf("Eval(%q) succeeded, want error", src)
		}
	}
	p, _ := e.Compile(`object.metadata.name`, DynType)
	if _, err := p.EvalBool(context.Background(), baseActivation()); err == nil {
		t.Error("EvalBool on string result should fail")
	}
	if _, err := p.EvalString(context.Background(), baseActivation()); err != nil {
		t.Errorf("EvalString: %v", err)
	}
	pb, _ := e.Compile(`true`, BoolType)
	if _, err := pb.EvalString(context.Background(), baseActivation()); err == nil {
		t.Error("EvalString on bool result should fail")
	}
}

// TestQuantityHugeValues pins the fix for a maxMemory bypass: MilliValue of
// quantities above ~8Pi wraps to a negative int64, so "10Pi" compared as
// smaller than "4Gi".
func TestQuantityHugeValues(t *testing.T) {
	e := newEnv(t, 0)
	ok := []struct {
		expr string
		want bool
	}{
		{`quantityCompare("10Pi", "4Gi") == 1`, true},
		{`quantityCompare("9000000000000000000", "4Gi") == 1`, true},
		{`quantityCompare("8Ei", "4Gi") == 1`, true},
		{`quantityCompare("1e300", "4Gi") == 1`, true},
		{`quantityCompare("123456789012345678901234567890", "4Gi") == 1`, true},
		{`quantityCompare("-10Pi", "4Gi") == -1`, true},
		{`quantityCompare("4Gi", "4Gi") == 0`, true},
		{`quantityCompare("4096Mi", "4Gi") == 0`, true},
		{`quantityCompare("4Gi", "5Gi") == -1`, true},
		{`quantityCompare("500m", 1) == -1`, true},
		{`quantityCompare(2, 1.5) == 1`, true},
		{`quantityCompare(1e300, "4Gi") == 1`, true},
		{`quantityCompare(params.max, "2") == 0`, true},
		{`quantityMilli("9223372036854775807m") == 9223372036854775807`, true},
		{`quantityMilli("-9223372036854775808m") == -9223372036854775807 - 1`, true},
		{`quantityMilli("1.0001m") == 2`, true},
		{`quantityMilli("-1.5m") == -2`, true},
		{`quantityMilli(9223372036854775) == 9223372036854775000`, true},
	}
	for _, tc := range ok {
		p, err := e.Compile(tc.expr, BoolType)
		if err != nil {
			t.Errorf("Compile(%q): %v", tc.expr, err)
			continue
		}
		got, err := p.EvalBool(context.Background(), baseActivation())
		if err != nil || got != tc.want {
			t.Errorf("Eval(%q) = %v, %v; want %v", tc.expr, got, err, tc.want)
		}
	}
	for _, src := range []string{
		`quantityMilli("10Pi") > 0`,
		`quantityMilli("8Ei") > 0`,
		`quantityMilli("9000000000000000000") > 0`,
		`quantityMilli("9223372036854775808m") > 0`,
		`quantityMilli("-10Pi") < 0`,
		`quantityMilli("1e300") > 0`,
		`quantityMilli(9223372036854776) > 0`,
		`quantityMilli(-9223372036854776) < 0`,
		`quantityMilli(1e300) > 0`,
		`quantityMilli(-1e300) < 0`,
		`quantityMilli(math.sqrt(-1.0)) > 0`,
		`quantityMilli(1.0 / 0.0) > 0`,
		`quantityCompare("12 apples", "1") == 0`,
		`quantityCompare("1", "12 apples") == 0`,
		`quantityCompare(true, "1") == 0`,
		`quantityCompare(1.0 / 0.0, "1") == 0`,
	} {
		p, err := e.Compile(src, BoolType)
		if err != nil {
			t.Fatalf("Compile(%q): %v", src, err)
		}
		if got, err := p.EvalBool(context.Background(), baseActivation()); err == nil {
			t.Errorf("Eval(%q) = %v, want error (no silent wrap-around)", src, got)
		}
	}
}

// TestQuantityHugeExponents pins the fix for a CPU/memory exhaustion: a
// quantity such as "1e100000000" parses instantly, but comparing it, scaling
// it to milli-units, or (for "1e-100000000") even parsing it builds a
// ~10^100000000 big integer inside one native call, which neither the CEL cost
// limit nor the evaluation deadline can interrupt. Every case must finish in
// milliseconds.
func TestQuantityHugeExponents(t *testing.T) {
	e := newEnv(t, 0)
	ok := []string{
		`quantityCompare("1e100000000", "4Gi") == 1`,
		`quantityCompare("4Gi", "1e100000000") == -1`,
		`quantityCompare("-1e100000000", "4Gi") == -1`,
		`quantityCompare("1E2147483647", "-1E2147483647") == 1`,
		`quantityCompare("1e100000000", "1e100000001") == 0`, // both saturate to +infinity
		`quantityCompare("1e-100000000", "1n") == 0`,         // ParseQuantity rounds up to 1n
		`quantityCompare("1e-100000000", 0) == 1`,
		`quantityCompare("-1e-100000000", 0) == -1`,
		`quantityCompare("0e100000000", 0) == 0`,
		`quantityCompare("-0.000e-2147483648", "0") == 0`,
		`quantityCompare("1e4294967297", 10) == 0`, // exponent truncated to int32, as ParseQuantity does
		`quantityCompare("1e1000", "9e999") == 1`,  // exact up to the bound
		`quantityCompare("1e1001", "9.99e1000") == 1`,
		`quantityCompare("123.45e998", "1e1000") == 1`,
		// Saturation must keep the order: the largest exactly-parsed value
		// (magnitude 10^1000) stays below every saturated one.
		`quantityCompare("1` + strings.Repeat("0", 120) + `e990", "1e1001") == 0`, // both saturate
		`quantityCompare("1` + strings.Repeat("0", 120) + `e990", "1e1000") == 1`,
		`quantityCompare("9.999e1000", "1e1001") == -1`,
		`quantityCompare("-9.999e1000", "-1e1001") == 1`,
		`quantityCompare("0.` + strings.Repeat("0", 110) + `1e-900", "1n") == 0`,
		`quantityCompare("0.` + strings.Repeat("0", 100) + `1e110", "1G") == 0`,
		`quantityMilli("1e-100000000") == 1`,
		`quantityMilli("-1e-100000000") == -1`,
		`quantityMilli("0e100000000") == 0`,
		`quantityMilli("1e-6") == 1`,
		`quantityMilli("4.5e3") == 4500000`,
	}
	bad := []string{
		`quantityMilli("1e100000000") > 0`,
		`quantityMilli("-1e100000000") < 0`,
		`quantityMilli("1e1000") > 0`,
		`quantityCompare("` + strings.Repeat("1", 200) + `", "1") == 1`,
		`quantityCompare("1", "` + strings.Repeat("0", 129) + `") == 1`,
		`quantityCompare("1e99999999999999999999", "1") == 1`, // exponent not an int64: ParseQuantity rejects it
	}
	run := func(src string) (bool, error) {
		p, err := e.Compile(src, BoolType)
		if err != nil {
			t.Fatalf("Compile(%q): %v", src, err)
		}
		type res struct {
			b   bool
			err error
		}
		ch := make(chan res, 1)
		start := time.Now()
		go func() {
			b, err := p.EvalBool(context.Background(), baseActivation())
			ch <- res{b, err}
		}()
		select {
		case r := <-ch:
			if d := time.Since(start); d > 500*time.Millisecond {
				t.Errorf("Eval(%q) took %v, want milliseconds", src, d)
			}
			return r.b, r.err
		case <-time.After(5 * time.Second):
			t.Fatalf("Eval(%q) still running after 5s (unbounded big-number work)", src)
			return false, nil
		}
	}
	for _, src := range ok {
		if got, err := run(src); err != nil || !got {
			t.Errorf("Eval(%q) = %v, %v; want true", src, got, err)
		}
	}
	for _, src := range bad {
		if got, err := run(src); err == nil {
			t.Errorf("Eval(%q) = %v, want error", src, got)
		}
	}
}

// TestParseQuantityMatchesKubernetes checks parseQuantity against
// resource.ParseQuantity around the saturation bound, at exponents that are
// still cheap for ParseQuantity: identical values inside the bound and for
// tiny values, +/-infinity only for values above 10^1000.
func TestParseQuantityMatchesKubernetes(t *testing.T) {
	limit := resource.MustParse("1e1001")
	for _, m := range []string{"1", "-1", "+9.99", "0.5", "-123.456", "0.0001", "-0.000700", "0", "-0.0", ".5", "7."} {
		for _, exp := range []int{-1300, -1001, -1000, -999, -12, -9, 0, 5, 997, 998, 999, 1000, 1001, 1003, 1300} {
			for _, e := range []string{"e", "E", "e+"} {
				if e == "e+" && exp < 0 {
					continue
				}
				s := m + e + strconv.Itoa(exp)
				want, err := resource.ParseQuantity(s)
				if err != nil {
					t.Fatalf("ParseQuantity(%q): %v", s, err)
				}
				got, err := parseQuantity(s)
				if err != nil {
					t.Fatalf("parseQuantity(%q): %v", s, err)
				}
				if got.inf != 0 {
					abs := want.DeepCopy()
					if abs.Sign() < 0 {
						abs.Neg()
					}
					if abs.Cmp(limit) < 0 || got.inf != want.Sign() {
						t.Errorf("parseQuantity(%q) = inf %d, but ParseQuantity = %s", s, got.inf, want.String())
					}
					continue
				}
				if got.q.Cmp(want) != 0 {
					t.Errorf("parseQuantity(%q) = %s, ParseQuantity = %s", s, got.q.String(), want.String())
				}
			}
		}
	}
}

func TestCostLimit(t *testing.T) {
	e := newEnv(t, 1000)
	p, err := e.Compile(`lists.range(5000).all(i, i >= 0)`, BoolType)
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.EvalBool(context.Background(), baseActivation())
	if err == nil || !strings.Contains(err.Error(), "cost limit") {
		t.Fatalf("want cost limit error, got %v", err)
	}
}

func TestContextCancellation(t *testing.T) {
	e := newEnv(t, 1<<62)
	p, err := e.Compile(`lists.range(2000).all(i, lists.range(2000).all(j, i + j >= 0))`, BoolType)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = p.EvalBool(ctx, baseActivation())
	if err == nil {
		t.Fatal("want interruption error")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("evaluation was not interrupted promptly: %v", time.Since(start))
	}
}

// FuzzQuantity feeds arbitrary strings to quantityCompare and quantityMilli:
// every call must finish quickly (no unbounded big-number work), and a
// successfully parsed value must agree with itself.
func FuzzQuantity(f *testing.F) {
	for _, s := range []string{"4Gi", "500m", "1e100000000", "1e-100000000", "-0.5E-2147483648", "1e4294967297", "10Pi", "8Ei", ".e9", "1.5e+3k", "0x10"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		start := time.Now()
		_, err := parseQuantity(s)
		quantityMilli(types.String(s))
		c := quantityCompare(types.String(s), types.String("4Gi"))
		if err == nil {
			if self := quantityCompare(types.String(s), types.String(s)); self != types.IntZero {
				t.Errorf("quantityCompare(%q, itself) = %v, want 0", s, self)
			}
			if _, isErr := c.(*types.Err); isErr {
				t.Errorf("quantityCompare(%q, 4Gi) = %v after a successful parse", s, c)
			}
		}
		if d := time.Since(start); d > 500*time.Millisecond {
			t.Errorf("quantity functions on %q took %v", s, d)
		}
	})
}
