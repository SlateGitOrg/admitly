package celenv

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
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
