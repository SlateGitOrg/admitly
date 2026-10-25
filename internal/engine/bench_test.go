package engine

import (
	"context"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
)

// Engine-level benchmarks: decode + evaluate, no HTTP or TLS.
// Run with `make bench` (or go test -run '^$' -bench . ./internal/engine/).

func benchInput(b *testing.B, obj string) *admissionv1.AdmissionRequest {
	b.Helper()
	return request(b, admissionv1.Create, obj)
}

func BenchmarkValidateCompliantPod(b *testing.B) {
	e := builtinEngine(b, Options{})
	req := benchInput(b, goodPod)
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		in, err := NewInput(req)
		if err != nil {
			b.Fatal(err)
		}
		res, err := e.Validate(ctx, in)
		if err != nil || len(res.Violations) != 0 {
			b.Fatalf("%v %+v", err, res.Violations)
		}
	}
}

func BenchmarkValidateViolatingPod(b *testing.B) {
	e := builtinEngine(b, Options{})
	bad := strings.Replace(goodPod, "registry.lab.local/team/web@"+digest, "docker.io/library/nginx:1.27", 1)
	bad = strings.Replace(bad, "      resources:", "      securityContext: {privileged: true}\n      resources:", 1)
	req := benchInput(b, bad)
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		in, _ := NewInput(req)
		res, err := e.Validate(ctx, in)
		if err != nil || len(res.Violations) != 3 {
			b.Fatalf("%v %+v", err, res.Violations)
		}
	}
}

func BenchmarkMutatePod(b *testing.B) {
	e := builtinEngine(b, Options{})
	req := benchInput(b, goodPod)
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		in, _ := NewInput(req)
		res, err := e.Mutate(ctx, in)
		if err != nil || len(res.Patch) != 2 {
			b.Fatalf("%v %+v", err, res.Patch)
		}
	}
}

// BenchmarkValidateManyContainers shows how evaluation scales with pod size.
func BenchmarkValidateManyContainers(b *testing.B) {
	e := builtinEngine(b, Options{})
	var sb strings.Builder
	sb.WriteString(strings.SplitAfter(goodPod, "  containers:\n")[0])
	for i := range 50 {
		sb.WriteString("    - name: c" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + "\n")
		sb.WriteString("      image: registry.lab.local/team/web@" + digest + "\n")
		sb.WriteString("      resources: {limits: {cpu: 100m, memory: 64Mi}}\n")
	}
	req := benchInput(b, sb.String())
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		in, _ := NewInput(req)
		res, err := e.Validate(ctx, in)
		if err != nil || len(res.Violations) != 0 {
			b.Fatalf("%v %+v", err, res.Violations)
		}
	}
}
