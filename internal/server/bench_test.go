package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// BenchmarkHTTPValidate measures the full handler (JSON decode, evaluation of
// built-ins plus signature verification, JSON encode) without network or TLS.
func BenchmarkHTTPValidate(b *testing.B) {
	benchHTTP(b, "/validate", "validate-compliant-pod")
}

// BenchmarkHTTPMutate measures the mutating handler.
func BenchmarkHTTPMutate(b *testing.B) {
	benchHTTP(b, "/mutate", "mutate-pod-defaults")
}

func benchHTTP(b *testing.B, path, golden string) {
	cfg, _ := fixture(b)
	cfg.Audit.File = ""
	mux := newServer(b, cfg).Mux
	body := goldenRequest(b, golden)
	b.ReportAllocs()
	for b.Loop() {
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("HTTP %d", rec.Code)
		}
	}
}
