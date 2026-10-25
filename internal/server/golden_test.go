package server

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
)

var update = flag.Bool("update", false, "rewrite golden response files")

// TestGoldenAdmissionReviews replays every testdata/golden/*.request.json
// AdmissionReview v1 through the HTTP handler and compares the full response
// review with the matching *.response.json. Mutating responses also have
// their base64 JSON Patch decoded into *.patch.json for readability.
// Run `go test ./internal/server -run Golden -update` to regenerate.
func TestGoldenAdmissionReviews(t *testing.T) {
	cfg, _ := fixture(t)
	srv := httptest.NewServer(newServer(t, cfg).Mux)
	defer srv.Close()

	files, err := filepath.Glob(filepath.Join("..", "..", "testdata", "golden", "*.request.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no golden requests found: %v", err)
	}
	for _, reqPath := range files {
		name := strings.TrimSuffix(filepath.Base(reqPath), ".request.json")
		t.Run(name, func(t *testing.T) {
			endpoint := "/validate"
			if strings.HasPrefix(name, "mutate-") {
				endpoint = "/mutate"
			}
			body, err := os.ReadFile(reqPath)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := http.Post(srv.URL+endpoint+"?timeout=10s", "application/json", bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("HTTP %d: %s", resp.StatusCode, raw)
			}
			var review admissionv1.AdmissionReview
			if err := json.Unmarshal(raw, &review); err != nil {
				t.Fatal(err)
			}
			var in admissionv1.AdmissionReview
			_ = json.Unmarshal(body, &in)
			if review.Response == nil || review.Response.UID != in.Request.UID {
				t.Fatalf("response UID mismatch: %+v", review.Response)
			}
			got := pretty(t, raw)
			compareGolden(t, strings.TrimSuffix(reqPath, ".request.json")+".response.json", got)
			if review.Response.Patch != nil {
				compareGolden(t, strings.TrimSuffix(reqPath, ".request.json")+".patch.json", pretty(t, review.Response.Patch))
			}
		})
	}
}

func pretty(t *testing.T, raw []byte) []byte {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}

func compareGolden(t *testing.T, path string, got []byte) {
	t.Helper()
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing golden file %s (run with -update): %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s mismatch\n--- got\n%s\n--- want\n%s", filepath.Base(path), got, want)
	}
}
