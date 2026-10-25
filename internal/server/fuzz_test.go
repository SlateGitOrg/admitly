package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
)

// FuzzValidateHandler feeds arbitrary bodies (seeded with every golden
// request) to /validate and /mutate. The handler must never panic, must only
// answer 200/400/413, and every 200 must be a well-formed AdmissionReview
// whose response UID echoes the request UID.
func FuzzValidateHandler(f *testing.F) {
	for _, name := range []string{"validate-compliant-pod", "validate-multi-violation", "validate-ephemeral-debug-container", "mutate-cronjob", "validate-delete-pod"} {
		f.Add(goldenRequest(f, name), false)
		f.Add(goldenRequest(f, name), true)
	}
	f.Add([]byte(`{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","request":{"uid":"x","object":{"spec":{"containers":"no"}}}}`), false)
	cfg, _ := fixture(f)
	cfg.Audit.File = ""
	mux := newServer(f, cfg).Mux
	f.Fuzz(func(t *testing.T, body []byte, mutate bool) {
		path := "/validate"
		if mutate {
			path = "/mutate"
		}
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		switch rec.Code {
		case http.StatusBadRequest, http.StatusRequestEntityTooLarge:
			return
		case http.StatusOK:
		default:
			t.Fatalf("unexpected HTTP %d: %s", rec.Code, rec.Body.String())
		}
		var in, out admissionv1.AdmissionReview
		if err := json.Unmarshal(body, &in); err != nil {
			// The handler's decoder is stricter about case but otherwise
			// equivalent; a body it accepted must decode here too.
			t.Fatalf("handler accepted a body encoding/json rejects: %v", err)
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Response == nil {
			t.Fatalf("malformed response %s: %v", rec.Body.String(), err)
		}
		if out.Response.UID != in.Request.UID {
			t.Fatalf("UID %q not echoed (got %q)", in.Request.UID, out.Response.UID)
		}
	})
}
