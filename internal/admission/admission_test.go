package admission

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/SlateGitOrg/admitly/internal/engine"
)

func TestNewValidation(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("engine required")
	}
	e, _ := engine.New(engine.Options{})
	if _, err := New(Options{Engine: e, FailureMode: "Sometimes"}); err == nil {
		t.Fatal("bad failure mode must fail")
	}
	h, err := New(Options{Engine: e})
	if err != nil {
		t.Fatal(err)
	}
	if h.FailureMode() != FailClosed || h.Timeout() != DefaultTimeout {
		t.Fatalf("defaults: %s %s", h.FailureMode(), h.Timeout())
	}
}

func TestCheckReview(t *testing.T) {
	ok := &admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Request:  &admissionv1.AdmissionRequest{UID: "u"},
	}
	if err := CheckReview(ok); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []*admissionv1.AdmissionReview{
		nil,
		{TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1beta1", Kind: "AdmissionReview"}, Request: ok.Request},
		{TypeMeta: ok.TypeMeta},
		{TypeMeta: ok.TypeMeta, Request: &admissionv1.AdmissionRequest{}},
	} {
		if err := CheckReview(bad); err == nil {
			t.Errorf("want error for %+v", bad)
		}
	}
}

func TestNoPoliciesFailsClosed(t *testing.T) {
	e, _ := engine.New(engine.Options{})
	h, _ := New(Options{Engine: e})
	review := &admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Request:  &admissionv1.AdmissionRequest{UID: "u", Kind: metav1.GroupVersionKind{Version: "v1", Kind: "Pod"}},
	}
	out, err := h.Review(context.Background(), Validate, review)
	if err != nil {
		t.Fatal(err)
	}
	if out.Response.Allowed || out.Response.UID != "u" || !strings.Contains(out.Response.Result.Message, "no policy set loaded") {
		t.Fatalf("got %+v", out.Response)
	}
	if _, err := h.Review(context.Background(), Validate, &admissionv1.AdmissionReview{}); err == nil {
		t.Fatal("malformed review must error")
	}
}

func TestWarningSanitising(t *testing.T) {
	if got := warning("a\nb\tc\x7f"); got != "a b c " {
		t.Fatalf("got %q", got)
	}
	long := strings.Repeat("é", 300)
	got := warning(long)
	if len(got) > maxWarningLength || !utf8.ValidString(got) || !strings.HasSuffix(got, "...") {
		t.Fatalf("bad truncation: len=%d valid=%v", len(got), utf8.ValidString(got))
	}
	if got := warning("bad\xffutf8"); !utf8.ValidString(got) {
		t.Fatal("invalid utf8 kept")
	}
}

func TestStatusFor(t *testing.T) {
	for reason, code := range map[string]int32{"Invalid": 422, "Unauthorized": 401, "Forbidden": 403, "InternalError": 403} {
		if _, c := statusFor(reason); c != code {
			t.Errorf("%s -> %d, want %d", reason, c, code)
		}
	}
	if groupKind(metav1.GroupVersionKind{Group: "apps", Kind: "Deployment"}) != "apps/Deployment" {
		t.Fatal("groupKind")
	}
	if mustJSON(func() {}) == "" {
		t.Fatal("mustJSON fallback")
	}
	if deadlineHint(context.Background()) != "deadline" {
		t.Fatal("deadlineHint")
	}
}
