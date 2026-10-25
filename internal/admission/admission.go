// Package admission turns AdmissionReview v1 requests into responses using
// the policy engine. It owns the decision logic: how violations map to
// allow/deny, warnings and audit annotations, and what happens when
// evaluation cannot complete (the global failure mode).
package admission

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/SlateGitOrg/admitly/internal/audit"
	"github.com/SlateGitOrg/admitly/internal/engine"
	"github.com/SlateGitOrg/admitly/internal/metrics"
)

// FailureMode decides requests whose evaluation could not complete.
type FailureMode string

// Failure modes.
const (
	// FailClosed denies the request (the safe default).
	FailClosed FailureMode = "Closed"
	// FailOpen admits the request with a warning.
	FailOpen FailureMode = "Open"
)

// Endpoint identifies the webhook being served.
type Endpoint string

// Endpoints.
const (
	Validate Endpoint = "validate"
	Mutate   Endpoint = "mutate"
)

// Decision labels used in metrics and audit records.
const (
	DecisionAllowed      = "allowed"
	DecisionDenied       = "denied"
	DecisionFailedOpen   = "failed_open"
	DecisionFailedClosed = "failed_closed"
)

// Audit annotation keys (the API server prefixes them with the webhook name).
const (
	AnnotationAuditViolations = "audit-violations"
	AnnotationIgnoredErrors   = "ignored-errors"
	AnnotationMutatedBy       = "mutated-by"
	AnnotationFailure         = "failure"
)

// maxWarningLength keeps each warning under the API server's 256-byte
// truncation limit for warning headers.
const maxWarningLength = 240

// ErrMalformedReview is returned for reviews that cannot be answered at all
// (wrong apiVersion/kind, missing request or UID). The HTTP layer maps it to 400.
var ErrMalformedReview = errors.New("malformed AdmissionReview")

// Options configure a Handler.
type Options struct {
	Engine      *engine.Engine
	FailureMode FailureMode
	// Timeout caps evaluation time per review. The HTTP layer may shorten it
	// further from the API server's own ?timeout= parameter.
	Timeout time.Duration
	Audit   *audit.Logger
	Metrics *metrics.Metrics
	Logger  *slog.Logger
}

// Handler answers AdmissionReviews. It is safe for concurrent use.
type Handler struct {
	opts Options
	log  *slog.Logger
}

// DefaultTimeout is used when Options.Timeout is zero. It is well inside the
// API server's default 10s webhook timeout.
const DefaultTimeout = 3 * time.Second

// New returns a Handler.
func New(opts Options) (*Handler, error) {
	if opts.Engine == nil {
		return nil, errors.New("admission: engine is required")
	}
	switch opts.FailureMode {
	case "":
		opts.FailureMode = FailClosed
	case FailClosed, FailOpen:
	default:
		return nil, fmt.Errorf("admission: failure mode must be Closed or Open, got %q", opts.FailureMode)
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Handler{opts: opts, log: log}, nil
}

// FailureMode returns the configured global failure mode.
func (h *Handler) FailureMode() FailureMode { return h.opts.FailureMode }

// Timeout returns the configured evaluation timeout.
func (h *Handler) Timeout() time.Duration { return h.opts.Timeout }

// CheckReview validates the envelope of a review.
func CheckReview(review *admissionv1.AdmissionReview) error {
	if review == nil {
		return fmt.Errorf("%w: empty body", ErrMalformedReview)
	}
	if review.APIVersion != "admission.k8s.io/v1" || review.Kind != "AdmissionReview" {
		return fmt.Errorf("%w: want admission.k8s.io/v1 AdmissionReview, got %s %s", ErrMalformedReview, review.APIVersion, review.Kind)
	}
	if review.Request == nil {
		return fmt.Errorf("%w: request is missing", ErrMalformedReview)
	}
	if review.Request.UID == "" {
		return fmt.Errorf("%w: request.uid is missing", ErrMalformedReview)
	}
	return nil
}

// Review answers one review. The caller's ctx may carry a deadline; the
// handler applies its own Timeout on top. It never returns a nil response
// for a well-formed review: panics and evaluation failures are converted
// into a decision according to the failure mode.
func (h *Handler) Review(ctx context.Context, ep Endpoint, review *admissionv1.AdmissionReview) (*admissionv1.AdmissionReview, error) {
	if err := CheckReview(review); err != nil {
		return nil, err
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, h.opts.Timeout)
	defer cancel()

	req := review.Request
	rec := &audit.Record{
		UID:       string(req.UID),
		Endpoint:  string(ep),
		Operation: string(req.Operation),
		Kind:      groupKind(req.Kind),
		Namespace: req.Namespace,
		Name:      req.Name,
		User:      req.UserInfo.Username,
		DryRun:    req.DryRun != nil && *req.DryRun,
	}
	resp := h.decide(ctx, ep, req, rec)
	resp.UID = req.UID

	elapsed := time.Since(start)
	rec.Time = start.UTC()
	rec.Allowed = resp.Allowed
	rec.DurationUS = elapsed.Microseconds()
	if err := h.opts.Audit.Log(rec); err != nil {
		h.log.Error("writing audit record", "error", err)
	}
	if h.opts.Metrics != nil {
		h.opts.Metrics.ObserveRequest(string(ep), rec.Decision, elapsed)
	}
	h.log.Debug("admission decision", "uid", req.UID, "endpoint", ep, "kind", rec.Kind,
		"namespace", req.Namespace, "name", req.Name, "decision", rec.Decision, "duration", elapsed)

	return &admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Response: resp,
	}, nil
}

func (h *Handler) decide(ctx context.Context, ep Endpoint, req *admissionv1.AdmissionRequest, rec *audit.Record) (resp *admissionv1.AdmissionResponse) {
	defer func() {
		if r := recover(); r != nil {
			h.log.Error("panic while evaluating admission request", "uid", req.UID, "panic", r)
			resp = h.failure(rec, "internal error")
		}
	}()

	in, err := engine.NewInput(req)
	if err != nil {
		return h.failure(rec, "undecodable request: "+err.Error())
	}
	var res *engine.Result
	if ep == Mutate {
		res, err = h.opts.Engine.Mutate(ctx, in)
	} else {
		res, err = h.opts.Engine.Validate(ctx, in)
	}
	if err != nil {
		return h.failure(rec, err.Error())
	}
	rec.Matched, rec.Violations, rec.Ignored, rec.Generation = res.Matched, res.Violations, res.Ignored, res.Generation
	if res.Incomplete {
		return h.failure(rec, fmt.Sprintf("evaluation did not finish within the deadline (%s)", deadlineHint(ctx)))
	}
	if ep == Mutate {
		return h.mutateResponse(res, rec)
	}
	return h.validateResponse(res, rec)
}

func (h *Handler) validateResponse(res *engine.Result, rec *audit.Record) *admissionv1.AdmissionResponse {
	resp := &admissionv1.AdmissionResponse{Allowed: true}
	annotate(resp, res)
	for _, v := range res.Audited() {
		resp.Warnings = append(resp.Warnings, warning(fmt.Sprintf("[audit] %s: %s", v.Policy, v.Message)))
	}
	enforced := res.Enforced()
	if len(enforced) == 0 {
		rec.Decision = DecisionAllowed
		return resp
	}
	parts := make([]string, len(enforced))
	for i, v := range enforced {
		parts[i] = fmt.Sprintf("[%s] %s", v.Policy, v.Message)
	}
	reason, code := statusFor(enforced[0].Reason)
	resp.Allowed = false
	resp.Result = &metav1.Status{
		Status:  metav1.StatusFailure,
		Reason:  reason,
		Code:    code,
		Message: "admitly denied the request: " + strings.Join(parts, "; "),
	}
	rec.Decision = DecisionDenied
	return resp
}

func (h *Handler) mutateResponse(res *engine.Result, rec *audit.Record) *admissionv1.AdmissionResponse {
	resp := &admissionv1.AdmissionResponse{Allowed: true}
	annotate(resp, res)
	if len(res.Violations) > 0 {
		// Only evaluation errors under failurePolicy Fail produce violations here.
		parts := make([]string, len(res.Violations))
		for i, v := range res.Violations {
			parts[i] = fmt.Sprintf("[%s] %s", v.Policy, v.Message)
		}
		resp.Allowed = false
		resp.Result = &metav1.Status{
			Status:  metav1.StatusFailure,
			Reason:  metav1.StatusReasonInternalError,
			Code:    500,
			Message: "admitly could not apply mutations: " + strings.Join(parts, "; "),
		}
		rec.Decision = DecisionDenied
		return resp
	}
	rec.Decision = DecisionAllowed
	if len(res.Patch) > 0 {
		patch, err := json.Marshal(res.Patch)
		if err != nil {
			return h.failure(rec, "encoding patch: "+err.Error())
		}
		pt := admissionv1.PatchTypeJSONPatch
		resp.Patch = patch
		resp.PatchType = &pt
		rec.PatchOps = len(res.Patch)
		setAnnotation(resp, AnnotationMutatedBy, strings.Join(res.MutatedBy, ","))
	}
	return resp
}

// failure applies the global failure mode.
func (h *Handler) failure(rec *audit.Record, reason string) *admissionv1.AdmissionResponse {
	rec.Failure = reason
	h.log.Warn("admission evaluation failed", "uid", rec.UID, "endpoint", rec.Endpoint, "reason", reason, "failureMode", h.opts.FailureMode)
	resp := &admissionv1.AdmissionResponse{}
	setAnnotation(resp, AnnotationFailure, reason)
	if h.opts.FailureMode == FailOpen {
		resp.Allowed = true
		resp.Warnings = []string{warning("admitly: " + reason + "; admitted because failureMode=Open")}
		rec.Decision = DecisionFailedOpen
		return resp
	}
	resp.Allowed = false
	resp.Result = &metav1.Status{
		Status:  metav1.StatusFailure,
		Reason:  metav1.StatusReasonInternalError,
		Code:    500,
		Message: "admitly could not evaluate policies (" + reason + "); denied because failureMode=Closed",
	}
	rec.Decision = DecisionFailedClosed
	return resp
}

func annotate(resp *admissionv1.AdmissionResponse, res *engine.Result) {
	if audited := res.Audited(); len(audited) > 0 {
		setAnnotation(resp, AnnotationAuditViolations, mustJSON(audited))
	}
	if len(res.Ignored) > 0 {
		setAnnotation(resp, AnnotationIgnoredErrors, mustJSON(res.Ignored))
	}
}

func setAnnotation(resp *admissionv1.AdmissionResponse, k, v string) {
	if resp.AuditAnnotations == nil {
		resp.AuditAnnotations = map[string]string{}
	}
	resp.AuditAnnotations[k] = v
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

func statusFor(reason string) (metav1.StatusReason, int32) {
	switch reason {
	case "Invalid":
		return metav1.StatusReasonInvalid, 422
	case "Unauthorized":
		return metav1.StatusReasonUnauthorized, 401
	default:
		return metav1.StatusReasonForbidden, 403
	}
}

// warning sanitises a message for the Warning HTTP header: single line,
// valid UTF-8, bounded length.
func warning(s string) string {
	s = strings.ToValidUTF8(s, "?")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) <= maxWarningLength {
		return s
	}
	cut := maxWarningLength - len("...")
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}

func groupKind(gvk metav1.GroupVersionKind) string {
	if gvk.Group == "" {
		return gvk.Kind
	}
	return gvk.Group + "/" + gvk.Kind
}

func deadlineHint(ctx context.Context) string {
	if err := ctx.Err(); err != nil {
		return err.Error()
	}
	return "deadline"
}
