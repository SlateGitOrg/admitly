// Package audit writes one JSON line per admission decision. The audit log
// is the evidence trail for Audit-mode rollouts: it records every violation,
// including those that did not block the request.
package audit

import (
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/SlateGitOrg/admitly/internal/engine"
)

// Record is one admission decision.
type Record struct {
	Time       time.Time            `json:"time"`
	UID        string               `json:"uid"`
	Endpoint   string               `json:"endpoint"`
	Operation  string               `json:"operation"`
	Kind       string               `json:"kind"`
	Namespace  string               `json:"namespace,omitempty"`
	Name       string               `json:"name,omitempty"`
	User       string               `json:"user"`
	DryRun     bool                 `json:"dryRun,omitempty"`
	Allowed    bool                 `json:"allowed"`
	Decision   string               `json:"decision"`
	Matched    []string             `json:"matched,omitempty"`
	Violations []engine.Violation   `json:"violations,omitempty"`
	Ignored    []engine.PolicyError `json:"ignoredErrors,omitempty"`
	PatchOps   int                  `json:"patchOps,omitempty"`
	Failure    string               `json:"failure,omitempty"`
	Generation uint64               `json:"generation,omitempty"`
	DurationUS int64                `json:"durationMicros"`
}

// Logger serialises records as JSON lines to a writer. It is safe for
// concurrent use. A nil *Logger discards records.
type Logger struct {
	mu  sync.Mutex
	enc *json.Encoder
}

// New returns a Logger writing to w.
func New(w io.Writer) *Logger {
	return &Logger{enc: json.NewEncoder(w)}
}

// Log writes r. Write errors are returned so the caller can count them; a
// failing audit sink never changes an admission decision.
func (l *Logger) Log(r *Record) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.enc.Encode(r)
}
