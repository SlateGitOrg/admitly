package webhook

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestAPIServerBudget(t *testing.T) {
	for q, want := range map[string]time.Duration{
		"/validate?timeout=10s":   8 * time.Second,
		"/validate?timeout=500ms": 400 * time.Millisecond,
		"/validate":               0,
		"/validate?timeout=abc":   0,
		"/validate?timeout=-1s":   0,
	} {
		got, ok := apiServerBudget(httptest.NewRequest("POST", q, nil))
		if got != want || ok != (want != 0) {
			t.Errorf("%s: got %v %v, want %v", q, got, ok, want)
		}
	}
}
