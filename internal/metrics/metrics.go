// Package metrics defines admitly's Prometheus metrics on a private registry.
package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/SlateGitOrg/admitly/internal/engine"
)

// Metrics holds every admitly collector. The zero value is not usable; use New.
type Metrics struct {
	registry *prometheus.Registry

	requests        *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
	policyEvals     *prometheus.CounterVec
	reloads         *prometheus.CounterVec
	generation      prometheus.Gauge
	badRequests     *prometheus.CounterVec
}

// New registers all collectors on a fresh registry, including Go runtime and
// process collectors.
func New() *Metrics {
	m := &Metrics{
		registry: prometheus.NewRegistry(),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "admitly_admission_requests_total",
			Help: "Admission reviews answered, by endpoint and decision (allowed, denied, failed_open, failed_closed).",
		}, []string{"endpoint", "decision"}),
		requestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "admitly_admission_duration_seconds",
			Help:    "Time to answer an admission review, measured inside the handler.",
			Buckets: []float64{0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 1, 2.5},
		}, []string{"endpoint"}),
		policyEvals: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "admitly_policy_evaluations_total",
			Help: "Policy evaluations by policy and outcome (pass, violation, error, mutated).",
		}, []string{"policy", "outcome"}),
		reloads: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "admitly_policy_reloads_total",
			Help: "Policy set (re)loads by result (success, error).",
		}, []string{"result"}),
		generation: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "admitly_policy_set_generation",
			Help: "Generation of the active policy set.",
		}),
		badRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "admitly_bad_requests_total",
			Help: "HTTP requests rejected before evaluation, by reason.",
		}, []string{"reason"}),
	}
	m.registry.MustRegister(m.requests, m.requestDuration, m.policyEvals, m.reloads, m.generation, m.badRequests,
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return m
}

// Handler serves the metrics in the Prometheus exposition format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// Registry exposes the registry for tests.
func (m *Metrics) Registry() *prometheus.Registry { return m.registry }

// ObserveRequest records one answered admission review.
func (m *Metrics) ObserveRequest(endpoint, decision string, d time.Duration) {
	m.requests.WithLabelValues(endpoint, decision).Inc()
	m.requestDuration.WithLabelValues(endpoint).Observe(d.Seconds())
}

// PolicyObserver returns an engine.Observer that counts policy outcomes.
func (m *Metrics) PolicyObserver() engine.Observer {
	return func(policy string, outcome engine.Outcome, _ time.Duration) {
		m.policyEvals.WithLabelValues(policy, string(outcome)).Inc()
	}
}

// ObserveReload records a policy reload attempt.
func (m *Metrics) ObserveReload(err error, generation uint64) {
	if err != nil {
		m.reloads.WithLabelValues("error").Inc()
		return
	}
	m.reloads.WithLabelValues("success").Inc()
	m.generation.Set(float64(generation))
}

// ObserveBadRequest records a request rejected before evaluation.
func (m *Metrics) ObserveBadRequest(reason string) {
	m.badRequests.WithLabelValues(reason).Inc()
}
