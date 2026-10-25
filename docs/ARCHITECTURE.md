# admitly architecture

## Package map

```
cmd/admitly            main: delegates to internal/cli
internal/cli           serve, eval, lint, certs, keygen, sign, verify, bench
internal/server        assembles config -> engine -> admission -> HTTP; policy hot reload
internal/webhook       HTTP routes, body/content-type limits, ?timeout= budget, TLS config, graceful shutdown
internal/admission     AdmissionReview v1 -> decision (status codes, warnings, audit annotations, patch, failure mode)
internal/engine        compiles policy sets; evaluates match -> matchConditions -> variables -> body
internal/celenv        CEL environment, custom functions, cost-bounded programs
internal/policy        policy document types, strict loader, structural validation, matching
internal/mutate        set-if-absent JSON Patch generation for securityContext defaults
internal/signature     cosign simple-signing payloads, key parsing, verification, directory store, LRU cache
internal/imageref      strict image reference parser, anchored glob matcher
internal/tlsutil       CA/serving/client certificate generation, hot-reloading certificate source
internal/config        server configuration, policy assembly (built-ins, dirs, overrides), source fingerprints
internal/audit         JSON-lines decision log
internal/metrics       Prometheus collectors on a private registry
internal/bench         end-to-end latency harness (TLS on loopback)
policies               embedded built-in policy library (YAML)
test/envtest           real kube-apiserver + etcd suite (build tag envtest)
test/manifests         strict decoding of deploy/ and examples/
```

Dependencies point downwards only: `cli -> server -> {webhook, admission} ->
engine -> {celenv, policy, mutate, signature} -> imageref`. The engine knows
nothing about HTTP; the admission package knows nothing about TLS.

## Request flow

```mermaid
sequenceDiagram
  participant API as kube-apiserver
  participant W as webhook (HTTP)
  participant A as admission.Handler
  participant E as engine.Engine
  participant V as signature.Verifier
  API->>W: POST /validate?timeout=10s (AdmissionReview v1, TLS)
  W->>W: content-type, 3 MiB cap, strict decode, budget = 0.8 x timeout
  W->>A: Review(ctx, Validate, review)
  A->>A: check envelope (v1, request, uid); ctx deadline = min(config timeout, budget)
  A->>E: NewInput(request) then Validate(ctx, input)
  loop each validating policy (sorted by name)
    E->>E: match (kind/group/op/subresource/namespace globs)
    E->>E: matchConditions, variables (CEL)
    alt ImageVerificationPolicy
      E->>V: Verify(image, keys) (cache, store, payload binding, signature)
    else ValidationPolicy
      E->>E: validations + messageExpression (CEL)
    end
  end
  E-->>A: Result{violations, ignored, incomplete}
  A->>A: enforce -> deny 403/422/401; audit -> warnings + annotations; incomplete -> failure mode
  A-->>W: AdmissionReview response (same UID)
  W-->>API: 200 JSON
```

The mutating path is identical up to the engine, which applies every
`MutationPolicy` in name order to the decoded object in place, collecting
JSON Patch operations; the response carries `patchType: JSONPatch`.
`admitly eval` reproduces the API server's ordering offline: mutate, apply the
patch with an independent RFC 6902 implementation, then validate.

## Policy model

A policy is one YAML document (`apiVersion: admitly.dev/v1alpha1`):

| Kind | Body | Modes |
|---|---|---|
| `ValidationPolicy` | `validations[]`: CEL bool `expression`, `message` or `messageExpression`, `reason` | Enforce, Audit, Disabled |
| `ImageVerificationPolicy` | `verification.rules[]`: image globs + public keys (inline or `keyFiles`) | Enforce, Audit, Disabled |
| `MutationPolicy` | `mutation.podSecurityContext` / `containerSecurityContext` defaults | Enforce, Disabled |

Common fields: `match` (resource rules with groups, kinds, operations,
sub-resources; namespace allow/deny globs), `matchConditions` (CEL),
`params` (free-form, exposed as `params`), `variables` (named CEL values,
evaluated in order, exposed as `variables.<name>`), `failurePolicy`,
`severity`, `description`.

### CEL environment

| Variable | Content |
|---|---|
| `object`, `oldObject` | decoded objects (null when absent) |
| `request` | uid, operation, namespace, name, subResource, dryRun, kind, resource, userInfo |
| `params`, `variables` | per policy |
| `podSpec`, `podMeta` | pod spec and its metadata for Pod and 7 workload kinds, else null |
| `containers` | init + regular + ephemeral containers of `podSpec` |

Extensions: cel-go optional types (`a.?b.orValue(x)`), strings, sets, lists,
math; plus `parseImage(s)` (registry, repository, name, tag, digest),
`s.matchesGlob(pattern)`, and two Kubernetes-quantity helpers:
`quantityCompare(a, b)` (-1/0/1, exact via `resource.Quantity.Cmp` up to a
magnitude of 10^1000; larger values such as `1e100000000` compare as
+/-infinity) and `quantityMilli(q)` (milli-units as int; an evaluation error when
the value does not fit in int64, e.g. `10Pi`, instead of wrapping negative).
Limit checks should use `quantityCompare`. Both reject quantity strings longer
than 128 characters and never hand an out-of-range decimal exponent to
`math/big`: a native function call cannot be interrupted by the deadline, so
its cost must be bounded by construction.

Pod-spec locations are a static table (`internal/engine/input.go`):
`/spec` (Pod), `/spec/template/spec` (Deployment, StatefulSet, DaemonSet,
ReplicaSet, ReplicationController, Job), `/spec/jobTemplate/spec/template/spec`
(CronJob). Extracting once lets every policy be kind-agnostic.

## Key algorithms and complexity

Let *P* be the number of policies, *E* the expressions per policy, *C* the
containers in the pod spec, *B* the request body size.

| Step | Algorithm | Cost |
|---|---|---|
| Decode | `sigs.k8s.io/json` case-sensitive unmarshal, ints preserved | O(B) |
| Pod-spec extraction | fixed-depth map walk | O(depth + C) |
| Matching | linear scan of rules; anchored component glob | O(rules) per policy; glob O(len(p) x len(s)) worst case, iterative (no backtracking explosion) |
| CEL evaluation | compiled once per policy-set load (type-checked ASTs); evaluation is tree-walking | O(P x E x C) for the built-ins, which iterate containers. With cost tracking cel-go v0.29.2 makes a comprehension over n items O(n^2) in time (see `BenchmarkComprehension`); bounded by the request deadline |
| Signature verification | LRU (container/list + map) keyed by repo@digest + key-set id; miss = read store file, JSON-decode records, check payload binding, verify each signature against each key | hit O(1); miss O(S x K) signature checks for S stored signatures and K keys |
| Mutation | recursive set-if-absent merge over sorted keys | O(C x D) for D default leaves; output is deterministic |
| Policy reload | SHA-256 fingerprint of policy directories every `reloadInterval`; full compile only when it changes; atomic pointer swap | O(total policy bytes) per tick |

In-flight requests keep the `PolicySet` pointer they started with, so a
reload never mixes old and new policies within one review.

## Concurrency

- `engine.Engine`: immutable compiled sets behind `atomic.Pointer`; evaluation
  allocates per-request activations; safe for concurrent use (tested with
  32 goroutines under `-race`).
- `signature.Verifier`: mutex-guarded LRU; only positive results are cached so
  newly added signatures take effect immediately.
- `tlsutil.Reloader`: mutex-guarded; stats the certificate files at most once
  per interval during handshakes.
- `audit.Logger`: mutex around a JSON encoder; write failures are logged and
  never change a decision.

## Decision mapping

| Engine result | Validate response | Mutate response |
|---|---|---|
| no violations | `allowed: true` | `allowed: true` (+ `patch` if any) |
| Audit violations only | `allowed: true`, `warnings: ["[audit] <policy>: <msg>"]`, `auditAnnotations.audit-violations` (JSON) | - |
| Enforce violations | `allowed: false`, status 403 Forbidden (422 Invalid / 401 Unauthorized when the validation's `reason` says so), message lists every `[policy] message` | - |
| eval error, failurePolicy Fail | violation with reason InternalError in the policy's mode | `allowed: false`, 500 |
| eval error, failurePolicy Ignore | `auditAnnotations.ignored-errors` | same |
| deadline / panic / undecodable / no policies | failure mode: Closed -> 500 deny; Open -> allow + warning | same |

Warnings are sanitised (single line, valid UTF-8, <= 240 bytes) to stay under
the API server's warning header limits.

## Observability

- Metrics (`/metrics`): `admitly_admission_requests_total{endpoint,decision}`,
  `admitly_admission_duration_seconds{endpoint}`,
  `admitly_policy_evaluations_total{policy,outcome}`,
  `admitly_policy_reloads_total{result}`, `admitly_policy_set_generation`,
  `admitly_bad_requests_total{reason}`, plus Go/process collectors.
- Logs: structured JSON via `log/slog`.
- Audit: one JSON line per decision (see `internal/audit`).
- Probes: `/healthz` (process), `/readyz` (a policy set is loaded).
