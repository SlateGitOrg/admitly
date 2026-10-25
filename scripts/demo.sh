#!/usr/bin/env bash
# Offline end-to-end demo: generates a lab signing key and TLS material,
# signs one image, evaluates example manifests with `admitly eval`, then runs
# the real HTTPS webhook and sends it AdmissionReview v1 requests with curl.
# Everything lives under .demo/ (gitignored) and runs against local fixtures.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
bin="./bin/admitly"
demo=".demo"
[ -x "$bin" ] || { echo "build first: make build" >&2; exit 1; }

rm -rf "$demo"
mkdir -p "$demo/policies"

step() { printf '\n==> %s\n' "$*"; }

step "1. Lab signing key and webhook TLS material"
"$bin" keygen --out "$demo/keys"
"$bin" certs --hosts 127.0.0.1,localhost --out "$demo/certs" --days 1

step "2. Sign the images we trust (the 'unsigned' image is left unsigned)"
"$bin" sign --key "$demo/keys/cosign.key" --store "$demo/signatures" \
  registry.lab.local/shop/checkout@sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945 \
  registry.lab.local/shop/storefront@sha256:1d3f0c9a7b2e4d6f8a0c2e4f6a8b0d2f4a6c8e0b2d4f6a8c0e2a4c6e8a0b2d4f \
  registry.lab.local/team/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
"$bin" verify --key "$demo/keys/cosign.pub" --store "$demo/signatures" \
  registry.lab.local/shop/checkout@sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945 \
  registry.lab.local/shop/unsigned@sha256:9b2a0f1fbc6a7ba6e1c8e0c3cfa8f0f9d2c2c8b1b6e7d5a4c3b2a1f0e9d8c7b6 || true

cp examples/policies/*.yaml "$demo/policies/"
cp "$demo/keys/cosign.pub" "$demo/policies/cosign.pub"
port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
cat > "$demo/admitly.yaml" <<EOF
listen: 127.0.0.1:$port
tls: {certFile: certs/tls.crt, keyFile: certs/tls.key}
failureMode: Closed
timeout: 3s
policies: {builtin: true, dirs: [policies], reloadInterval: 2s}
signatures: {storeDir: signatures}
audit: {file: audit.log}
logLevel: warn
EOF

step "3. Lint the policy set (built-ins + examples/policies)"
"$bin" lint --config "$demo/admitly.yaml"

step "4. Offline evaluation of examples/manifests/pods.yaml (mutate -> validate)"
"$bin" eval --config "$demo/admitly.yaml" --fail-on-deny=false examples/manifests/pods.yaml

step "5. Start the HTTPS webhook on 127.0.0.1:$port"
"$bin" serve --config "$demo/admitly.yaml" 2>"$demo/server.log" &
pid=$!
trap 'kill $pid 2>/dev/null || true; wait $pid 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do
  curl -sf --cacert "$demo/certs/ca.crt" "https://127.0.0.1:$port/readyz" >/dev/null 2>&1 && break
  sleep 0.1
done
echo "readyz: $(curl -s --cacert "$demo/certs/ca.crt" "https://127.0.0.1:$port/readyz")"

summarise() {
  python3 -c '
import base64, json, sys
r = json.load(sys.stdin)["response"]
out = {"uid": r["uid"], "allowed": r["allowed"]}
if r.get("status"): out["status"] = {k: r["status"][k] for k in ("code", "reason", "message") if k in r["status"]}
if r.get("warnings"): out["warnings"] = r["warnings"]
if r.get("patch"): out["patch"] = json.loads(base64.b64decode(r["patch"]))
if r.get("auditAnnotations"): out["auditAnnotations"] = r["auditAnnotations"]
print(json.dumps(out, indent=2))'
}

for c in validate-privileged-pod validate-audit-latest-tag validate-unsigned-image mutate-pod-defaults; do
  endpoint=validate; [[ $c == mutate-* ]] && endpoint=mutate
  step "6. POST testdata/golden/$c.request.json -> /$endpoint"
  curl -s --cacert "$demo/certs/ca.crt" -H 'Content-Type: application/json' \
    --data-binary "@testdata/golden/$c.request.json" "https://127.0.0.1:$port/$endpoint?timeout=10s" | summarise
done

step "7. Hot reload: switch disallow-latest-tag from Audit to Enforce without a restart"
sed -i.bak 's/mode: Audit/mode: Enforce/' "$demo/policies/disallow-latest-tag.yaml" && rm -f "$demo/policies/disallow-latest-tag.yaml.bak"
for _ in $(seq 1 40); do
  out="$(curl -s --cacert "$demo/certs/ca.crt" -H 'Content-Type: application/json' \
    --data-binary @testdata/golden/validate-audit-latest-tag.request.json "https://127.0.0.1:$port/validate" | summarise)"
  grep -q '"allowed": false' <<<"$out" && break
  sleep 0.25
done
echo "$out"

step "8. Malformed requests are rejected before evaluation"
printf 'wrong content type -> HTTP %s\n' "$(curl -s -o /dev/null -w '%{http_code}' --cacert "$demo/certs/ca.crt" -H 'Content-Type: text/plain' --data 'x' "https://127.0.0.1:$port/validate")"
printf 'v1beta1 review     -> HTTP %s\n' "$(sed 's#admission.k8s.io/v1#admission.k8s.io/v1beta1#' testdata/golden/validate-compliant-pod.request.json | curl -s -o /dev/null -w '%{http_code}' --cacert "$demo/certs/ca.crt" -H 'Content-Type: application/json' --data-binary @- "https://127.0.0.1:$port/validate")"
printf 'untrusted client   -> %s\n' "$(curl -s -o /dev/null "https://127.0.0.1:$port/healthz" 2>&1 && echo 'connected (unexpected)' || echo 'TLS verification failed (expected: client does not trust the webhook CA)')"

step "9. Metrics excerpt"
curl -s --cacert "$demo/certs/ca.crt" "https://127.0.0.1:$port/metrics" | grep -E '^admitly_(admission_requests_total|policy_reloads_total|policy_set_generation|bad_requests_total)' | sort

step "10. Audit log (one JSON line per decision; first record shown)"
head -n 1 "$demo/audit.log" | python3 -m json.tool
echo "audit records: $(wc -l < "$demo/audit.log" | tr -d ' ')"

step "demo complete (artifacts in .demo/)"
