#!/usr/bin/env bash
# End-to-end test of the canonical Docker Compose deployment.
#
# Runs the documented procedure (docs/DEPLOYMENT.md) against a fresh copy of
# this repository's working tree (tracked + untracked, minus .gitignore'd
# files — i.e. what a clean clone would contain), using a mock upstream
# provider (tests/docker/mock_provider.py) so forwarding can be counted.
#
#   tests/docker/e2e.sh
#
# Environment:
#   E2E_NO_CACHE=1        build the image with --no-cache
#   E2E_KEEP=1            leave the stack, volumes and work dir in place
#   E2E_PROVIDER_PROBE=1  also send one clean request to the real
#                         api.openai.com with an invalid key (expects 401)
#
# Requires: docker (with compose plugin), curl, python3, git. Host ports
# 127.0.0.1:8787 and 127.0.0.1:8788 must be free.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROJECT="hermes-e2e"
WS="e2e-clinic"
WORK="$(mktemp -d /tmp/hermes-e2e.XXXXXX)"
OUT="$WORK/receipt-export"
API="http://127.0.0.1:8787"
GW="http://127.0.0.1:8788"

log()  { printf '\n=== %s\n' "$*"; }
ok()   { printf '  PASS  %s\n' "$*"; }
die()  { printf '  FAIL  %s\n' "$*" >&2; exit 1; }
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

cleanup() {
  local rc=$?
  if [[ "${E2E_KEEP:-0}" != "1" ]]; then
    (cd "$WORK" 2>/dev/null && "${DC[@]}" down -v --remove-orphans >/dev/null 2>&1) || true
    rm -rf "$WORK"
  else
    echo "E2E_KEEP=1: stack '$PROJECT' and $WORK left in place."
  fi
  if [[ $rc -eq 0 ]]; then echo; echo "E2E RESULT: ALL CHECKS PASSED"; else echo; echo "E2E RESULT: FAILED (exit $rc)"; fi
}
trap cleanup EXIT

log "Copy working tree to $WORK (clean-clone equivalent)"
(cd "$REPO_ROOT" && git ls-files -z --cached --others --exclude-standard \
  | xargs -0 -I{} sh -c 'test -e "{}" && printf "%s\0" "{}"' \
  | tar --null -T - -cf -) | tar -xf - -C "$WORK"
cd "$WORK"
mkdir -p "$OUT"
[[ ! -e .env.hermes ]] || die ".env.hermes must not be part of the repository copy"
DC=(docker compose -p "$PROJECT" -f docker-compose.yml -f tests/docker/docker-compose.test.yml)

log "Generate configuration"
./scripts/generate-env.sh
ADMIN_TOKEN="$(grep '^HERMES_ADMIN_TOKEN=' .env.hermes | cut -d= -f2)"
[[ ${#ADMIN_TOKEN} -eq 64 ]] || die "admin token not generated"
[[ "$(stat -c %a .env.hermes)" == "600" ]] || die ".env.hermes is not mode 600"
if [[ "${E2E_PROVIDER_PROBE:-0}" == "1" ]]; then
  sed -i 's|^HERMES_OPENAI_API_KEY=$|HERMES_OPENAI_API_KEY=sk-hermes-e2e-invalid-key|' .env.hermes
fi
ok ".env.hermes generated (mode 600)"

log "Build image"
BUILD_ARGS=()
[[ "${E2E_NO_CACHE:-0}" == "1" ]] && BUILD_ARGS+=(--no-cache)
"${DC[@]}" build "${BUILD_ARGS[@]}" hermes-api
ok "image hermes-relay:1.0.0 built"

log "Create persistent gateway keystore"
INIT_OUT="$("${DC[@]}" run --rm --no-deps hermes-gateway hermes-relay keystore-init)"
echo "$INIT_OUT"
KEY_ID="$(echo "$INIT_OUT" | sed -n 's/^key_id: //p')"
[[ -n "$KEY_ID" ]] || die "keystore-init did not report a key_id"
if "${DC[@]}" run --rm --no-deps hermes-gateway hermes-relay keystore-init >/dev/null 2>&1; then
  die "keystore-init overwrote an existing keystore"
fi
ok "keystore created, key_id=$KEY_ID; second keystore-init refused"

wait_healthy() {
  "${DC[@]}" up -d --wait --wait-timeout 300
  for svc in hermes-api hermes-gateway; do
    local state
    state="$(docker inspect -f '{{.State.Health.Status}}' "$("${DC[@]}" ps -q "$svc")")"
    [[ "$state" == "healthy" ]] || die "$svc health is $state"
  done
  ok "hermes-api and hermes-gateway containers report healthy"
}

check_endpoints() {
  local body
  body="$(curl -sS -f "$API/health")" || die "API /health failed"
  [[ "$(echo "$body" | json 'd["status"]')" == "operational" ]] || die "API health: $body"
  ok "host -> API $API/health: $body"
  body="$(curl -sS -f "$GW/gateway/health")" || die "gateway /gateway/health failed"
  ok "host -> gateway $GW/gateway/health: $body"
  "${DC[@]}" exec -T hermes-gateway python -c \
    "import urllib.request; print(urllib.request.urlopen('http://hermes-api:8787/health').read().decode())" >/dev/null \
    || die "gateway container cannot reach hermes-api:8787"
  ok "gateway container -> hermes-api:8787 reachable"
  if curl -sS -m 3 "http://$(hostname -I | awk '{print $1}'):8787/health" >/dev/null 2>&1; then
    die "API port 8787 is reachable on a non-loopback interface"
  fi
  ok "API port 8787 not reachable on non-loopback host address"
}

mock_requests() {
  "${DC[@]}" exec -T hermes-gateway python -c \
    "import urllib.request; print(urllib.request.urlopen('http://mock-provider:9000/__requests').read().decode())"
}

CLEAN_BODY='{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Summarize the benefits of regular exercise in two sentences."}]}'
PHI_BODY='{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Patient John Smith, SSN 234-56-7891, MRN 4452981, needs a follow-up."}]}'
GW_PATH="/gateway/azure_openai/openai/v1/chat/completions"

send_requests() {
  local phase="$1" before after status
  before="$(mock_requests | json 'len(d)')"

  status="$(curl -sS -o "$WORK/clean-$phase.json" -w '%{http_code}' -X POST "$GW$GW_PATH" \
    -H "X-API-Key: $WS_KEY" -H "Authorization: Bearer client-secret-must-not-leak" \
    -H "content-type: application/json" -d "$CLEAN_BODY")"
  [[ "$status" == "200" ]] || die "clean request returned $status: $(cat "$WORK/clean-$phase.json")"
  after="$(mock_requests)"
  [[ "$(echo "$after" | json 'len(d)')" == "$((before + 1))" ]] || die "clean request not forwarded exactly once"
  echo "$after" | CLEAN_BODY="$CLEAN_BODY" python3 -c '
import json, os, sys
r = json.load(sys.stdin)[-1]
assert r["body"] == os.environ["CLEAN_BODY"], "forwarded body differs from client body"
h = r["headers"]
assert h.get("api-key") == "mock-provider-key", "provider credential not injected"
assert "authorization" not in h and "x-api-key" not in h, "client auth header leaked upstream"
' || die "clean request forwarding checks failed"
  ok "[$phase] clean request: HTTP 200, forwarded once, body unchanged, client auth stripped, provider key injected"

  before="$(mock_requests | json 'len(d)')"
  status="$(curl -sS -o "$WORK/phi-$phase.json" -w '%{http_code}' -X POST "$GW$GW_PATH" \
    -H "X-API-Key: $WS_KEY" -H "content-type: application/json" -d "$PHI_BODY")"
  [[ "$status" == "403" ]] || die "PHI request returned $status (expected 403): $(cat "$WORK/phi-$phase.json")"
  [[ "$(json 'd["error"]["code"]' < "$WORK/phi-$phase.json")" == "phi_detected" ]] || die "403 body lacks phi_detected"
  after="$(mock_requests | json 'len(d)')"
  [[ "$after" == "$before" ]] || die "PHI request reached the upstream provider"
  if mock_requests | grep -q "234-56-7891"; then die "SSN observed at upstream"; fi
  ok "[$phase] PHI request: HTTP 403 phi_detected, upstream request count unchanged ($after)"

  status="$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$GW$GW_PATH" \
    -H "X-API-Key: not-a-real-key" -H "content-type: application/json" -d "$CLEAN_BODY")"
  [[ "$status" == "401" ]] || die "invalid workspace key returned $status"
  ok "[$phase] invalid workspace key: HTTP 401"
}

verify_export() {
  local phase="$1" expected="$2" dir="$OUT/$1" verify_out
  "${DC[@]}" exec -T hermes-gateway hermes-relay export-receipts --workspace "$WS" --out "/app/exports/$phase"
  "${DC[@]}" cp "hermes-gateway:/app/exports/$phase" "$dir" >/dev/null
  local n
  n="$(ls "$dir"/*.cose | wc -l)"
  [[ "$n" == "$expected" ]] || die "expected $expected receipts, found $n"
  local block
  block="$(ls "$dir"/*-BLOCK-*.cose | tail -1)"
  # Verification runs in a new container with no network and no access to the
  # data or keys volumes: only the exported receipts and public key.
  verify_out="$(docker run --rm --network none -v "$dir:/r:ro" hermes-relay:1.0.0 \
    hermes-verify receipt "/r/$(basename "$block")" --public-key /r/gateway-public.pem)"
  echo "$verify_out" | sed 's/^/    /'
  echo "$verify_out" | head -1 | grep -qx VALID || die "BLOCK receipt did not verify"
  echo "$verify_out" | grep -qx "decision: BLOCK" || die "receipt decision is not BLOCK"
  echo "$verify_out" | grep -qx "forwarded: False" || die "BLOCK receipt says forwarded"
  echo "$verify_out" | grep -qx "signer_key_id: $KEY_ID" || die "BLOCK receipt signed by unexpected key"
  ok "[$phase] latest BLOCK receipt: hermes-verify VALID, forwarded False, signer_key_id=$KEY_ID"

  verify_out="$(docker run --rm --network none -v "$dir:/r:ro" hermes-relay:1.0.0 \
    hermes-verify chain /r --public-key /r/gateway-public.pem --workspace-id "$WS")"
  echo "$verify_out" | sed 's/^/    /'
  echo "$verify_out" | head -1 | grep -qx VALID || die "receipt chain did not verify"
  echo "$verify_out" | grep -qx "receipts: $expected" || die "chain length mismatch"
  echo "$verify_out" | grep -qx "signer_key_ids: $KEY_ID" || die "chain signed by more than one key"
  ok "[$phase] full chain of $expected receipts: VALID, single signer_key_id=$KEY_ID"
}

log "Phase 1: first startup"
wait_healthy
check_endpoints
LOGS="$("${DC[@]}" logs hermes-gateway 2>&1)"
echo "$LOGS" | grep -q "Application startup complete" || die "gateway did not complete startup"

log "Phase 1: create workspace via loopback API with X-Admin-Token"
status="$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$API/v1/workspaces" -H "content-type: application/json" \
  -d "{\"workspace_id\":\"$WS\",\"name\":\"E2E Clinic\",\"owner_email\":\"it@e2e-clinic.example\",\"plan\":\"production\"}")"
[[ "$status" == "401" ]] || die "workspace creation without admin token returned $status"
ok "workspace creation without X-Admin-Token: HTTP 401"
WS_KEY="$(curl -sS -f -X POST "$API/v1/workspaces" -H "X-Admin-Token: $ADMIN_TOKEN" -H "content-type: application/json" \
  -d "{\"workspace_id\":\"$WS\",\"name\":\"E2E Clinic\",\"owner_email\":\"it@e2e-clinic.example\",\"plan\":\"production\"}" \
  | json 'd["api_key"]')"
[[ ${#WS_KEY} -eq 64 ]] || die "no workspace API key returned"
ok "workspace '$WS' created; one-time API key received"

send_requests phase1
verify_export phase1 2

if [[ "${E2E_PROVIDER_PROBE:-0}" == "1" ]]; then
  log "Real provider probe: api.openai.com with an invalid key"
  status="$(curl -sS -o "$WORK/openai.json" -w '%{http_code}' -X POST "$GW/gateway/openai/v1/chat/completions" \
    -H "X-API-Key: $WS_KEY" -H "content-type: application/json" -d "$CLEAN_BODY")"
  echo "    upstream body: $(head -c 300 "$WORK/openai.json")"
  [[ "$status" == "401" ]] || die "expected OpenAI 401 passthrough, got $status"
  ok "gateway reached api.openai.com over HTTPS; provider 401 passed through"
  PROBE_RECEIPTS=1
else
  PROBE_RECEIPTS=0
fi

log "Phase 2: docker compose restart"
"${DC[@]}" restart
wait_healthy
check_endpoints
send_requests phase2
verify_export phase2 $((4 + PROBE_RECEIPTS))

log "Phase 3: docker compose down (volumes kept) then up"
"${DC[@]}" down
wait_healthy
check_endpoints
send_requests phase3
verify_export phase3 $((6 + PROBE_RECEIPTS))

log "Volume contents after down/up"
"${DC[@]}" exec -T hermes-gateway sh -c 'id; ls -ln /app/keys /app/data /app/data/workspaces "/app/data/workspaces/'"$WS"'"'
