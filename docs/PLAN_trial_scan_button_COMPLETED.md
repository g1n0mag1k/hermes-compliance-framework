# PLAN — Trial Scan Button

Source decisions: `1B` (dedicated `POST /v1/trial-scan`) + `2B` (Portfolio header + restore `lib/api.js` + add `GET /v1/status`).
Quota addendum: trial scan quota persists in SQLite across server restarts.
Rules: `CURSORRULES.md`. Do not start implementation until owner says **GO**.

---

## 1. BRANCH

- Create and work on: `cursor/trial-scan-button-46fa`
- Base: `main` (never commit directly to `main`)
- Push target: `origin/cursor/trial-scan-button-46fa`

---

## 2. BACKEND CHANGES

### Files touched in `hermes/`

| File | Change |
|------|--------|
| [`hermes/api.py`](hermes/api.py) | Add `StatusResponse` model + `GET /v1/status` (includes trial quota fields). Add `POST /v1/trial-scan` with SQLite-backed quota enforcement. Add helpers to create/read/increment `trial_quota` in `hermes_chain.db` (via `HERMES_DB_PATH`) without modifying `attestation.py`. |

### New functions / endpoints

- Helpers in `api.py` (names may be `_ensure_trial_quota_table`, `_get_trial_quota`, `_increment_trial_quota`):
  - Ensure `trial_quota` table exists
  - Read / write quota for `workspace_id='default'`
- `GET /v1/status` — `status_endpoint()` (API-key auth via existing `verify_api_key`). Aggregates attestation-chain metrics for the dashboard (`chain_position`, `total_scans`, `last_scan_at`, `zero_phi_egress_confirmed`, `phi_classes_detected_today`, `critical_findings_open`, `evidence_current_as_of`, `chain_integrity`). Also reads `scans_used` and `first_scan_at` from `trial_quota` and returns:
  - `scans_used`
  - `scans_remaining` (max `5 - scans_used`, floored at 0)
  - `trial_expires_at` — `first_scan_at + 14 days` when `first_scan_at` is set; empty/null when no trial has started
  - `trial_active` — `true` only when **both** `scans_used < 5` **and** now is before `trial_expires_at`; returns `false` after the 14-day window even if `scans_remaining > 0`
- `POST /v1/trial-scan` — `trial_scan_endpoint()` (API-key auth). No request body. Behavior:
  1. Read `scans_used` / `first_scan_at` from `trial_quota` **before** every scan
  2. If `scans_used >= 5` **or** the 14-day window has expired (`now >= first_scan_at + 14 days`), return **429** (do not scrub, do not increment)
  3. Build canary text from `hermes.auditor.CANARY_CORPUS` (same pattern as `tests/test_agent.py`)
  4. Call `scrub_payload` + `_issue_scrub_attestation`; enqueue `dispatch_webhook` and `dispatch_drata_cct`
  5. On **successful** scan only, write/increment `scans_used` (set `first_scan_at` on first success); **never** increment on error, timeout, or failed scan
  6. Return `ScrubResponse`

### New database tables

- **`trial_quota`** in the **same** `hermes_chain.db` file the attestation chain already uses (path from `HERMES_DB_PATH`). **Not** a separate database file. Table creation/reads/writes live in `api.py` only:

```sql
CREATE TABLE IF NOT EXISTS trial_quota (
  workspace_id TEXT PRIMARY KEY DEFAULT 'default',
  scans_used INTEGER DEFAULT 0,
  first_scan_at TEXT,
  extended_by INTEGER DEFAULT 0
)
```

- Quota **must** persist across server restarts (SQLite file, not in-memory).
- No other new tables.

### Will NOT touch (backend)

- `hermes/classifier.py`
- `hermes/attestation.py`
- `hermes/webhooks.py`
- `hermes/agent.py`, `hermes/auditor.py`, `hermes/proxy.py`, `hermes/vault.py`, `hermes/report.py`, `hermes/cli.py`, `hermes/demo.py`, `hermes/benchmark.py`, `hermes/__init__.py`
- No new Python dependencies
- No changes to existing `/v1/scrub` or `/v1/review` contracts beyond additive endpoints in `api.py`

---

## 3. FRONTEND CHANGES

### Files touched in `dashboard/src/`

| File | Change |
|------|--------|
| [`dashboard/src/lib/api.js`](dashboard/src/lib/api.js) | **Create** (missing on `main` but already imported by `App.jsx`). Export `API_URL`, `fetchStatus()`, and new `runTrialScan()`. |
| [`dashboard/src/components/TrialScanButton.jsx`](dashboard/src/components/TrialScanButton.jsx) | **Create.** Button that calls `runTrialScan()`, shows loading/error/success (including 429 quota exhausted), then invokes an `onComplete` callback so the parent can refresh status. |
| [`dashboard/src/components/PortfolioHeader.jsx`](dashboard/src/components/PortfolioHeader.jsx) | Mount `TrialScanButton` in the portfolio header row (next to brand / subtitle area). Accept `onScanComplete` prop and pass through. |
| [`dashboard/src/App.jsx`](dashboard/src/App.jsx) | Pass `load` (status refresh) into `PortfolioHeader` as `onScanComplete` so a successful trial scan refreshes dashboard metrics. |

### New components / functions

- Component: `TrialScanButton`
- Functions in `api.js`: `fetchStatus`, `runTrialScan` (plus `API_URL` / `API_KEY` constants)

### Will NOT touch (frontend)

- `dashboard/src/components/ClientTable.jsx`
- `dashboard/src/components/ClientDetail.jsx`
- `dashboard/src/components/StatCard.jsx`
- `dashboard/src/components/TrendSparkline.jsx`
- `dashboard/src/main.jsx`
- `dashboard/src/index.css`
- `landing/**` (no landing-page changes)
- No new npm packages
- No changes to `dashboard/package.json` dependency list

---

## 4. TEST PLAN

### Baseline

- Confirmed current baseline: **136** `def test_` functions across `tests/` (matches owner-stated floor of 136).

### New tests to add (in [`tests/test_api.py`](tests/test_api.py))

1. `test_status_endpoint_requires_api_key` — missing/invalid key rejected
2. `test_status_endpoint_after_scrub` — after `/v1/scrub`, `/v1/status` reports chain metrics
3. `test_status_endpoint_includes_trial_quota_fields` — response includes `scans_used`, `scans_remaining`, `trial_active`, `trial_expires_at`
4. `test_trial_scan_endpoint_requires_api_key` — missing/invalid key rejected
5. `test_trial_scan_endpoint_returns_scrub_response` — 200, `clean_text` + `compliance_receipt` present, chain advances, quota increments by 1
6. `test_trial_scan_then_status_reflects_scan` — after trial scan, `/v1/status` `total_scans` / PHI classes / quota fields update
7. `test_trial_scan_returns_429_when_quota_exhausted` — after 5 successful trial scans, 6th returns 429 and does not increment further
8. `test_trial_quota_persists_after_simulated_restart` — run successful trial scan(s), create a new `AttestationChain` instance (simulated restart / new process handle on same DB path), verify `scans_used` is still correct via re-read of `trial_quota` / `/v1/status`

### Minimum passing count after changes

- **144** tests passing (136 baseline + 8 new). Floor never decreases.

---

## 5. BUILD VERIFICATION

- After frontend changes: run `npm run build` inside `dashboard/`
- After backend changes: run `.venv/bin/python -m pytest` (full suite; target ≥144 passing)
- Also: import/compile smoke as needed (`compileall` / dashboard build must succeed)

---

## 6. COMMIT PLAN

- Branch: `cursor/trial-scan-button-46fa`
- Commit message:

```
feat: add trial scan button with /v1/trial-scan and /v1/status

Wire MSP dashboard Trial Scan control to a dedicated canary endpoint,
persist trial quota in SQLite across restarts, restore dashboard api
client, and expose GET /v1/status for live metrics.
```

---

## 7. WHAT YOU WILL NOT DO

- No changes to `classifier.py`
- No changes to `attestation.py`
- No changes to `webhooks.py`
- No new Python dependencies
- No new npm packages
- No commits to `main`

---

## STOP

Plan only. Awaiting owner **GO** before any implementation.
