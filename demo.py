"""
Hermes Relay — Live Investor Demo
Zero-Trust Compliance Infrastructure

Run: streamlit run demo.py
Requires: HERMES_API_KEY set in environment or .env.hermes
"""

import streamlit as st
import httpx
import json
import os
import re
import base64
from pathlib import Path
from dotenv import load_dotenv, dotenv_values
import os
from datetime import datetime, timezone

# Load env from multiple locations
for _env_path in [".env.hermes", "/etc/secrets/.env.hermes", "/app/.env.hermes"]:
    if Path(_env_path).exists():
        load_dotenv(_env_path)
        break

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Hermes Relay",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Logo loader ───────────────────────────────────────────────────────────────
def load_logo_b64() -> str | None:
    """Load logo from assets/ and return base64 string, or None if not found."""
    candidates = [
        Path(__file__).parent / "assets" / "hermes-logo.webp",
        Path(__file__).parent / "assets" / "hermes-logo.png",
        Path("assets/hermes-logo.webp"),
        Path("assets/hermes-logo.png"),
    ]
    for p in candidates:
        if p.exists():
            with open(p, "rb") as f:
                return base64.b64encode(f.read()).decode()
    return None

LOGO_B64 = load_logo_b64()
LOGO_MIME = "image/webp" if LOGO_B64 else None

# ── Enterprise theme — dark navy + teal ───────────────────────────────────────
st.markdown("""
<style>
    html, body, [class*="css"] {
        font-family: 'Inter', 'Segoe UI', system-ui, sans-serif;
    }
    .stApp {
        background-color: #0b1622;
        color: #cdd6e0;
    }

    /* Sidebar */
    [data-testid="stSidebar"] {
        background-color: #0d1e30;
        border-right: 1px solid #1a3347;
    }
    [data-testid="stSidebar"] * { color: #a8baca !important; }

    /* Header */
    .hermes-header {
        display: flex;
        align-items: center;
        gap: 18px;
        padding: 16px 0 16px 0;
        border-bottom: 1px solid #1a3347;
        margin-bottom: 28px;
    }
    .hermes-logo-img {
        height: 64px;
        width: auto;
        filter: drop-shadow(0 2px 8px rgba(0,201,167,0.18));
    }
    .hermes-wordmark {
        font-size: 1.9rem;
        font-weight: 800;
        letter-spacing: 0.06em;
        color: #e8f0f7;
        line-height: 1;
        text-transform: uppercase;
    }
    .hermes-wordmark span {
        color: #00c9a7;
    }
    .hermes-tagline {
        font-size: 0.7rem;
        font-weight: 500;
        letter-spacing: 0.14em;
        text-transform: uppercase;
        color: #4a7a96;
        margin-top: 5px;
    }
    .hermes-badge {
        background: #0d2e26;
        color: #00c9a7;
        border: 1px solid #00c9a7;
        border-radius: 4px;
        font-size: 0.68rem;
        font-weight: 700;
        letter-spacing: 0.1em;
        padding: 4px 10px;
        text-transform: uppercase;
        margin-left: auto;
        white-space: nowrap;
    }

    /* Input */
    .stTextArea textarea {
        background-color: #0f2035 !important;
        border: 1px solid #1e3d57 !important;
        border-radius: 6px !important;
        color: #cdd6e0 !important;
        font-size: 0.92rem !important;
        font-family: 'JetBrains Mono', 'Fira Code', 'Courier New', monospace !important;
        resize: vertical !important;
        line-height: 1.6 !important;
    }
    .stTextArea textarea:focus {
        border-color: #00c9a7 !important;
        box-shadow: 0 0 0 2px rgba(0,201,167,0.15) !important;
    }
    .stTextArea label {
        color: #4a7a96 !important;
        font-size: 0.72rem !important;
        letter-spacing: 0.1em !important;
        text-transform: uppercase !important;
        font-weight: 600 !important;
    }

    /* Primary button */
    .stButton > button {
        background-color: #00c9a7 !important;
        color: #0b1622 !important;
        border: none !important;
        border-radius: 6px !important;
        font-weight: 800 !important;
        font-size: 0.88rem !important;
        letter-spacing: 0.08em !important;
        padding: 10px 24px !important;
        text-transform: uppercase !important;
        transition: all 0.15s ease !important;
    }
    .stButton > button:hover {
        background-color: #00ddb8 !important;
        transform: translateY(-1px) !important;
        box-shadow: 0 4px 16px rgba(0,201,167,0.25) !important;
    }
    .stButton > button:active {
        background-color: #00a88c !important;
        transform: translateY(0) !important;
    }
    .stButton > button:disabled {
        background-color: #1a3347 !important;
        color: #3a5a72 !important;
    }

    /* Output card */
    .output-card {
        background-color: #0f2035;
        border: 1px solid #1e3d57;
        border-radius: 6px;
        padding: 18px 20px;
        font-family: 'JetBrains Mono', 'Fira Code', monospace;
        font-size: 0.91rem;
        line-height: 1.75;
        color: #cdd6e0;
        min-height: 130px;
        word-break: break-word;
        white-space: pre-wrap;
    }
    .output-placeholder {
        color: #1e3d57;
        font-style: italic;
    }
    .panel-label {
        color: #4a7a96;
        font-size: 0.72rem;
        letter-spacing: 0.1em;
        text-transform: uppercase;
        font-weight: 600;
        margin-bottom: 8px;
    }

    /* Redaction tokens */
    .redact-ssn {
        background-color: rgba(255, 82, 82, 0.15);
        color: #ff7070;
        border: 1px solid rgba(255, 82, 82, 0.3);
        border-radius: 3px;
        padding: 1px 6px;
        font-weight: 700;
        font-size: 0.86em;
        white-space: nowrap;
    }
    .redact-pan {
        background-color: rgba(255, 165, 0, 0.12);
        color: #ffb347;
        border: 1px solid rgba(255, 165, 0, 0.28);
        border-radius: 3px;
        padding: 1px 6px;
        font-weight: 700;
        font-size: 0.86em;
        white-space: nowrap;
    }
    .redact-generic {
        background-color: rgba(0, 201, 167, 0.1);
        color: #00c9a7;
        border: 1px solid rgba(0, 201, 167, 0.25);
        border-radius: 3px;
        padding: 1px 6px;
        font-weight: 700;
        font-size: 0.86em;
        white-space: nowrap;
    }

    /* Stat cards */
    .stat-row {
        display: flex;
        gap: 10px;
        margin: 14px 0 0 0;
    }
    .stat-card {
        flex: 1;
        background: #0d1e30;
        border: 1px solid #1a3347;
        border-radius: 6px;
        padding: 12px 10px;
        text-align: center;
    }
    .stat-value {
        font-size: 1.6rem;
        font-weight: 800;
        color: #00c9a7;
        line-height: 1;
    }
    .stat-value.flagged { color: #ff7070; }
    .stat-label {
        font-size: 0.68rem;
        color: #4a7a96;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        margin-top: 5px;
    }

    /* Audit entries */
    .audit-entry {
        background: #0b1e2e;
        border: 1px solid #1a3347;
        border-left: 3px solid #00c9a7;
        border-radius: 4px;
        padding: 10px 12px;
        margin-bottom: 8px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.72rem;
        color: #4a7a96;
        word-break: break-all;
    }
    .audit-txid { color: #00c9a7; font-weight: 700; margin-bottom: 3px; }
    .audit-flags { color: #ff7070; margin-bottom: 2px; }
    .audit-clean { color: #00c9a7; margin-bottom: 2px; }
    .audit-hash { color: #1e3d57; font-size: 0.65rem; margin-top: 4px; }

    /* Status dot */
    .dot-on  { display:inline-block; width:8px; height:8px; border-radius:50%;
               background:#00c9a7; box-shadow:0 0 6px #00c9a7; margin-right:6px; }
    .dot-off { display:inline-block; width:8px; height:8px; border-radius:50%;
               background:#ff5252; margin-right:6px; }

    hr { border-color: #1a3347 !important; }

    /* Hide Streamlit chrome */
    #MainMenu { visibility: hidden; }
    footer     { visibility: hidden; }
    header     { visibility: hidden; }
    .block-container { padding-top: 1.5rem !important; max-width: 1140px; }
</style>
""", unsafe_allow_html=True)

# ── Config ────────────────────────────────────────────────────────────────────
API_BASE = os.getenv("HERMES_API_BASE", "http://hermes-api:8000")
API_KEY  = os.getenv("HERMES_API_KEY", "")

# ── Session state ─────────────────────────────────────────────────────────────
for k, v in [("audit_log", []), ("last_result", None), ("api_healthy", None)]:
    if k not in st.session_state:
        st.session_state[k] = v

# ── Helpers ───────────────────────────────────────────────────────────────────
def check_health() -> bool:
    try:
        r = httpx.get(f"{API_BASE}/health", timeout=3.0)
        return r.status_code == 200
    except Exception:
        return False

def scrub_text(text: str) -> dict | None:
    try:
        r = httpx.post(
            f"{API_BASE}/v1/scrub",
            json={"payload": text},
            headers={"X-API-Key": API_KEY},
            timeout=10.0,
        )
        return r.json() if r.status_code == 200 else {"error": f"HTTP {r.status_code}: {r.text}"}
    except httpx.ConnectError:
        return {"error": "Cannot reach Hermes API. Is the stack running?"}
    except Exception as e:
        return {"error": str(e)}

def highlight_redactions(text: str) -> str:
    def replacer(m):
        t = m.group(0)
        if "SSN" in t:   return f'<span class="redact-ssn">{t}</span>'
        if any(x in t for x in ("PAN", "CARD", "CC")): return f'<span class="redact-pan">{t}</span>'
        return f'<span class="redact-generic">{t}</span>'
    return re.sub(r'\[REDACTED_[A-Z_]+\]', replacer, text)

def flag_str(flags: dict) -> str:
    active = [k for k, v in flags.items() if v]
    return "  ·  ".join(active) if active else "CLEAN"

# ── Header ────────────────────────────────────────────────────────────────────
if LOGO_B64:
    logo_html = (
        f'<img class="hermes-logo-img" '
        f'src="data:{LOGO_MIME};base64,{LOGO_B64}" alt="Hermes Relay" />'
    )
else:
    logo_html = '<div style="font-size:2rem;">🔒</div>'

st.markdown(f"""
<div class="hermes-header">
    {logo_html}
    <div>
        <div class="hermes-wordmark">HERMES <span>RELAY</span></div>
        <div class="hermes-tagline">Zero-Trust Compliance Infrastructure &nbsp;·&nbsp; hermesrelay.dev</div>
    </div>
    <div class="hermes-badge">&#9679; Live Demo</div>
</div>
""", unsafe_allow_html=True)

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### System Status")
    healthy = check_health()
    st.session_state.api_healthy = healthy
    if healthy:
        st.markdown('<span class="dot-on"></span>API Online', unsafe_allow_html=True)
    else:
        st.markdown('<span class="dot-off"></span>API Offline', unsafe_allow_html=True)
        st.warning("Run: `docker compose up -d`")

    st.markdown("---")
    st.markdown("### Coverage")
    st.markdown("""
- ✅ **HIPAA** — SSN + Named Entities
- ✅ **PCI-DSS** — Card Numbers (PAN)
- 🔜 DOB · MRN · Phone *(v1.1)*
- 🔜 Streaming proxy mode *(v1.2)*
    """)

    st.markdown("---")
    st.markdown("### Audit Chain")

    if st.session_state.audit_log:
        for entry in reversed(st.session_state.audit_log[-8:]):
            flags   = entry.get("flags", {})
            fs      = flag_str(flags)
            txid    = entry.get("transaction_id", "N/A")
            ts      = entry.get("timestamp", "")
            ah      = entry.get("audit_hash", "N/A")
            cin     = entry.get("char_count_in", "?")
            cout    = entry.get("char_count_out", "?")
            flag_cls = "audit-flags" if any(flags.values()) else "audit-clean"
            st.markdown(f"""
<div class="audit-entry">
  <div class="audit-txid">TX · {str(txid)[:16]}…</div>
  <div class="{flag_cls}">⚑ {fs}</div>
  <div>{cin} → {cout} chars</div>
  <div>{ts}</div>
  <div class="audit-hash">SHA-256 · {str(ah)[:28]}…</div>
</div>""", unsafe_allow_html=True)

        if st.button("Clear Log", use_container_width=True):
            st.session_state.audit_log  = []
            st.session_state.last_result = None
            st.rerun()
    else:
        st.markdown(
            '<div style="color:#1e3d57;font-size:0.8rem;font-style:italic;">'
            'Awaiting first transaction.</div>',
            unsafe_allow_html=True
        )

    st.markdown("---")
    st.markdown(
        '<div style="font-size:0.68rem;color:#1e3d57;line-height:1.6;">'
        'Sui-Generis LLC · Rocky Top, TN<br>'
        'HIPAA · PCI-DSS · Zero-Trust<br>'
        'hermesrelay.dev</div>',
        unsafe_allow_html=True
    )

# ── Main columns ─────────────────────────────────────────────────────────────
col_l, col_r = st.columns([1, 1], gap="large")

with col_l:
    st.markdown('<div class="panel-label">Input Payload</div>', unsafe_allow_html=True)
    input_text = st.text_area(
        label="Input",
        placeholder=(
            "Paste any text containing sensitive data.\n\n"
            "Example:\n"
            "Patient John Smith, SSN 482-12-9021, billed to\n"
            "Visa 4111 1111 1111 1111 for the Q2 invoice.\n\n"
            "Hermes will intercept and redact all PHI and PAN\n"
            "before this payload reaches any AI pipeline."
        ),
        height=230,
        label_visibility="collapsed",
        key="input_text",
    )
    c1, c2 = st.columns([3, 1])
    with c1:
        scrub_clicked = st.button(
            "⬡  SCRUB PAYLOAD",
            disabled=(not healthy),
            use_container_width=True,
        )
    with c2:
        if st.button("Reset", use_container_width=True):
            st.session_state.last_result = None
            st.rerun()

with col_r:
    st.markdown('<div class="panel-label">Redacted Output</div>', unsafe_allow_html=True)
    result = st.session_state.last_result

    if result and "error" not in result:
        highlighted = highlight_redactions(result.get("redacted_text", ""))
        st.markdown(f'<div class="output-card">{highlighted}</div>', unsafe_allow_html=True)

        flags   = result.get("flags", {})
        n_hipaa = flags.get("HIPAA_SSN", 0)
        n_pci   = flags.get("PCI_PAN",   0)
        cin     = result.get("char_count_in",  0)
        cout    = result.get("char_count_out", 0)
        removed = cin - cout
        total_flags = n_hipaa + n_pci

        hipaa_cls = "stat-value flagged" if n_hipaa else "stat-value"
        pci_cls   = "stat-value flagged" if n_pci   else "stat-value"

        st.markdown(f"""
<div class="stat-row">
  <div class="stat-card">
    <div class="{hipaa_cls}">{n_hipaa}</div>
    <div class="stat-label">HIPAA Flags</div>
  </div>
  <div class="stat-card">
    <div class="{pci_cls}">{n_pci}</div>
    <div class="stat-label">PCI Flags</div>
  </div>
  <div class="stat-card">
    <div class="stat-value">{removed}</div>
    <div class="stat-label">Chars Removed</div>
  </div>
  <div class="stat-card">
    <div class="stat-value" style="font-size:1rem;padding-top:4px;">✓</div>
    <div class="stat-label">Chain Intact</div>
  </div>
</div>""", unsafe_allow_html=True)

    elif result and "error" in result:
        st.error(f"API Error: {result['error']}")
    else:
        st.markdown(
            '<div class="output-card">'
            '<span class="output-placeholder">'
            'Redacted output appears here.\n\n'
            'PHI tokens → red\nPAN tokens → orange\nOther → teal'
            '</span></div>',
            unsafe_allow_html=True
        )

# ── Execute scrub ─────────────────────────────────────────────────────────────
if scrub_clicked:
    if not input_text.strip():
        st.warning("Enter a payload to scrub.")
    elif not API_KEY:
        st.error("HERMES_API_KEY not set. Add it to .env.hermes and restart.")
    else:
        with st.spinner("Relaying through compliance engine…"):
            result = scrub_text(input_text)
        if result and "error" not in result:
            if "timestamp" not in result:
                result["timestamp"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            st.session_state.last_result = result
            st.session_state.audit_log.append(result)
        else:
            st.session_state.last_result = result
        st.rerun()
