# Experimental modules

These modules are **unwired**. They are not imported by any application code under
`hermes/`, are **not copied into the shipped Docker image** (the Dockerfile only
`COPY`s `hermes/`), and are **not part of any compliance claim**.

| Module | Status |
|--------|--------|
| `vault.py` | Reversible token vault — exists for roadmap work; not called by `scrub_payload` |
| `proxy.py` | Zero-trust LLM scrub proxy — not mounted or imported by the API |

Do not treat presence of this directory as a product feature or audit control.
