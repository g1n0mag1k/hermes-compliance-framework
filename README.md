# Hermes Compliance Framework

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)]()
[![Compliance](https://img.shields.io/badge/HIPAA-Ready-success.svg)]()
[![DSCSA](https://img.shields.io/badge/DSCSA-Compliant-success.svg)]()

**Hermes** is an enterprise-grade compliance and deterministic redaction layer built for healthcare organizations and Managed Service Providers (MSPs). It allows organizations to safely deploy AI, Copilot, and LLM-driven workflows by ensuring Protected Health Information (PHI) never leaves the client tenant.

By sitting between local endpoints and external AI APIs, Hermes intercepts, evaluates, and deterministically redacts sensitive data to maintain strict HIPAA and DSCSA supply chain compliance.

## Core Capabilities

*   **Deterministic PHI Redaction:** Utilizes strict, rule-based logic and localized NLP models to identify and strip PHI *before* it hits the transport layer. 
*   **Zero-Data-Retention Architecture:** Operates strictly in-memory during the redaction phase. No prompts, queries, or PHI are logged or stored on disk. What happens in the tenant, stays in the tenant.
*   **DSCSA Supply Chain Validation:** Built to handle the specific regulatory tracking requirements of the pharmaceutical supply chain.
*   **MSP-Friendly Integration:** API-first design that drops cleanly into existing security stacks and RMM tools. 

## System Architecture

Hermes is built on a lightweight Python backend optimized for Linux environments (Ubuntu/Zorin OS). It acts as a reverse proxy/middleware layer.

1.  **Ingress:** User submits a query via Copilot, custom UI (Streamlit/HTML), or internal app.
2.  **Redaction Engine:** Hermes intercepts the payload and applies deterministic regex, checksums, and local NER (Named Entity Recognition) to sanitize PHI.
3.  **Forwarding:** The sanitized prompt is forwarded to the intended LLM provider.
4.  **Re-hydration (Optional):** The LLM response is returned and dynamically re-associated with local context before being delivered back to the user.

## Prerequisites

*   Python 3.10+
*   Linux environment (Ubuntu 22.04 LTS or Zorin OS recommended)
*   Redis (for fast, ephemeral session state management without disk writing)

## Quick Start / Installation

Clone the repository and set up your virtual environment:

```bash
git clone [https://github.com/g1n0mag1k/hermes.git](https://github.com/g1n0mag1k/hermes.git)
cd hermes
python3 -m venv venv
source venv/bin/activate
