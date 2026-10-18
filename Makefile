# Hermes Relay — developer convenience targets
# Usage:  make <target>
# Requires: Python 3.12, Docker, docker compose

PYTHON      ?= python3
VENV        ?= .venv
PIP         := $(VENV)/bin/pip
PYTEST      := $(VENV)/bin/python -m pytest
HERMES_CLI  := $(VENV)/bin/hermes-relay

.PHONY: help venv install install-dev test test-fast lint typecheck \
        spacy-model up down logs clean

##@ General

help:   ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n\n"} \
	  /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2 } \
	  /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)

##@ Setup

venv:   ## Create .venv (Python 3.12 required)
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip

install: venv   ## Install runtime dependencies
	$(PIP) install -r requirements.txt
	$(PIP) install -e .

install-dev: install   ## Install dev/test dependencies
	$(PIP) install -r requirements-dev.txt

spacy-model: install   ## Download the spaCy NLP model (required for classifier)
	$(VENV)/bin/python -m spacy download en_core_web_sm

##@ Development

up:   ## Start API + gateway via Docker Compose
	docker compose up --build -d

down:   ## Stop all Compose services
	docker compose down

logs:   ## Tail logs for all Compose services
	docker compose logs -f

env:   ## Generate .env from .env.hermes.example (will not overwrite existing .env)
	@if [ -f .env ]; then \
	  echo ".env already exists — edit it manually or delete it first."; \
	else \
	  cp .env.hermes.example .env; \
	  echo "Created .env from .env.hermes.example — fill in the required values."; \
	fi

##@ Testing

test:   ## Run full test suite (562+ tests)
	$(PYTEST) -x -q

test-fast:   ## Run tests excluding slow docker/e2e
	$(PYTEST) -x -q -m "not slow and not e2e"

lint:   ## Lint with ruff
	$(VENV)/bin/ruff check hermes/ gateway/ tests/

typecheck:   ## Type-check with mypy
	$(VENV)/bin/mypy hermes/ gateway/

##@ Cleanup

clean:   ## Remove __pycache__ and .pyc files
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete
