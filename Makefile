# llm-triage-boundaries — convenience runners.
# On Windows use the equivalent commands in RUNBOOK.md if `make` is unavailable.

PY ?= python
MODELS ?= llama3.1:8b

.PHONY: help setup test check smoke dry run analyze clean

help:
	@echo "targets:"
	@echo "  setup    - install dev dependencies"
	@echo "  check    - no-model sanity (schema + guardrails + prompts)"
	@echo "  test     - run pytest (leakage, invariant, injection-invariance, metrics)"
	@echo "  dry      - offline pipeline test (no Ollama)"
	@echo "  smoke    - quick real run (repeats=3, tiers 0&2, clean)"
	@echo "  run      - full real run (set MODELS=\"m1 m2\")"
	@echo "  analyze  - print the analysis report"

setup:
	$(PY) -m pip install -r requirements-dev.txt

check:
	$(PY) schema.py
	$(PY) guardrails.py
	$(PY) prompts.py

test:
	$(PY) -m pytest

dry:
	$(PY) evaluate.py --dry-run --quick
	$(PY) analyze.py

smoke:
	$(PY) evaluate.py --quick
	$(PY) analyze.py

run:
	$(PY) evaluate.py --models $(MODELS) --tiers 0 1 2 --conditions clean naive --repeats 20

analyze:
	$(PY) analyze.py

clean:
	rm -f results*.json
	rm -rf __pycache__ .pytest_cache tests/__pycache__
