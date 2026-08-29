.PHONY: setup test lint demo clean

VENV := .venv/bin
PY := $(VENV)/python

setup:
	python3 -m venv .venv
	$(VENV)/pip install -e ".[dev]"

test:
	$(PY) -m pytest

lint:
	$(PY) -m ruff check opensystem tests || true

demo:
	$(VENV)/opensystem security-test mock --rounds 5

clean:
	rm -rf .venv .pytest_cache build dist *.egg-info
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
	find . -name '*.pyc' -delete
	rm -rf .os opensystem.db
