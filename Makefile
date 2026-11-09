.PHONY: setup lint test bench demo audit ci

PY ?= python

setup:
	$(PY) -m pip install --upgrade pip && $(PY) -m pip install -e ".[dev]"

# ruff, ruff format and mypy --strict.
lint:
	$(PY) -m ruff check . && $(PY) -m ruff format --check . && $(PY) -m mypy

# Parser, evaluator, conditions, snapshot, collection (fake boto3), CLI.
test:
	$(PY) -m pytest -q

# Effective permissions for every principal of the hand-written lab account.
demo:
	iamgraph perms examples/lab-snapshot.json

# Evaluation throughput on a seeded synthetic account (1,000 users, 500 roles).
bench:
	iamgraph bench --users 1000 --roles 500

# Known vulnerabilities in the installed Python dependencies.
audit:
	$(PY) -m pip_audit --skip-editable --cache-dir .tmp/pip-audit

ci: setup lint test
