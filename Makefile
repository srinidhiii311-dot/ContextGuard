# ContextGuard — Cross-Platform Makefile
.PHONY: test test-all lint verify release clean help

PYTHON ?= python

help:
	@echo "Available commands:"
	@echo "  make test       Run test suite excluding live LLM (pytest -m 'not llm')"
	@echo "  make test-all   Run entire test suite (including live LLM tests)"
	@echo "  make lint       Run syntax and static analysis checks (ruff)"
	@echo "  make verify     Verify document claims against eval results"
	@echo "  make reproduce  Run full evaluation benchmark suite and verify claims ledger"
	@echo "  make release    Build clean distribution archive in dist/"
	@echo "  make clean      Remove python caches and temporary test databases"

test:
	$(PYTHON) -m pytest -m "not llm" -q

record-test:
	$(PYTHON) scripts/record_test_run.py

test-all:
	$(PYTHON) -m pytest -v

lint:
	$(PYTHON) -m ruff check contextguard backend agent tests --select E9,F63,F7,F82

verify:
	$(PYTHON) scripts/verify_claims.py

reproduce:
	$(PYTHON) scripts/evaluate_baselines.py
	$(PYTHON) scripts/run_sequence_eval.py
	$(PYTHON) scripts/verify_claims.py

release:
	$(PYTHON) scripts/create_zip.py
	$(PYTHON) scripts/create_eval_bundle.py

clean:
	$(PYTHON) -c "import shutil, pathlib; [shutil.rmtree(p) for p in pathlib.Path('.').rglob('__pycache__')]; [p.unlink() for p in pathlib.Path('.').glob('*.pyc') if p.is_file()]"
