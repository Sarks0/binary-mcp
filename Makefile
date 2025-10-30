.PHONY: help install test run clean compile-sample diagnose

help:
	@echo "Ghidra MCP Server - Development Commands"
	@echo ""
	@echo "  make install        - Install dependencies with uv"
	@echo "  make test          - Run test suite"
	@echo "  make test-cov      - Run tests with coverage"
	@echo "  make run           - Run MCP server"
	@echo "  make compile-sample - Compile test malware sample"
	@echo "  make diagnose      - Run diagnostic checks"
	@echo "  make clean         - Clean cache and temporary files"
	@echo "  make clean-all     - Clean everything including dependencies"
	@echo "  make lint          - Run code linting with ruff"
	@echo "  make format        - Format code with ruff"

install:
	uv sync

install-dev:
	uv sync --extra dev

test:
	uv run pytest -v

test-cov:
	uv run pytest --cov=src --cov-report=html --cov-report=term -v

run:
	uv run python -m src.server

compile-sample:
	@echo "Compiling test malware sample..."
	gcc -o samples/test_malware samples/test_malware.c
	@echo "Sample compiled: samples/test_malware"

diagnose:
	@echo "Running diagnostic checks..."
	@uv run python -c "from src.ghidra.runner import GhidraRunner; import json; r = GhidraRunner(); print(json.dumps(r.diagnose(), indent=2))"

clean:
	@echo "Cleaning cache and temporary files..."
	rm -rf ~/.ghidra_mcp_cache/
	rm -rf ghidra_projects/
	rm -f temp_analysis_*.json
	rm -rf .pytest_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	@echo "Clean complete!"

clean-all: clean
	@echo "Cleaning all generated files..."
	rm -rf .venv/
	rm -f samples/test_malware
	rm -f samples/*.exe
	@echo "Clean all complete!"

lint:
	uv run ruff check src/ tests/

format:
	uv run ruff format src/ tests/

.DEFAULT_GOAL := help
