.PHONY: all build up down clean lint format test typecheck

PYTHON ?= .venv/bin/python

all: build

build:
	@echo "Building Docker image..."
	@docker compose build

up:
	@echo "Starting services..."
	@docker compose up -d

down:
	@echo "Stopping services..."
	@docker compose down

clean:
	@echo "Cleaning up..."
	@docker compose down -v

lint:
	@echo "Running linters..."
	@$(PYTHON) -m ruff check exporter.py tests/

format:
	@echo "Formatting code..."
	@$(PYTHON) -m ruff format exporter.py tests/

typecheck:
	@echo "Running type checker..."
	@$(PYTHON) -m mypy exporter.py tests/ --ignore-missing-imports

test:
	@echo "Running tests..."
	@$(PYTHON) -m pytest --cov --cov-report=term-missing
