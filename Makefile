PAPERLESS_NGX_SRC ?= $(CURDIR)/../paperless-ngx/src
IMAGE ?= paperless-ngx-esig

.PHONY: help venv test lint build docker docker-local publish-test publish clean

help: ## Show available commands
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

venv: ## Create a virtual environment and install dev dependencies
	uv sync

test: ## Run the test suite (requires a Paperless-ngx checkout; see README)
	PYTHONPATH=$(PAPERLESS_NGX_SRC) uv run pytest

lint: ## Run ruff
	uv run ruff check src tests

build: ## Build the wheel and sdist into dist/
	uv build

docker: ## Build the Docker image (latest release from PyPI)
	docker build -t $(IMAGE) .

docker-local: ## Build the Docker image from your local checkout
	docker build --build-arg ESIG_SOURCE=local -t $(IMAGE) .

publish-test: build ## Upload to TestPyPI (run once to verify, then publish)
	uv publish --publish-url https://test.pypi.org/legacy/

publish: build ## Upload to PyPI (requires an API token; see README)
	uv publish

clean: ## Remove build artifacts and caches
	rm -rf dist build src/paperless_esig.egg-info .pytest_cache .ruff_cache
	find . -name __pycache__ -type d -exec rm -rf {} +
