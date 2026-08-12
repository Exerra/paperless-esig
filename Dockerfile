# Paperless-ngx image with the paperless-esig parser pre-installed.
#
# Examples:
#
#   # latest release from PyPI (default)
#   docker build -t paperless-ngx-esig .
#
#   # a specific release
#   docker build --build-arg ESIG_VERSION=0.3.0 -t paperless-ngx-esig .
#
#   # your local checkout (for development / unreleased changes)
#   docker build --build-arg ESIG_SOURCE=local -t paperless-ngx-esig .
#
#   # a specific Paperless-ngx base version
#   docker build --build-arg PAPERLESS_VERSION=2.14.7 -t paperless-ngx-esig .
#
# Then point your docker-compose.yml at the resulting image instead of
# the stock ghcr.io/paperless-ngx/paperless-ngx one.

ARG PAPERLESS_VERSION=latest
FROM ghcr.io/paperless-ngx/paperless-ngx:${PAPERLESS_VERSION}

ARG ESIG_SOURCE=pypi
ARG ESIG_VERSION=latest

COPY . /usr/src/paperless-esig

RUN if [ "$ESIG_SOURCE" = "local" ]; then \
      uv pip install --system --no-python-downloads /usr/src/paperless-esig; \
    elif [ "$ESIG_VERSION" = "latest" ]; then \
      uv pip install --system --no-python-downloads paperless-esig; \
    else \
      uv pip install --system --no-python-downloads "paperless-esig==${ESIG_VERSION}"; \
    fi
