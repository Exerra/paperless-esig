# paperless-esig

Third-party parser for Paperless-ngx that adds support for **EU
electronically signed documents** — ETSI ASiC-E containers as used under
the eIDAS regulation:

- `.edoc` — Latvia (EDOC 2.0)
- `.asice` — Estonia
- `.bdoc` — Estonia
- `.adoc` — Lithuania

These files bundle the signed document (usually a PDF), an electronic
signature, and a manifest inside a ZIP container. Paperless-ngx cannot
consume them out of the box: libmagic reports them as `application/zip`
and they are rejected.

## What it does

- Stores the **original container unchanged** (required for legal compliance)
- Extracts the signed PDF as the display/archive rendition (browsers cannot
  render ZIP containers)
- Extracts the text of the inner documents for search
- Uses the **signature signing time** as the document date
- Shows the **signature metadata** in the metadata tab: signer name,
  organisation and country, signing time, certificate chain and issuer,
  RFC 3161 timestamp authority, OCSP presence
- Performs **offline cryptographic verification** and reports whether the
  document digest, the SignedProperties digest and the signature value
  are valid
- Handles nested containers ("EDOC within EDOC", as produced by the Latvian
  e-archive) and multi-document containers (multiple PDFs and office
  documents merged into a single rendition)
- **Assigns the signer as the document's correspondent**: after
  consumption, if no correspondent was determined by content matching or
  workflow rules, the signer (organisation preferred over common name) is
  looked up case-insensitively and created if it does not exist, and the
  document is re-indexed so the correspondent is searchable immediately.
  Disable with `PAPERLESS_ESIG_ASSIGN_SIGNER_AS_CORRESPONDENT=false`
  (default: enabled). Known limitations: the assignment is not recorded in
  the audit log, and the UI may show the new correspondent as "Private"
  until the page is reloaded (the frontend's name-list caches are not
  invalidated when a correspondent is created server-side).

## Signature formats

Currently **XAdES** signatures are parsed and verified. Support for
**CAdES** (and other signature types found in the wild) is planned.

## Quick start

You need a working Paperless-ngx installation. Two ways to add the parser:

### Option A: Docker (recommended)

Build the image (or see [Building the Docker image](#building-the-docker-image)
for all options):

```sh
docker build -t paperless-ngx-esig .
```

Then edit your `docker-compose.yml`: replace the `webserver` image with
your build:

```yaml
services:
  webserver:
    image: paperless-ngx-esig
    # ...everything else stays the same
```

Restart: `docker compose up -d`.

### Option B: Bare metal

```sh
uv pip install paperless-esig
```

(install into the same virtual environment that runs Paperless-ngx)

## Verify the install

1. Start Paperless-ngx and watch the logs. You should see a line like:

   ```
   No third-party parsers discovered.
   ```
   replaced by something like:
   ```
   [paperless.parsers.registry]   [third-party] Paperless-ngx ESig Parser v0.2.0 — https://github.com/Exerra/paperless-esig
   ```
2. Upload an `.edoc` / `.asice` / `.bdoc` / `.adoc` file. It should be
   consumed, display the inner PDF, and show signature metadata in the
   metadata tab.

If the parser line is missing, see [Troubleshooting](#troubleshooting).

## Building the Docker image

```sh
# latest release from PyPI (default)
docker build -t paperless-ngx-esig .

# a specific release
docker build --build-arg ESIG_VERSION=0.2.0 -t paperless-ngx-esig .

# your local checkout — for development or unreleased changes
docker build --build-arg ESIG_SOURCE=local -t paperless-ngx-esig .

# a specific Paperless-ngx base version
docker build --build-arg PAPERLESS_VERSION=2.14.7 -t paperless-ngx-esig .
```

`make docker` / `make docker-local` are shortcuts for the first and third
commands.

## Development

### Prerequisites

- [uv](https://docs.astral.sh/uv/) (`curl -LsSf https://astral.sh/uv/install.sh | sh` or `brew install uv`)
- Python 3.11+ (uv will install it for you)
- Docker (only for the Docker image targets)
- A checkout of [Paperless-ngx](https://github.com/paperless-ngx/paperless-ngx)
  for the test suite (see below)

### Step by step

```sh
# 1. Get the code
git clone https://github.com/Exerra/paperless-esig.git
cd paperless-esig

# 2. Create a virtual environment and install everything
#    (package + dev dependencies: django, pytest, ruff, ...)
uv sync

# 3. Get a Paperless-ngx checkout for the test suite.
#    The tests import Paperless-ngx's own code, so it must be on PYTHONPATH.
#    Any working checkout of the dev branch works:
git clone --depth 1 https://github.com/paperless-ngx/paperless-ngx.git ../paperless-ngx

# 4. Run the tests
PYTHONPATH=../paperless-ngx/src uv run pytest
#    or just:  make test

# 5. Lint
uv run ruff check src tests
#    or just:  make lint
```

Notes:

- `make test` uses `PAPERLESS_NGX_SRC` (default: `../paperless-ngx/src`
  relative to this repo). Override with
  `make test PAPERLESS_NGX_SRC=/path/to/paperless-ngx/src`.
- The tests build synthetic signed containers (no real personal data) and
  only need the Paperless-ngx source importable — no database or running
  instance required.

### Building a wheel locally

```sh
uv build
#    or just:  make build
```

Artifacts land in `dist/` as `paperless_esig-<version>-py3-none-any.whl`
and `paperless_esig-<version>.tar.gz`.

## Publishing to PyPI

Do this once per release (after bumping `version` in `pyproject.toml`).

### 1. Get an API token

1. Create an account at <https://pypi.org> (and <https://test.pypi.org>).
2. PyPI → Account settings → **API tokens** → *Add API token*.
   Scope it to the `paperless-esig` project (or your whole account while
   you're still testing).
3. `uv publish` will ask for the token the first time and store it in your
   keyring.

### 2. Upload to TestPyPI first (optional but recommended)

```sh
uv publish --publish-url https://test.pypi.org/legacy/
#    or just:  make publish-test
```

Verify it installs:

```sh
uv venv /tmp/test-esig --python 3.11
uv pip install --python /tmp/test-esig/bin/python --index-url https://test.pypi.org/simple paperless-esig
/tmp/test-esig/bin/python -c "import paperless_esig; print(paperless_esig.__version__)"
```

### 3. Upload to PyPI

```sh
uv publish
#    or just:  make publish
```

### 4. Verify the release

```sh
uv pip install paperless-esig
```

and confirm the parser shows up in the Paperless-ngx logs as described in
[Verify the install](#verify-the-install).

## Makefile cheat sheet

| Command                    | What it does                                        |
| -------------------------- | --------------------------------------------------- |
| `make venv`                | Create venv + install dev dependencies (`uv sync`)  |
| `make test`                | Run the test suite                                  |
| `make lint`                | Run ruff                                            |
| `make build`               | Build wheel + sdist into `dist/`                    |
| `make docker`              | Build the image from the latest PyPI release        |
| `make docker-local`        | Build the image from your local checkout            |
| `make publish-test`        | Build + upload to TestPyPI                          |
| `make publish`             | Build + upload to PyPI                              |
| `make clean`               | Remove build artifacts and caches                   |

## Troubleshooting

- **"No third-party parsers discovered" in the logs** — the package is not
  installed in the environment Paperless-ngx runs in. For Docker, check
  your compose file points at the image you built (`docker images`).
- **`uv: command not found`** — install uv first (see
  [Prerequisites](#prerequisites)). Alternatively `python3 -m pip install .`
  works too.
- **Tests fail with `ModuleNotFoundError: No module named 'documents'`** —
  the Paperless-ngx checkout is missing or not on `PYTHONPATH`. See step 3
  in [Development](#development).
- **Plain ZIP files are rejected with "Unsupported mime type"** — expected.
  See [Limitations](#limitations).

## Limitations

- Documents are stored with `document.mime_type == "application/zip"`,
  because a third-party parser can only declare the MIME type that
  libmagic actually reports. The original filename extension (`.edoc`,
  `.asice`, …) is preserved in the stored filename.
- Plain ZIP files pass the API/mail upload validation (the parser cannot
  inspect a file at validation time) but are rejected during consumption
  with a clear "Unsupported mime type" error. ZIP files placed in the
  consume directory are attempted instead of silently skipped.
- Office documents (DOCX, ODT, …) inside a container are converted to PDF
  via **Gotenberg** and their text is extracted via **Tika** when those
  services are configured (`PAPERLESS_TIKA_ENDPOINT`); without them the
  DOCX text is still extracted locally and the affected pages are omitted
  from the rendition.

## Requirements

- Paperless-ngx 2.x (uses the `paperless_ngx.parsers` entrypoint registry)
- The inner PDF is required for display; containers without any PDF cannot
  be ingested

## License

GPL-3.0-or-later (derived from the Paperless-ngx project, which is
GPL-3.0).
