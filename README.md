# paperless-esig

<picture><source media="(prefers-color-scheme: dark)" srcset="https://shieldcn.dev/badge/Paperless--ngx-398439.svg?logo=paperlessngx&amp;mode=dark"><img alt="badge" src="https://shieldcn.dev/badge/Paperless--ngx-398439.svg?logo=paperlessngx&amp;mode=light"></picture>

Third-party parser for Paperless-ngx, which adds support for EU electronically signed documents.

## Supported formats

| Format | Extensions |
| --- | --- |
| ASiC-E containers | `.edoc`, `.asice`, `.bdoc`, `.adoc` |
| CAdES signatures | `.p7m` |
| PAdES-signed PDFs | `.pdf` |

Paperless-ngx does not consume these files by default. The parser is required for them.

<details>
<summary>Why Paperless-ngx cannot handle these files</summary>

ASiC-E containers are ZIP archives. libmagic reports them as `application/zip`, and Paperless-ngx rejects the MIME type. CAdES files are reported as `application/octet-stream` and are also rejected. PAdES-signed PDFs are consumed, but the built-in parser does not expose their signature metadata.

</details>

<details>
<summary>Signature formats in detail</summary>

### XAdES

Used inside ETSI ASiC-E containers (`.edoc`, `.asice`, `.bdoc`, `.adoc`). The parser extracts the signing time, signer certificate, certificate chain, RFC 3161 timestamp, and OCSP values. It verifies the document digest, the SignedProperties digest, and the signature value offline.

### CAdES

CMS SignedData (ETSI EN 319 122) in `.p7m` files. The embedded PDF becomes the rendition. The CMS signing time, signer, and verification results are exposed as metadata. Detached `.p7s` signatures are detected but rejected during parsing with a clear error, because they carry no document.

### PAdES

PDFs signed with the `ETSI.CAdES.detached` or `adbe.pkcs7.detached` subfilter. The signed PDF is the rendition. The document date prefers the CMS signing time and falls back to the signature's `/M` field. The covered byte range, signer, and verification results are exposed as metadata.

### Encoding notes

Both DER and BER (indefinite-length) CMS encodings are accepted. Some signers, such as the `adbe.pkcs7.detached` flavour, emit BER. Verification is offline only. It proves that the document digest and the signature value are consistent with the signer certificate. It does not validate trust chains, revocation status, or timestamps.

</details>

## What the parser does

- **Stores the original file unchanged. This is required for legal compliance.**
   <details>
   <summary>How to download the original file</summary>

   The default download option returns the parsed PDF. The parsed PDF is not a signed document. To download the original file (`.edoc`, `.asice`, `.p7m`, and so on), use the "Download original" option instead.

   PAdES-signed PDFs are not affected. For these files, the original file and the parsed rendition are the same document.

   Web UI:

   1. Open the document detail view.
   2. Click the arrow next to "Download".
   3. Select "Download original".

   Mobile apps:

   1. Use the share or download action.
   2. Select the original document option.

   The original document option is available in mobile apps such as Swift Paperless for iOS.
   </details>
- Extracts the signed PDF as the display and archive rendition. Browsers cannot render ZIP containers. A PAdES PDF is already a rendition and keeps its signature.
- Extracts the text of the PDF for search.
- Sets the document date from the signature signing time, with fallbacks to the PAdES `/M` field and the PDF creation date.
- Displays signature metadata in the metadata tab: signer name, organisation, country, signing time, certificate chain and issuer, RFC 3161 timestamp authority, and OCSP presence.
- Verifies the document digest and the signature value offline.
- Handles nested containers (an EDOC inside an EDOC, as produced by the Latvian e-archive) and multi-document containers (multiple PDFs and office documents merged into a single rendition).
- Assigns the signer as the document's correspondent. This happens after consumption, only when no correspondent was determined by content matching or workflow rules. The signer (organisation preferred over common name) is looked up case-insensitively and created if it does not exist, and the document is re-indexed so the correspondent is searchable immediately. This is enabled by default. Disable it with `PAPERLESS_ESIG_ASSIGN_SIGNER_AS_CORRESPONDENT=false`. Known limitations: the assignment is not recorded in the audit log, and the UI may show the new correspondent as "Private" until the page is reloaded.

## Install

The parser runs inside Paperless-ngx. Use one of two methods.

### Method 1: Docker

1. Clone this repository and build the image:

   ```sh
   docker build -t paperless-ngx-esig .
   ```

2. In `docker-compose.yml`, replace the `webserver` image with your build:

   ```yaml
   services:
     webserver:
       image: paperless-ngx-esig
       # ...everything else stays the same
   ```

3. Restart the stack:

   ```sh
   docker compose up -d
   ```

### Method 2: Bare metal

Install the package into the same virtual environment that runs Paperless-ngx:

```sh
uv pip install paperless-esig
```

## Verify the install

1. Start Paperless-ngx and check the logs. Look for a line like this:

   ```
   [paperless.parsers.registry]   [third-party] Paperless-ngx ESig Parser v0.3.0 — https://github.com/Exerra/paperless-esig
   ```

   If the logs say `No third-party parsers discovered.` instead, see [Troubleshooting](#troubleshooting).

2. Upload an `.edoc`, `.asice`, `.bdoc`, `.adoc`, or `.p7m` file, or a PAdES-signed PDF. The document is consumed, displays the inner PDF, and shows signature metadata in the metadata tab.

## Limitations

- Documents are stored with the MIME type that libmagic reports. ASiC-E containers are stored as `application/zip` and CAdES files as `application/octet-stream`. The original file extension (`.edoc`, `.asice`, `.p7m`, and so on) is preserved in the stored filename.
- Plain ZIP files pass API and mail upload validation but are rejected during consumption with an "Unsupported mime type" error. The parser cannot inspect a file at validation time. ZIP files placed in the consume directory are attempted instead of silently skipped. The same applies to `application/octet-stream` files: CAdES signatures are the only octet-stream files that are consumed.
- Detached `.p7s` signatures are detected but rejected during parsing. They carry no document, so there is nothing to display or search.
- Office documents (DOCX, ODT, and similar) inside a container are converted to PDF by Gotenberg, and their text is extracted by Tika, when those services are configured with `PAPERLESS_TIKA_ENDPOINT`. Without them, the DOCX text is still extracted locally and the affected pages are omitted from the rendition.

## Requirements

- Paperless-ngx 2.x. The parser uses the `paperless_ngx.parsers` entrypoint registry.
- The container must contain a PDF. Containers without a PDF cannot be ingested.

## Troubleshooting

- `No third-party parsers discovered.` in the logs. The package is not installed in the environment that Paperless-ngx runs in. For Docker, check that your compose file points at the image you built (`docker images`).
- `uv: command not found`. Install uv first. Alternatively, `python3 -m pip install .` works.
- Plain ZIP files are rejected with "Unsupported mime type". This is expected. See [Limitations](#limitations).

## License

GPL-3.0-or-later. Derived from the Paperless-ngx project, which is GPL-3.0.

## For developers

<details>
<summary>Building the Docker image</summary>

The build defaults to the latest release from PyPI:

```sh
docker build -t paperless-ngx-esig .
```

Build a specific release:

```sh
docker build --build-arg ESIG_VERSION=0.3.0 -t paperless-ngx-esig .
```

Build from your local checkout, for development or unreleased changes:

```sh
docker build --build-arg ESIG_SOURCE=local -t paperless-ngx-esig .
```

Build against a specific Paperless-ngx base version:

```sh
docker build --build-arg PAPERLESS_VERSION=2.14.7 -t paperless-ngx-esig .
```

`make docker` and `make docker-local` are shortcuts for the first and third commands.

</details>

<details>
<summary>Development</summary>

### Prerequisites

- [uv](https://docs.astral.sh/uv/)
- Python 3.11 or newer (uv installs it for you)
- Docker, only for the Docker image targets
- A checkout of [Paperless-ngx](https://github.com/paperless-ngx/paperless-ngx), for the test suite

### Set up

```sh
git clone https://github.com/Exerra/paperless-esig.git
cd paperless-esig
uv sync
git clone --depth 1 https://github.com/paperless-ngx/paperless-ngx.git ../paperless-ngx
```

`uv sync` creates a virtual environment and installs the package plus dev dependencies (django, pytest, ruff, and others). The tests import Paperless-ngx's own code, so the checkout must be on `PYTHONPATH`.

### Run the tests

```sh
PYTHONPATH=../paperless-ngx/src uv run pytest
```

`make test` does the same. It uses `PAPERLESS_NGX_SRC`, which defaults to `../paperless-ngx/src` relative to this repo. Override it with `make test PAPERLESS_NGX_SRC=/path/to/paperless-ngx/src`.

The tests build synthetic signed containers. They do not contain real personal data. They need only the Paperless-ngx source importable. No database or running instance is required.

If the tests fail with `ModuleNotFoundError: No module named 'documents'`, the Paperless-ngx checkout is missing or not on `PYTHONPATH`.

### Lint

```sh
uv run ruff check src tests
```

### Build a wheel

```sh
uv build
```

Artifacts land in `dist/` as `paperless_esig-<version>-py3-none-any.whl` and `paperless_esig-<version>.tar.gz`.

### Makefile targets

| Command | What it does |
| --- | --- |
| `make venv` | Create venv and install dev dependencies (`uv sync`) |
| `make test` | Run the test suite |
| `make lint` | Run ruff |
| `make build` | Build wheel and sdist into `dist/` |
| `make docker` | Build the image from the latest PyPI release |
| `make docker-local` | Build the image from your local checkout |
| `make clean` | Remove build artifacts and caches |

</details>
