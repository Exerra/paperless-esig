# paperless-edoc

Third-party parser for Paperless-ngx that adds support for **ETSI ASiC-E**
signed documents — the container format used for electronically signed
documents across the EU under the eIDAS regulation:

- `.edoc` — Latvia (EDOC 2.0)
- `.asice` — Estonia
- `.bdoc` — Estonia
- `.adoc` — Lithuania

These files bundle the signed document (usually a PDF), an XAdES signature,
and a manifest inside a ZIP container. Paperless-ngx cannot consume them
out of the box: libmagic reports them as `application/zip` and they are
rejected.

## What it does

- Stores the **original container unchanged** (required for legal compliance)
- Extracts the signed PDF as the display/archive rendition (browsers cannot
  render ZIP containers)
- Extracts the text of the inner documents for search
- Uses the **XAdES signing time** as the document date
- Shows the **signature metadata** in the metadata tab: signer name,
  organisation and country, signing time, certificate chain and issuer,
  RFC 3161 timestamp authority, OCSP presence
- Performs **offline cryptographic verification** and reports whether the
  document digest, the SignedProperties digest and the signature value
  are valid
- Handles nested containers ("EDOC within EDOC", as produced by the Latvian
  e-archive) and multi-document containers (multiple PDFs and office
  documents merged into a single rendition)

## Installation

The parser is discovered through Paperless-ngx's
`paperless_ngx.parsers` entrypoint; no changes to Paperless-ngx itself
are needed.

### Bare metal

```sh
uv pip install paperless-edoc
```

(install into the same virtual environment that runs Paperless-ngx)

### Docker

The stock image has no hook for extra packages, so build a small custom
image:

```dockerfile
FROM ghcr.io/paperless-ngx/paperless-ngx:latest
RUN uv pip install --system --no-python-downloads paperless-edoc
```

Point your compose file at this image instead of the stock one.

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

## Development

```sh
uv venv --python 3.11 .venv
uv pip install -e . django pillow lxml cryptography pikepdf pytest pytest-django pytest-mock
PYTHONPATH=/path/to/paperless-ngx/src .venv/bin/python -m pytest
```

The tests build synthetic signed containers (no real personal data) and
import `documents.parsers` / `paperless.parsers`, so a Paperless-ngx
checkout must be importable in the test environment.

## License

GPL-3.0-or-later (derived from the Paperless-ngx project, which is
GPL-3.0).
