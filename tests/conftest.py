"""
Pytest configuration for the paperless-edoc parser package.

The parser (and ``documents.parsers`` / ``paperless.parsers`` that it
imports) require a Django environment, so the tests configure a minimal
settings module pointing at a scratch directory inside the OS temp
folder.  Paperless-ngx itself must be importable (installed, or its
``src/`` directory on ``PYTHONPATH``) for the imports to succeed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from paperless_edoc.parser import EdocDocumentParser

if TYPE_CHECKING:
    from collections.abc import Generator


@pytest.fixture()
def edoc_parser() -> Generator[EdocDocumentParser, None, None]:
    """Yield an EdocDocumentParser and clean up its temporary directory afterwards.

    Yields
    ------
    EdocDocumentParser
        A ready-to-use parser instance.
    """
    with EdocDocumentParser() as parser:
        yield parser


@pytest.fixture()
def edoc_container_bytes() -> bytes:
    """Bytes of a synthetically signed EDOC 2.0 container.

    Built by the test-only fixture helpers (no real-world personal data).
    """
    from edoc_fixtures import build_edoc_container

    return build_edoc_container()
