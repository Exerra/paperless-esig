"""
Pytest configuration for the paperless-esig parser package.

The parser (and ``documents.parsers`` / ``paperless.parsers`` that it
imports) require a Django environment, so the tests configure a minimal
settings module pointing at a scratch directory inside the OS temp
folder.  Paperless-ngx itself must be importable (installed, or its
``src/`` directory on ``PYTHONPATH``) for the imports to succeed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from paperless_esig.parser import ESigDocumentParser

if TYPE_CHECKING:
    from collections.abc import Generator


@pytest.fixture()
def esig_parser() -> Generator[ESigDocumentParser, None, None]:
    """Yield an ESigDocumentParser and clean up its temporary directory afterwards.

    Yields
    ------
    ESigDocumentParser
        A ready-to-use parser instance.
    """
    with ESigDocumentParser() as parser:
        yield parser


@pytest.fixture()
def edoc_container_bytes() -> bytes:
    """Bytes of a synthetically signed EDOC 2.0 container.

    Built by the test-only fixture helpers (no real-world personal data).
    """
    from esig_fixtures import build_esig_container

    return build_esig_container()
