"""
Tests for paperless_edoc.correspondent (signer-as-correspondent).

The handler is exercised with mocked model/backend loaders since the
package's minimal Django settings do not register the ``documents`` app.
The signer extraction itself is tested against real synthetic containers.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING
from unittest import mock

from edoc_fixtures import build_edoc_container
from paperless_edoc.correspondent import _on_document_consumption_finished
from paperless_edoc.parser import extract_signer_name

if TYPE_CHECKING:
    import pytest


def _document_stub(**kwargs):
    defaults = {
        "pk": 1,
        "correspondent_id": None,
        "correspondent": None,
        "mime_type": "application/zip",
    }
    defaults.update(kwargs)
    return mock.Mock(**defaults)


def _fake_correspondent(name: str = "Test Organization"):
    return mock.Mock(pk=7, name=name, MATCH_NONE="none")


class TestExtractSignerName:
    """Signer extraction from real synthetic containers."""

    def test_returns_organization_over_cn(self) -> None:
        container = build_edoc_container(
            signer_cn="111111-11111",
            signer_org="Latvijas Testa Uzņēmums",
            signer_country="LV",
        )
        assert extract_signer_name(container) == "Latvijas Testa Uzņēmums"

    def test_returns_cn_when_no_organization(self) -> None:
        container = build_edoc_container(
            signer_cn="Jānis Bērziņš",
            signer_org=None,
            signer_country="LV",
        )
        assert extract_signer_name(container) == "Jānis Bērziņš"

    def test_placeholder_cn_returns_none(self) -> None:
        container = build_edoc_container(
            signer_cn="Private",
            signer_org=None,
            signer_country="LV",
        )
        assert extract_signer_name(container) is None

    def test_plain_zip_returns_none(self, tmp_path: Path) -> None:
        path = tmp_path / "plain.zip"
        path.write_bytes(b"PK\x03\x04 not an ASiC container")
        assert extract_signer_name(path) is None

    def test_garbage_returns_none(self) -> None:
        assert extract_signer_name(b"not a zip at all") is None

    def test_path_based_extraction(self, tmp_path: Path) -> None:
        path = tmp_path / "document.edoc"
        path.write_bytes(
            build_edoc_container(signer_cn="Test Signer", signer_org="Org"),
        )
        assert extract_signer_name(path) == "Org"


class TestSignerAsCorrespondentHandler:
    """The document_consumption_finished handler."""

    def test_disabled_by_setting(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("PAPERLESS_EDOC_ASSIGN_SIGNER_AS_CORRESPONDENT", "no")
        document = _document_stub()
        with (
            mock.patch(
                "paperless_edoc.parser.extract_signer_name",
            ) as extract,
            mock.patch(
                "paperless_edoc.correspondent._load_correspondent_model"
            ) as load,
        ):
            _on_document_consumption_finished(
                sender=object(),
                document=document,
                original_file=Path("/tmp/doc.edoc"),
            )
        extract.assert_not_called()
        load.assert_not_called()

    def test_skips_when_correspondent_already_assigned(self) -> None:
        document = _document_stub(correspondent_id=5)
        with mock.patch(
            "paperless_edoc.parser.extract_signer_name",
        ) as extract:
            _on_document_consumption_finished(
                sender=object(),
                document=document,
                original_file=Path("/tmp/doc.edoc"),
            )
        extract.assert_not_called()

    def test_skips_non_zip_mime_types(self) -> None:
        document = _document_stub(mime_type="application/pdf")
        with mock.patch(
            "paperless_edoc.parser.extract_signer_name",
        ) as extract:
            _on_document_consumption_finished(
                sender=object(),
                document=document,
                original_file=Path("/tmp/doc.pdf"),
            )
        extract.assert_not_called()

    def test_skips_without_original_file(self) -> None:
        document = _document_stub()
        with mock.patch(
            "paperless_edoc.parser.extract_signer_name",
        ) as extract:
            _on_document_consumption_finished(sender=object(), document=document)
        extract.assert_not_called()

    def test_skips_without_signer_name(self) -> None:
        document = _document_stub()
        with (
            mock.patch(
                "paperless_edoc.parser.extract_signer_name",
                return_value=None,
            ),
            mock.patch(
                "paperless_edoc.correspondent._load_correspondent_model"
            ) as load,
        ):
            _on_document_consumption_finished(
                sender=object(),
                document=document,
                original_file=Path("/tmp/doc.edoc"),
            )
        load.assert_not_called()

    def test_assigns_existing_correspondent_case_insensitively(self) -> None:
        document = _document_stub()
        existing = _fake_correspondent()
        queryset = mock.Mock()
        queryset.first.return_value = existing
        correspondent_model = mock.Mock()
        correspondent_model.objects.filter.return_value = queryset
        document_model = mock.Mock()
        backend = mock.Mock()
        document.get_effective_content.return_value = "content"

        with (
            mock.patch(
                "paperless_edoc.parser.extract_signer_name",
                return_value="Test Organization",
            ),
            mock.patch(
                "paperless_edoc.correspondent._load_correspondent_model",
                return_value=correspondent_model,
            ),
            mock.patch(
                "paperless_edoc.correspondent._load_document_model",
                return_value=document_model,
            ),
            mock.patch(
                "paperless_edoc.correspondent._search_backend",
                return_value=backend,
            ),
        ):
            _on_document_consumption_finished(
                sender=object(),
                document=document,
                original_file=Path("/tmp/doc.edoc"),
            )

        correspondent_model.objects.filter.assert_called_once_with(
            name__iexact="Test Organization",
        )
        correspondent_model.objects.create.assert_not_called()
        document_model.objects.filter.assert_called_once_with(pk=1)
        document_model.objects.filter.return_value.update.assert_called_once_with(
            correspondent=existing,
        )
        assert document.correspondent is existing
        backend.add_or_update.assert_called_once_with(
            document,
            effective_content="content",
        )

    def test_creates_new_correspondent_with_match_none(self) -> None:
        document = _document_stub()
        created = _fake_correspondent("New Signer")
        queryset = mock.Mock()
        queryset.first.return_value = None
        correspondent_model = mock.Mock()
        correspondent_model.MATCH_NONE = "none"
        correspondent_model.objects.filter.return_value = queryset
        correspondent_model.objects.create.return_value = created
        document_model = mock.Mock()
        backend = mock.Mock()
        document.get_effective_content.return_value = "content"

        with (
            mock.patch(
                "paperless_edoc.parser.extract_signer_name",
                return_value="New Signer",
            ),
            mock.patch(
                "paperless_edoc.correspondent._load_correspondent_model",
                return_value=correspondent_model,
            ),
            mock.patch(
                "paperless_edoc.correspondent._load_document_model",
                return_value=document_model,
            ),
            mock.patch(
                "paperless_edoc.correspondent._search_backend",
                return_value=backend,
            ),
        ):
            _on_document_consumption_finished(
                sender=object(),
                document=document,
                original_file=Path("/tmp/doc.edoc"),
            )

        correspondent_model.objects.create.assert_called_once_with(
            name="New Signer",
            matching_algorithm="none",
        )
        document_model.objects.filter.return_value.update.assert_called_once_with(
            correspondent=created,
        )
        backend.add_or_update.assert_called_once()

    def test_errors_do_not_raise(self) -> None:
        document = _document_stub()
        with (
            mock.patch(
                "paperless_edoc.parser.extract_signer_name",
                return_value="Test Organization",
            ),
            mock.patch(
                "paperless_edoc.correspondent._load_correspondent_model",
                side_effect=RuntimeError("boom"),
            ),
        ):
            _on_document_consumption_finished(
                sender=object(),
                document=document,
                original_file=Path("/tmp/doc.edoc"),
            )
