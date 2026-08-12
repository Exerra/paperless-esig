"""
Tests for paperless_esig.parser.ESigDocumentParser and its helpers.

Synthetic EDOC 2.0 (ASiC-E) containers are built in-test by the helpers
in ``esig_fixtures.py`` — real Latvian sample files contain personal data
and are therefore not committed to the repository.  The cryptographic
structure of the fixtures mirrors real containers, which are verified
manually against the genuine eParaksts samples.

The tests import ``documents.parsers`` / ``paperless.parsers``, so
Paperless-ngx must be installed (or on ``PYTHONPATH``) in the test
environment; see ``conftest.py`` for the minimal Django configuration.
"""

from __future__ import annotations

import datetime
import io
import zipfile
from pathlib import Path
from unittest import mock

import pytest
from django.test import override_settings
from documents.parsers import ParseError
from paperless.parsers import MetadataEntry, ParserContext, ParserProtocol

from esig_fixtures import (
    build_esig_container,
    build_nested_edoc_container,
    build_simple_docx,
    build_simple_pdf,
)
from paperless_esig.parser import (
    ESIG_CONTAINER_MIME_TYPE,
    ESigDocumentParser,
    is_esig_container,
)


def _write_container(
    tmp_path: Path,
    *,
    filename: str = "document.edoc",
    **kwargs,
) -> Path:
    """Write a synthetic EDOC container to *tmp_path* and return its path."""
    path = tmp_path / filename
    path.write_bytes(build_esig_container(**kwargs))
    return path


class TestEdocParserProtocol:
    """Verify that ESigDocumentParser satisfies the ParserProtocol contract."""

    def test_isinstance_satisfies_protocol(
        self,
        esig_parser: ESigDocumentParser,
    ) -> None:
        assert isinstance(esig_parser, ParserProtocol)

    def test_class_attributes_present(self) -> None:
        assert isinstance(ESigDocumentParser.name, str) and ESigDocumentParser.name
        assert (
            isinstance(ESigDocumentParser.version, str) and ESigDocumentParser.version
        )
        assert isinstance(ESigDocumentParser.author, str) and ESigDocumentParser.author
        assert isinstance(ESigDocumentParser.url, str) and ESigDocumentParser.url

    def test_supported_mime_types(self) -> None:
        mime_types = ESigDocumentParser.supported_mime_types()
        assert isinstance(mime_types, dict)
        assert mime_types == {
            "application/zip": ".edoc",
            ESIG_CONTAINER_MIME_TYPE: ".asice",
            "application/octet-stream": ".p7m",
            "application/pkcs7-mime": ".p7m",
            "application/x-pkcs7-mime": ".p7m",
            "application/pkcs7-signature": ".p7s",
            "application/x-pkcs7-signature": ".p7s",
            "application/pdf": ".pdf",
        }

    def test_supported_extensions_include_member_states(self) -> None:
        import mimetypes

        extensions = set()
        for mime_type, ext in ESigDocumentParser.supported_mime_types().items():
            extensions.update(mimetypes.guess_all_extensions(mime_type))
            extensions.add(ext)
        assert {".edoc", ".asice", ".bdoc", ".adoc"} <= extensions

    def test_score_without_path_accepts_zip(
        self,
    ) -> None:
        # The API/mail validation paths call score() without a path (and
        # with an empty filename); any application/zip file must then be
        # accepted so ASiC-E uploads pass validation.
        assert ESigDocumentParser.score("application/zip", "") == 10
        assert ESigDocumentParser.score("application/zip", "document.zip") == 10

    def test_score_with_path_inspects_content(
        self,
        edoc_container_bytes: bytes,
        tmp_path: Path,
    ) -> None:
        container = _write_container(tmp_path, filename="document.edoc")
        assert (
            ESigDocumentParser.score("application/zip", "document.edoc", container)
            == 10
        )

        plain_zip = tmp_path / "archive.zip"
        plain_zip.write_bytes(b"PK\x03\x04 not an ASiC container")
        assert (
            ESigDocumentParser.score("application/zip", "archive.zip", plain_zip)
            is None
        )

    def test_score_other_mime_types(self) -> None:
        # Without a path, application/pdf is never claimed (the built-in
        # PDF parser handles validation) and unknown types are declined.
        assert ESigDocumentParser.score("application/pdf", "document.pdf") is None
        assert ESigDocumentParser.score("text/plain", "document.txt") is None
        # octet-stream is accepted when no filename is given (the
        # API/mail validation paths) — the content check happens at
        # consumption time — and with a CAdES extension otherwise.
        assert ESigDocumentParser.score("application/octet-stream", "") == 10
        assert (
            ESigDocumentParser.score(
                "application/octet-stream",
                "document.p7m",
            )
            == 10
        )
        assert (
            ESigDocumentParser.score(
                "application/octet-stream",
                "signature.p7s",
            )
            == 10
        )
        assert (
            ESigDocumentParser.score(
                "application/octet-stream",
                "random.bin",
            )
            is None
        )
        # The RFC 8551 CAdES MIME types are accepted on their own.
        assert ESigDocumentParser.score("application/pkcs7-mime", "") == 10
        assert ESigDocumentParser.score("application/pkcs7-signature", "") == 10

    def test_can_produce_archive_is_false(
        self,
        esig_parser: ESigDocumentParser,
    ) -> None:
        assert esig_parser.can_produce_archive is False

    def test_requires_pdf_rendition_is_true(
        self,
        esig_parser: ESigDocumentParser,
    ) -> None:
        assert esig_parser.requires_pdf_rendition is True

    def test_get_page_count_returns_none_without_archive(
        self,
        esig_parser: ESigDocumentParser,
    ) -> None:
        assert (
            esig_parser.get_page_count(
                Path("does-not-exist.edoc"),
                ESIG_CONTAINER_MIME_TYPE,
            )
            is None
        )

    def test_context_manager_cleans_up_tempdir(self) -> None:
        with ESigDocumentParser() as parser:
            tempdir = parser._tempdir
            assert tempdir.exists()
        assert not tempdir.exists()


class TestEdocMimeHelpers:
    """Verify the libmagic workaround helpers."""

    def test_is_esig_container_path(
        self,
        edoc_container_bytes: bytes,
        tmp_path: Path,
    ) -> None:
        path = _write_container(tmp_path)
        assert is_esig_container(path) is True

    def test_is_esig_container_bytes(self, edoc_container_bytes: bytes) -> None:
        assert is_esig_container(edoc_container_bytes) is True

    def test_is_esig_container_plain_zip(self, tmp_path: Path) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("mimetype", "application/zip")
            archive.writestr("hello.txt", "hi")
        assert is_esig_container(buffer.getvalue()) is False

    def test_is_esig_container_encrypted_zip_does_not_raise(self) -> None:
        """Encrypted containers (allowed by ASiC-E) must not crash detection."""

        class _EncryptedZipStub:
            def __enter__(self):
                return self

            def __exit__(self, *args) -> bool:
                return False

            @staticmethod
            def read(name: str) -> bytes:
                raise RuntimeError(
                    f"File {name!r} is encrypted, password required for extraction",
                )

        with mock.patch(
            "paperless_esig.parser.zipfile.ZipFile",
            return_value=_EncryptedZipStub(),
        ):
            assert is_esig_container(b"PK\x03\x04") is False

    def test_is_esig_container_garbage(self) -> None:
        assert is_esig_container(b"not a zip at all") is False
        assert is_esig_container(b"") is False


class TestEdocContainerParsing:
    """Verify parsing of synthetic EDOC containers."""

    def test_parse_extracts_pdf_text(
        self,
        mocker,
        esig_parser: ESigDocumentParser,
        tmp_path: Path,
    ) -> None:
        path = _write_container(tmp_path)
        mocked = mocker.patch(
            "paperless.parsers.utils.extract_pdf_text",
            return_value="Hello EDOC",
        )

        esig_parser.parse(path, ESIG_CONTAINER_MIME_TYPE)

        assert mocked.called
        assert esig_parser.get_text() == "Hello EDOC"

        archive_path = esig_parser.get_archive_path()
        assert archive_path is not None
        assert archive_path.is_file()
        assert archive_path.read_bytes()[:4] == b"%PDF"
        assert esig_parser.get_date() == datetime.datetime(
            2026,
            1,
            15,
            10,
            30,
            0,
            tzinfo=datetime.UTC,
        )

    def test_parse_returns_page_count(
        self,
        mocker,
        esig_parser: ESigDocumentParser,
        tmp_path: Path,
    ) -> None:
        path = _write_container(tmp_path)
        mocker.patch(
            "paperless.parsers.utils.extract_pdf_text",
            return_value="Hello EDOC",
        )

        esig_parser.parse(path, ESIG_CONTAINER_MIME_TYPE)

        page_count = esig_parser.get_page_count(path, ESIG_CONTAINER_MIME_TYPE)
        assert isinstance(page_count, int)
        assert page_count >= 1

    def test_parse_falls_back_to_pdf_creation_date(
        self,
        mocker,
        esig_parser: ESigDocumentParser,
        tmp_path: Path,
    ) -> None:
        path = _write_container(tmp_path, signing_time=None)
        mocker.patch(
            "paperless.parsers.utils.extract_pdf_text",
            return_value="Hello EDOC",
        )

        esig_parser.parse(path, ESIG_CONTAINER_MIME_TYPE)

        assert esig_parser.get_date() == datetime.datetime(
            2026,
            1,
            15,
            10,
            30,
            0,
            tzinfo=datetime.UTC,
        )

    def test_parse_signing_time_with_offset(
        self,
        mocker,
        esig_parser: ESigDocumentParser,
        tmp_path: Path,
    ) -> None:
        signing_time = datetime.datetime(
            2026,
            7,
            2,
            9,
            52,
            1,
            tzinfo=datetime.timezone(datetime.timedelta(hours=3)),
        )
        path = _write_container(tmp_path, signing_time=signing_time)
        mocker.patch(
            "paperless.parsers.utils.extract_pdf_text",
            return_value="Hello EDOC",
        )

        esig_parser.parse(path, ESIG_CONTAINER_MIME_TYPE)

        assert esig_parser.get_date() == signing_time

    def test_parse_missing_file_raises(self, esig_parser: ESigDocumentParser) -> None:
        with pytest.raises(ParseError):
            esig_parser.parse(
                Path("does-not-exist.edoc"),
                ESIG_CONTAINER_MIME_TYPE,
            )

    def test_parse_plain_zip_raises(
        self,
        esig_parser: ESigDocumentParser,
        tmp_path: Path,
    ) -> None:
        path = tmp_path / "plain.edoc"
        path.write_bytes(b"PK\x03\x04\x00\x00\x00\x00\x00\x00")
        with pytest.raises(ParseError, match="Could not parse signed document"):
            esig_parser.parse(path, ESIG_CONTAINER_MIME_TYPE)

    def test_parse_wrong_container_mimetype_raises(
        self,
        esig_parser: ESigDocumentParser,
        tmp_path: Path,
    ) -> None:
        path = _write_container(
            tmp_path,
            container_mimetype="application/vnd.etsi.asic-s+zip",
        )
        with pytest.raises(ParseError, match="mimetype"):
            esig_parser.parse(path, ESIG_CONTAINER_MIME_TYPE)

    def test_parse_container_without_pdf_raises(
        self,
        esig_parser: ESigDocumentParser,
        tmp_path: Path,
    ) -> None:
        path = _write_container(
            tmp_path,
            document_name="document.txt",
            document_data=b"this is not a pdf",
        )
        with pytest.raises(ParseError, match="PDF"):
            esig_parser.parse(path, ESIG_CONTAINER_MIME_TYPE)

    def test_parse_container_without_signatures_raises(
        self,
        esig_parser: ESigDocumentParser,
        tmp_path: Path,
    ) -> None:
        path = _write_container(tmp_path, include_signature=False)
        with pytest.raises(ParseError, match="signature"):
            esig_parser.parse(path, ESIG_CONTAINER_MIME_TYPE)

    def test_parse_orders_signed_reference_before_manifest(
        self,
        mocker,
        esig_parser: ESigDocumentParser,
        tmp_path: Path,
    ) -> None:
        """The XAdES reference URI is merged before the manifest file list."""
        manifest_pdf = build_simple_pdf(text="Manifest PDF")
        signed_pdf = build_simple_pdf(text="Signed PDF")
        path = _write_container(
            tmp_path,
            document_name="document.pdf",
            document_data=manifest_pdf,
            signed_name="signed.pdf",
            extra_entries={"signed.pdf": signed_pdf},
        )
        mocker.patch(
            "paperless.parsers.utils.extract_pdf_text",
            return_value="Signed PDF",
        )

        esig_parser.parse(path, ESIG_CONTAINER_MIME_TYPE)

        # Both inner documents are merged into the rendition, the signed
        # reference first.
        assert esig_parser.get_page_count(path, ESIG_CONTAINER_MIME_TYPE) == 2
        text = esig_parser.get_text()
        assert text.index("=== signed.pdf ===") < text.index("=== document.pdf ===")

    def test_get_thumbnail_uses_rendition(
        self,
        mocker,
        esig_parser: ESigDocumentParser,
        tmp_path: Path,
    ) -> None:
        path = _write_container(tmp_path)
        mocker.patch(
            "paperless.parsers.utils.extract_pdf_text",
            return_value="Hello EDOC",
        )
        thumbnail = mocker.patch(
            "paperless_esig.parser.make_thumbnail_from_pdf",
            return_value=tmp_path / "thumb.webp",
        )

        result = esig_parser.get_thumbnail(path, ESIG_CONTAINER_MIME_TYPE)

        assert thumbnail.called
        assert result == tmp_path / "thumb.webp"

    def test_parse_c14n11_edoc_signatures_naming(
        self,
        mocker,
        esig_parser: ESigDocumentParser,
        tmp_path: Path,
    ) -> None:
        """The eParaksts mobile profile consumes end to end.

        Real-world containers produced by the eParaksts mobile signing
        library store their XAdES signature in
        ``META-INF/edoc-signatures-S1.xml`` (the name mandated by the
        Latvian EDOC 2.0 specification) and sign with inclusive
        c14n 1.1 over an ECDSA P-384 key.
        """
        path = _write_container(
            tmp_path,
            canonicalization="inclusive",
            key_type="ec",
            signature_file_name="META-INF/edoc-signatures-S1.xml",
        )
        mocker.patch(
            "paperless.parsers.utils.extract_pdf_text",
            return_value="Hello EDOC",
        )

        esig_parser.parse(path, ESIG_CONTAINER_MIME_TYPE)

        archive_path = esig_parser.get_archive_path()
        assert archive_path is not None
        assert archive_path.read_bytes() == build_simple_pdf()
        assert esig_parser.get_text() == "Hello EDOC"

    def test_parse_resolves_signer_name(
        self,
        mocker,
        esig_parser: ESigDocumentParser,
        tmp_path: Path,
    ) -> None:
        """The signer's organization is exposed after parsing."""
        path = _write_container(tmp_path)
        mocker.patch(
            "paperless.parsers.utils.extract_pdf_text",
            return_value="Hello EDOC",
        )

        esig_parser.parse(path, ESIG_CONTAINER_MIME_TYPE)

        assert esig_parser.get_signer_name() == "Test Organization"

    def test_parse_signer_name_falls_back_to_common_name(
        self,
        mocker,
        esig_parser: ESigDocumentParser,
        tmp_path: Path,
    ) -> None:
        """Without an organization attribute the common name is used."""
        path = _write_container(tmp_path, signer_org=None)
        mocker.patch(
            "paperless.parsers.utils.extract_pdf_text",
            return_value="Hello EDOC",
        )

        esig_parser.parse(path, ESIG_CONTAINER_MIME_TYPE)

        assert esig_parser.get_signer_name() == "Test Signer"

    def test_parse_signer_name_ignores_placeholder_common_name(
        self,
        mocker,
        esig_parser: ESigDocumentParser,
        tmp_path: Path,
    ) -> None:
        """A placeholder CN (e.g. eParaksts mobile) yields no name."""
        path = _write_container(tmp_path, signer_org=None, signer_cn="Private")
        mocker.patch(
            "paperless.parsers.utils.extract_pdf_text",
            return_value="Hello EDOC",
        )

        esig_parser.parse(path, ESIG_CONTAINER_MIME_TYPE)

        assert esig_parser.get_signer_name() is None

    def test_parse_signer_name_mobile_signing_variant(
        self,
        mocker,
        esig_parser: ESigDocumentParser,
        tmp_path: Path,
    ) -> None:
        """Signer resolution works for the eParaksts mobile profile."""
        path = _write_container(
            tmp_path,
            canonicalization="inclusive",
            key_type="ec",
            signature_file_name="META-INF/edoc-signatures-S1.xml",
        )
        mocker.patch(
            "paperless.parsers.utils.extract_pdf_text",
            return_value="Hello EDOC",
        )

        esig_parser.parse(path, ESIG_CONTAINER_MIME_TYPE)

        assert esig_parser.get_signer_name() == "Test Organization"

    def test_get_signer_name_none_before_parse(
        self,
        esig_parser: ESigDocumentParser,
    ) -> None:
        assert esig_parser.get_signer_name() is None


class TestEdocNestedContainers:
    """Verify parsing of nested containers ("EDOC within EDOC").

    The Latvian e-archive produces bundles whose outer container wraps
    documents plus an inner EDOC container carrying the actual PDF.
    """

    def _write_nested_container(
        self,
        tmp_path: Path,
        *,
        filename: str = "bundle.edoc",
        **kwargs,
    ) -> Path:
        path = tmp_path / filename
        path.write_bytes(build_nested_edoc_container(**kwargs))
        return path

    def test_parse_nested_container_extracts_inner_pdf(
        self,
        mocker,
        esig_parser: ESigDocumentParser,
        tmp_path: Path,
    ) -> None:
        path = self._write_nested_container(tmp_path)
        mocked = mocker.patch(
            "paperless.parsers.utils.extract_pdf_text",
            return_value="Hello Nested EDOC",
        )

        esig_parser.parse(path, ESIG_CONTAINER_MIME_TYPE)

        assert mocked.called
        assert esig_parser.get_text() == "Hello Nested EDOC"
        assert esig_parser.get_date() == datetime.datetime(
            2026,
            1,
            15,
            10,
            30,
            0,
            tzinfo=datetime.UTC,
        )

        archive_path = esig_parser.get_archive_path()
        assert archive_path is not None
        assert archive_path.is_file()
        assert archive_path.read_bytes()[:4] == b"%PDF"

    def test_parse_nested_container_with_docx_entries(
        self,
        mocker,
        esig_parser: ESigDocumentParser,
        tmp_path: Path,
    ) -> None:
        """DOCX companions do not shadow the nested container."""
        inner_pdf = build_simple_pdf(text="Inner decision PDF")
        path = self._write_nested_container(
            tmp_path,
            inner_document_data=inner_pdf,
            extra_entries={
                "lemums.docx": b"PK\x03\x04docx-bytes",
                "protokols.docx": b"PK\x03\x04docx-bytes",
            },
        )
        mocker.patch(
            "paperless.parsers.utils.extract_pdf_text",
            return_value="Inner decision PDF",
        )

        esig_parser.parse(path, ESIG_CONTAINER_MIME_TYPE)

        archive_path = esig_parser.get_archive_path()
        assert archive_path is not None
        assert archive_path.read_bytes() == inner_pdf

    def test_parse_nested_container_returns_page_count(
        self,
        mocker,
        esig_parser: ESigDocumentParser,
        tmp_path: Path,
    ) -> None:
        path = self._write_nested_container(tmp_path)
        mocker.patch(
            "paperless.parsers.utils.extract_pdf_text",
            return_value="Hello Nested EDOC",
        )

        esig_parser.parse(path, ESIG_CONTAINER_MIME_TYPE)

        page_count = esig_parser.get_page_count(path, ESIG_CONTAINER_MIME_TYPE)
        assert isinstance(page_count, int)
        assert page_count >= 1

    def test_parse_nested_container_without_inner_pdf_raises(
        self,
        esig_parser: ESigDocumentParser,
        tmp_path: Path,
    ) -> None:
        inner = build_esig_container(
            document_name="document.bin",
            document_data=b"this is not a pdf",
        )
        outer = build_esig_container(
            document_data=inner,
            document_name="nested.edoc",
            signed_name="nested.edoc",
            canonicalization="inclusive",
            key_type="ec",
            signature_file_name="META-INF/edoc-signatures-S1.xml",
        )
        path = tmp_path / "bundle.edoc"
        path.write_bytes(outer)

        with pytest.raises(ParseError, match="PDF"):
            esig_parser.parse(path, ESIG_CONTAINER_MIME_TYPE)

    def test_metadata_nested_container_uses_outer_signature(
        self,
        tmp_path: Path,
    ) -> None:
        path = self._write_nested_container(
            tmp_path,
            signer_cn="Bundle Signer",
            signer_org="Bundle Organization",
            signer_country="LV",
        )
        with ESigDocumentParser() as parser:
            metadata = parser.extract_metadata(path, ESIG_CONTAINER_MIME_TYPE)

        def _entry(prefix: str, key: str) -> str | None:
            for entry in metadata:
                if entry["prefix"] == prefix and entry["key"] == key:
                    return entry["value"]
            return None

        assert _entry("container", "mimetype") == ESIG_CONTAINER_MIME_TYPE
        assert _entry("container", "nested.edoc") == "application/octet-stream"
        assert _entry("signature", "signature_count") == "1"
        assert _entry("signature", "signing_time") == "2026-01-15T10:30:00Z"
        assert _entry("signature", "signer_name") == "Bundle Signer"
        assert _entry("signature", "signer_organization") == "Bundle Organization"
        assert _entry("signature", "signature_algorithm") == "ecdsa-sha256"
        assert _entry("signature", "document_digest_valid") == "true"
        assert _entry("signature", "signed_properties_valid") == "true"
        assert _entry("signature", "signature_valid") == "true"

    @override_settings(TIKA_ENDPOINT="", TIKA_GOTENBERG_ENDPOINT="")
    def test_parse_bundle_merges_docx_and_pdf(
        self,
        mocker,
        esig_parser: ESigDocumentParser,
        tmp_path: Path,
    ) -> None:
        """All inner documents merge into one rendition, text included."""
        path = self._write_nested_container(
            tmp_path,
            extra_entries={
                "lemums.docx": build_simple_docx("Decision text"),
                "protokols.docx": build_simple_docx("Protocol text"),
            },
        )
        mocker.patch.object(
            esig_parser,
            "_office_to_pdf",
            return_value=build_simple_pdf(text="DOCX PAGE"),
        )
        mocker.patch(
            "paperless.parsers.utils.extract_pdf_text",
            return_value="Certificate text",
        )

        esig_parser.parse(path, ESIG_CONTAINER_MIME_TYPE)

        # Inner PDF plus both converted DOCX pages
        assert esig_parser.get_page_count(path, ESIG_CONTAINER_MIME_TYPE) == 3
        text = esig_parser.get_text()
        assert "Certificate text" in text
        assert "Decision text" in text
        assert "Protocol text" in text
        # Signature-reference order is preserved in text and rendition
        assert text.index("=== lemums.docx ===") < text.index("=== nested.edoc ===")

    @override_settings(TIKA_ENDPOINT="", TIKA_GOTENBERG_ENDPOINT="")
    def test_parse_bundle_without_services_keeps_docx_text(
        self,
        mocker,
        esig_parser: ESigDocumentParser,
        tmp_path: Path,
    ) -> None:
        """Without Tika/Gotenberg the DOCX text is still extracted locally."""
        path = self._write_nested_container(
            tmp_path,
            extra_entries={"lemums.docx": build_simple_docx("Decision text")},
        )
        mocker.patch(
            "paperless.parsers.utils.extract_pdf_text",
            return_value="Certificate text",
        )

        esig_parser.parse(path, ESIG_CONTAINER_MIME_TYPE)

        text = esig_parser.get_text()
        assert "Certificate text" in text
        assert "Decision text" in text
        # The DOCX pages cannot be rendered without Gotenberg
        assert esig_parser.get_page_count(path, ESIG_CONTAINER_MIME_TYPE) == 1

    @override_settings(TIKA_ENDPOINT="http://tika:9998", TIKA_GOTENBERG_ENDPOINT="")
    def test_parse_bundle_prefers_tika_text(
        self,
        mocker,
        esig_parser: ESigDocumentParser,
        tmp_path: Path,
    ) -> None:
        """Tika text wins over the local DOCX extraction when available."""
        tika_client_mock = mocker.patch("tika_client.TikaClient")
        parsed = tika_client_mock.return_value.__enter__.return_value.tika.as_text.from_buffer.return_value
        parsed.content = "Tika decision text"
        path = self._write_nested_container(
            tmp_path,
            extra_entries={"lemums.docx": build_simple_docx("Local fallback text")},
        )
        mocker.patch(
            "paperless.parsers.utils.extract_pdf_text",
            return_value="Certificate text",
        )

        esig_parser.parse(path, ESIG_CONTAINER_MIME_TYPE)

        text = esig_parser.get_text()
        assert "Tika decision text" in text
        assert "Local fallback text" not in text


class TestEdocMetadata:
    """Verify metadata extraction from the XAdES signature."""

    def _metadata(
        self,
        tmp_path: Path,
        **kwargs,
    ) -> list[MetadataEntry]:
        path = _write_container(tmp_path, **kwargs)
        with ESigDocumentParser() as parser:
            return parser.extract_metadata(path, ESIG_CONTAINER_MIME_TYPE)

    def _entry(
        self,
        metadata: list[MetadataEntry],
        prefix: str,
        key: str,
    ) -> str | None:
        for entry in metadata:
            if entry["prefix"] == prefix and entry["key"] == key:
                return entry["value"]
        return None

    def test_metadata_archive_mime_returns_empty(self, tmp_path: Path) -> None:
        # Unsigned PDFs (and anything that is not a signed format) yield
        # no metadata from this parser — they belong to the built-in
        # PDF parser.
        path = tmp_path / "plain.pdf"
        path.write_bytes(b"%PDF-1.4 not really a pdf")
        with ESigDocumentParser() as parser:
            assert parser.extract_metadata(path, "application/pdf") == []

    def test_metadata_plain_zip_returns_empty(self, tmp_path: Path) -> None:
        path = tmp_path / "plain.edoc"
        path.write_bytes(b"PK\x03\x04\x00\x00\x00\x00\x00\x00")
        with ESigDocumentParser() as parser:
            assert parser.extract_metadata(path, ESIG_CONTAINER_MIME_TYPE) == []

    def test_metadata_container_entries(self, tmp_path: Path) -> None:
        metadata = self._metadata(tmp_path)

        assert (
            self._entry(metadata, "container", "mimetype") == ESIG_CONTAINER_MIME_TYPE
        )
        assert self._entry(metadata, "container", "document.pdf") == "application/pdf"

    def test_metadata_signature_entries(self, tmp_path: Path) -> None:
        metadata = self._metadata(
            tmp_path,
            signer_cn="Test Signer",
            signer_org="Test Organization",
            signer_country="LV",
        )

        assert self._entry(metadata, "signature", "signature_count") == "1"
        assert (
            self._entry(metadata, "signature", "signing_time") == "2026-01-15T10:30:00Z"
        )
        assert self._entry(metadata, "signature", "signer_name") == "Test Signer"
        assert (
            self._entry(metadata, "signature", "signer_organization")
            == "Test Organization"
        )
        assert self._entry(metadata, "signature", "signer_country") == "LV"
        assert (
            self._entry(metadata, "signature", "signer_certificate_serial") is not None
        )
        assert self._entry(metadata, "signature", "signature_algorithm") == "rsa-sha256"
        assert self._entry(metadata, "signature", "digest_algorithm") == "sha256"
        assert self._entry(metadata, "signature", "document_digest_valid") == "true"
        assert self._entry(metadata, "signature", "signed_properties_valid") == "true"
        assert self._entry(metadata, "signature", "signature_valid") == "true"

    def test_metadata_certificate_chain_and_liveness(self, tmp_path: Path) -> None:
        metadata = self._metadata(tmp_path)

        assert self._entry(metadata, "signature", "certificate_count") == "2"
        assert (
            self._entry(metadata, "signature", "certificate_chain")
            == "Test Root CA > Test Intermediate CA"
        )
        assert self._entry(metadata, "signature", "ocsp_response_count") == "1"

    def test_metadata_timestamp(self, tmp_path: Path) -> None:
        metadata = self._metadata(tmp_path)

        assert self._entry(metadata, "timestamp", "signature_timestamp") == "present"
        assert self._entry(metadata, "timestamp", "timestamp_authority") == "Test TSA"

    def test_metadata_without_timestamp(self, tmp_path: Path) -> None:
        metadata = self._metadata(tmp_path, include_timestamp=False)

        assert self._entry(metadata, "timestamp", "signature_timestamp") is None

    def test_metadata_tampered_payload(self, tmp_path: Path) -> None:
        """Digest covers different bytes than the stored payload."""
        other = build_simple_pdf(text="Different document")
        metadata = self._metadata(tmp_path, digest_over=other)

        assert self._entry(metadata, "signature", "document_digest_valid") == "false"
        assert self._entry(metadata, "signature", "signed_properties_valid") == "true"
        assert self._entry(metadata, "signature", "signature_valid") == "true"

    def test_metadata_tampered_signature(self, tmp_path: Path) -> None:
        """Signature value is computed over different bytes."""
        metadata = self._metadata(tmp_path, sign_over=b"tampered signed info")

        assert self._entry(metadata, "signature", "signature_valid") == "false"

    def test_metadata_tampered_signed_properties(self, tmp_path: Path) -> None:
        """SigningTime changed after signing: SignedProperties digest mismatch."""
        data = build_esig_container()
        tampered_signature = (
            zipfile.ZipFile(io.BytesIO(data))
            .read("META-INF/signatures001.xml")
            .replace(b"2026-01-15T10:30:00Z", b"2026-01-15T10:31:00Z")
        )

        buffer = io.BytesIO()
        with (
            zipfile.ZipFile(io.BytesIO(data)) as source,
            zipfile.ZipFile(
                buffer,
                "w",
            ) as target,
        ):
            for item in source.infolist():
                content = (
                    tampered_signature
                    if item.filename == "META-INF/signatures001.xml"
                    else source.read(item.filename)
                )
                target.writestr(item, content)
        path = tmp_path / "tampered.edoc"
        path.write_bytes(buffer.getvalue())

        with ESigDocumentParser() as parser:
            metadata = parser.extract_metadata(path, ESIG_CONTAINER_MIME_TYPE)

        assert self._entry(metadata, "signature", "signed_properties_valid") == "false"
        assert self._entry(metadata, "signature", "document_digest_valid") == "true"
        assert self._entry(metadata, "signature", "signature_valid") == "true"

    def test_metadata_signer_cert_from_certificate_values(self, tmp_path: Path) -> None:
        """The signer certificate can live only in CertificateValues."""
        metadata = self._metadata(
            tmp_path,
            include_keyinfo_cert=False,
            include_signer_in_certificate_values=True,
        )

        assert self._entry(metadata, "signature", "signer_name") == "Test Signer"
        assert self._entry(metadata, "signature", "signature_valid") == "true"
        assert self._entry(metadata, "signature", "certificate_count") == "3"
        assert (
            self._entry(metadata, "signature", "certificate_chain")
            == "Test Signer > Test Root CA > Test Intermediate CA"
        )

    def test_metadata_sorted(self, tmp_path: Path) -> None:
        metadata = self._metadata(tmp_path)

        keys = [(entry["prefix"], entry["key"]) for entry in metadata]
        assert keys == sorted(keys)

    def test_metadata_c14n11_ecdsa_signature(self, tmp_path: Path) -> None:
        """The eParaksts mobile profile verifies under inclusive c14n 1.1.

        Containers signed with the eParaksts mobile signing library
        declare ``xml-c14n11`` canonicalisation and an ECDSA signature;
        the offline verification must honour the declared method instead
        of assuming exclusive canonicalisation.
        """
        metadata = self._metadata(
            tmp_path,
            canonicalization="inclusive",
            key_type="ec",
            signature_file_name="META-INF/edoc-signatures-S1.xml",
        )

        assert (
            self._entry(metadata, "signature", "signature_algorithm") == "ecdsa-sha256"
        )
        assert self._entry(metadata, "signature", "document_digest_valid") == "true"
        assert self._entry(metadata, "signature", "signed_properties_valid") == "true"
        assert self._entry(metadata, "signature", "signature_valid") == "true"
        assert self._entry(metadata, "signature", "signer_name") == "Test Signer"

    def test_metadata_c14n11_tampered_signature(self, tmp_path: Path) -> None:
        """A tampered c14n 1.1 signature is reported as invalid."""
        metadata = self._metadata(
            tmp_path,
            canonicalization="inclusive",
            key_type="ec",
            signature_file_name="META-INF/edoc-signatures-S1.xml",
            sign_over=b"tampered signed info",
        )

        assert self._entry(metadata, "signature", "document_digest_valid") == "true"
        assert self._entry(metadata, "signature", "signed_properties_valid") == "true"
        assert self._entry(metadata, "signature", "signature_valid") == "false"

    def test_metadata_finds_edoc_signatures_naming(self, tmp_path: Path) -> None:
        """Signature files named per the Latvian EDOC 2.0 spec are found."""
        data = build_esig_container(
            canonicalization="inclusive",
            key_type="ec",
            signature_file_name="META-INF/edoc-signatures-S1.xml",
        )
        assert (
            zipfile.ZipFile(io.BytesIO(data)).read("META-INF/edoc-signatures-S1.xml")
            is not None
        )
        metadata = self._metadata(
            tmp_path,
            canonicalization="inclusive",
            key_type="ec",
            signature_file_name="META-INF/edoc-signatures-S1.xml",
        )
        assert self._entry(metadata, "signature", "signature_count") == "1"


class TestEdocConfigure:
    def test_configure_is_noop(self, esig_parser: ESigDocumentParser) -> None:
        esig_parser.configure(ParserContext())
        esig_parser.configure(ParserContext(mailrule_id=1))
