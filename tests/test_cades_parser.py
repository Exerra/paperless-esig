"""
Parser integration tests for CAdES (.p7m) and PAdES documents.

The fixtures mirror the signature profiles found in the wild: attached
CAdES signatures, PAdES PDFs with both subfilters, BER encodings and
the date fallbacks for signatures without a signing time.
"""

from __future__ import annotations

import datetime
from typing import TYPE_CHECKING

import pytest
from documents.parsers import ParseError

from cades_fixtures import (
    build_cms,
    build_pades_pdf,
    build_signer,
    pades_covered_bytes,
)
from paperless_esig import pades as esig_pades
from paperless_esig.parser import ESigDocumentParser, extract_signer_name

if TYPE_CHECKING:
    from pathlib import Path

_CONTENT_STREAM = b"BT /F1 24 Tf 72 720 Td (Hello PAdES) Tj ET"

_SIGNING_TIME = datetime.datetime(
    2026,
    1,
    15,
    10,
    30,
    0,
    tzinfo=datetime.UTC,
)


def _write_cades(tmp_path: Path, cades: bytes, filename: str = "doc.p7m") -> Path:
    path = tmp_path / filename
    path.write_bytes(cades)
    return path


def _write_pades(tmp_path: Path, pdf: bytes, filename: str = "doc.pdf") -> Path:
    path = tmp_path / filename
    path.write_bytes(pdf)
    return path


def _build_signed_pdf(
    *,
    subfilter: str = "ETSI.CAdES.detached",
    m: str = "D:20260115103000Z",
    with_signing_time: bool = True,
    contents_size: int = 4096,
) -> bytes:
    key, cert, _ = build_signer()
    template = build_pades_pdf(
        _CONTENT_STREAM,
        b"\x00" * contents_size,
        subfilter=subfilter,
        m=m,
    )
    covered = pades_covered_bytes(template)
    cms_bytes = build_cms(
        covered,
        key=key,
        certificate=cert,
        attached=False,
        signing_time=_SIGNING_TIME,
        with_signing_time=with_signing_time,
    )
    return build_pades_pdf(
        _CONTENT_STREAM,
        cms_bytes,
        subfilter=subfilter,
        m=m,
    )


def _metadata_value(
    metadata: list[dict],
    prefix: str,
    key: str,
) -> str | None:
    for entry in metadata:
        if entry["prefix"] == prefix and entry["key"] == key:
            return entry["value"]
    return None


class TestCadesScoring:
    def test_p7m_content_claimed(self, tmp_path: Path) -> None:
        key, cert, _ = build_signer()
        path = _write_cades(
            tmp_path,
            build_cms(b"x", key=key, certificate=cert),
        )
        assert (
            ESigDocumentParser.score(
                "application/octet-stream",
                path.name,
                path,
            )
            == 10
        )

    def test_non_signature_octet_stream_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "random.bin"
        path.write_bytes(b"not a cms")
        assert (
            ESigDocumentParser.score(
                "application/octet-stream",
                path.name,
                path,
            )
            is None
        )

    def test_pkcs7_mime_content_checked_with_path(self, tmp_path: Path) -> None:
        key, cert, _ = build_signer()
        valid = _write_cades(
            tmp_path,
            build_cms(b"x", key=key, certificate=cert),
            filename="doc.p7m",
        )
        assert (
            ESigDocumentParser.score(
                "application/pkcs7-mime",
                valid.name,
                valid,
            )
            == 10
        )
        invalid = tmp_path / "not-signed.p7m"
        invalid.write_bytes(b"definitely not a CMS")
        assert (
            ESigDocumentParser.score(
                "application/pkcs7-mime",
                invalid.name,
                invalid,
            )
            is None
        )

    def test_signed_pdf_claimed(self, tmp_path: Path) -> None:
        path = _write_pades(tmp_path, _build_signed_pdf())
        assert (
            ESigDocumentParser.score("application/pdf", path.name, path) == 10
        )

    def test_unsigned_pdf_not_claimed(self, tmp_path: Path) -> None:
        path = _write_pades(tmp_path, b"%PDF-1.4\n1 0 obj\n<< >>\nendobj\n")
        assert (
            ESigDocumentParser.score("application/pdf", path.name, path)
            is None
        )


class TestCadesParse:
    def test_parse_p7m_extracts_pdf(
        self,
        esig_parser: ESigDocumentParser,
        tmp_path: Path,
    ) -> None:
        key, cert, _ = build_signer()
        path = _write_cades(
            tmp_path,
            build_cms(
                b"%PDF-1.4\n%%EOF",
                key=key,
                certificate=cert,
                signing_time=_SIGNING_TIME,
            ),
        )
        esig_parser.parse(path, "application/octet-stream")
        assert esig_parser.get_archive_path() is not None
        assert esig_parser.get_archive_path().read_bytes() == b"%PDF-1.4\n%%EOF"
        assert esig_parser.get_date() == _SIGNING_TIME
        assert esig_parser.get_signer_name() == "Test Organization"

    def test_parse_p7m_date_falls_back_to_pdf_creation(
        self,
        esig_parser: ESigDocumentParser,
        tmp_path: Path,
    ) -> None:
        key, cert, _ = build_signer()
        path = _write_cades(
            tmp_path,
            build_cms(
                b"%PDF-1.4\n%%EOF",
                key=key,
                certificate=cert,
                with_signing_time=False,
            ),
        )
        esig_parser.parse(path, "application/octet-stream")
        # No signing time and no parseable PDF date in the payload.
        assert esig_parser.get_date() is None

    def test_parse_detached_cades_rejected(
        self,
        esig_parser: ESigDocumentParser,
        tmp_path: Path,
    ) -> None:
        key, cert, _ = build_signer()
        path = _write_cades(
            tmp_path,
            build_cms(b"x", key=key, certificate=cert, attached=False),
            filename="sig.p7s",
        )
        with pytest.raises(ParseError, match="attached content"):
            esig_parser.parse(path, "application/pkcs7-signature")

    def test_parse_cades_non_pdf_content_raises(
        self,
        esig_parser: ESigDocumentParser,
        tmp_path: Path,
    ) -> None:
        key, cert, _ = build_signer()
        path = _write_cades(
            tmp_path,
            build_cms(b"<xml>not a pdf</xml>", key=key, certificate=cert),
        )
        with pytest.raises(ParseError, match="not a PDF"):
            esig_parser.parse(path, "application/octet-stream")

    def test_parse_pades_extracts_text(
        self,
        esig_parser: ESigDocumentParser,
        tmp_path: Path,
    ) -> None:
        path = _write_pades(tmp_path, _build_signed_pdf())
        esig_parser.parse(path, "application/pdf")
        archive = esig_parser.get_archive_path()
        assert archive is not None
        assert archive.read_bytes() == path.read_bytes()
        assert esig_parser.get_date() == _SIGNING_TIME
        assert esig_parser.get_signer_name() == "Test Organization"

    def test_parse_pades_without_signing_time_uses_m_field(
        self,
        esig_parser: ESigDocumentParser,
        tmp_path: Path,
    ) -> None:
        pdf = _build_signed_pdf(with_signing_time=False, m="D:20260304050607+02'00'")
        path = _write_pades(tmp_path, pdf)
        esig_parser.parse(path, "application/pdf")
        # 2026-03-04T05:06:07+02:00 == 03:06:07Z.
        assert esig_parser.get_date() == datetime.datetime(
            2026,
            3,
            4,
            3,
            6,
            7,
            tzinfo=datetime.UTC,
        )

    def test_parse_pades_without_any_date(self, tmp_path: Path) -> None:
        # No CMS signing time, no /M field, no PDF creation date in the
        # synthetic payload: the date must be None.
        key, cert, _ = build_signer()
        template = build_pades_pdf(
            _CONTENT_STREAM,
            b"\x00" * 4096,
            m=None,
        )
        covered = pades_covered_bytes(template)
        cms_bytes = build_cms(
            covered,
            key=key,
            certificate=cert,
            attached=False,
            with_signing_time=False,
        )
        pdf = build_pades_pdf(_CONTENT_STREAM, cms_bytes, m=None)
        path = _write_pades(tmp_path, pdf)
        with ESigDocumentParser() as parser:
            parser.parse(path, "application/pdf")
            assert parser.get_date() is None
            assert parser.get_signer_name() == "Test Organization"

    def test_parse_plain_file_raises(
        self,
        esig_parser: ESigDocumentParser,
        tmp_path: Path,
    ) -> None:
        path = tmp_path / "plain.txt"
        path.write_bytes(b"nothing signed here")
        with pytest.raises(ParseError, match="Could not parse signed document"):
            esig_parser.parse(path, "text/plain")


class TestCadesMetadata:
    def test_p7m_metadata(
        self,
        tmp_path: Path,
    ) -> None:
        key, cert, _ = build_signer()
        path = _write_cades(
            tmp_path,
            build_cms(
                b"%PDF-1.4\n%%EOF",
                key=key,
                certificate=cert,
                signing_time=_SIGNING_TIME,
            ),
        )
        with ESigDocumentParser() as parser:
            metadata = parser.extract_metadata(path, "application/octet-stream")
        assert _metadata_value(metadata, "signature", "signature_count") == "1"
        assert (
            _metadata_value(metadata, "signature", "signing_time")
            == "2026-01-15T10:30:00+00:00"
        )
        assert (
            _metadata_value(metadata, "signature", "document_digest_valid")
            == "true"
        )
        assert (
            _metadata_value(metadata, "signature", "signature_valid") == "true"
        )
        assert (
            _metadata_value(metadata, "signature", "signer_name")
            == "Test Signer"
        )
        assert (
            _metadata_value(metadata, "signature", "signer_organization")
            == "Test Organization"
        )

    def test_p7m_metadata_tampered_content(
        self,
        tmp_path: Path,
    ) -> None:
        key, cert, _ = build_signer()
        content = b"original content"
        path = _write_cades(
            tmp_path,
            build_cms(content, key=key, certificate=cert),
        )
        data = path.read_bytes()
        # Flip a byte inside the embedded content.
        offset = data.find(b"original content")
        assert offset != -1
        path.write_bytes(
            data[:offset] + bytes([data[offset] ^ 0xFF]) + data[offset + 1:],
        )
        with ESigDocumentParser() as parser:
            metadata = parser.extract_metadata(path, "application/octet-stream")
        assert (
            _metadata_value(metadata, "signature", "document_digest_valid")
            == "false"
        )

    def test_pades_metadata(
        self,
        tmp_path: Path,
    ) -> None:
        pdf = _build_signed_pdf()
        path = _write_pades(tmp_path, pdf)
        with ESigDocumentParser() as parser:
            metadata = parser.extract_metadata(path, "application/pdf")
        assert (
            _metadata_value(metadata, "signature", "pdf_subfilter")
            == "ETSI.CAdES.detached"
        )
        assert (
            _metadata_value(metadata, "signature", "signer_reason")
            == "Test Signer"
        )
        assert (
            _metadata_value(metadata, "signature", "document_digest_valid")
            == "true"
        )
        assert (
            _metadata_value(metadata, "signature", "signature_valid") == "true"
        )

    def test_pades_metadata_tampered_pdf(
        self,
        tmp_path: Path,
    ) -> None:
        pdf = _build_signed_pdf()
        tampered = bytearray(pdf)
        tampered[25] ^= 0xFF
        path = _write_pades(tmp_path, bytes(tampered))
        with ESigDocumentParser() as parser:
            metadata = parser.extract_metadata(path, "application/pdf")
        assert (
            _metadata_value(metadata, "signature", "document_digest_valid")
            == "false"
        )

    def test_p7m_metadata_with_timestamp_and_ocsp(
        self,
        tmp_path: Path,
    ) -> None:
        key, cert, _ = build_signer()
        path = _write_cades(
            tmp_path,
            build_cms(
                b"%PDF-1.4\n%%EOF",
                key=key,
                certificate=cert,
                with_timestamp=True,
                with_ocsp=True,
            ),
        )
        with ESigDocumentParser() as parser:
            metadata = parser.extract_metadata(path, "application/octet-stream")
        assert (
            _metadata_value(metadata, "timestamp", "signature_timestamp")
            == "present"
        )
        assert (
            _metadata_value(metadata, "signature", "ocsp_response_count") == "1"
        )

    def test_p7m_metadata_certificate_chain(self, tmp_path: Path) -> None:
        key, cert, _ = build_signer(common_name="Signer One", serial=1)
        _, filler, _ = build_signer(common_name="Filler CA", serial=2)
        path = _write_cades(
            tmp_path,
            build_cms(
                b"%PDF-1.4\n%%EOF",
                key=key,
                certificate=cert,
                include_certificates=[cert, filler],
            ),
        )
        with ESigDocumentParser() as parser:
            metadata = parser.extract_metadata(path, "application/octet-stream")
        # CMS certificates are a SET OF, so ordering is not guaranteed.
        chain = _metadata_value(metadata, "signature", "certificate_chain")
        assert chain is not None
        assert "Signer One" in chain
        assert "Filler CA" in chain

    def test_pades_metadata_name_field(self, tmp_path: Path) -> None:
        key, cert, _ = build_signer()
        template = build_pades_pdf(
            _CONTENT_STREAM,
            b"\x00" * 4096,
            name="Test Signer Name",
        )
        covered = pades_covered_bytes(template)
        cms_bytes = build_cms(covered, key=key, certificate=cert, attached=False)
        pdf = build_pades_pdf(
            _CONTENT_STREAM,
            cms_bytes,
            name="Test Signer Name",
        )
        path = _write_pades(tmp_path, pdf)
        with ESigDocumentParser() as parser:
            metadata = parser.extract_metadata(path, "application/pdf")
        assert (
            _metadata_value(metadata, "signature", "signer_pdf_name")
            == "Test Signer Name"
        )

    def test_metadata_unreadable_path_returns_empty(self, tmp_path: Path) -> None:
        with ESigDocumentParser() as parser:
            assert parser.extract_metadata(tmp_path, "application/pdf") == []
        path = _write_pades(tmp_path, b"%PDF-1.4\n%%EOF")
        with ESigDocumentParser() as parser:
            assert parser.extract_metadata(path, "application/pdf") == []

    def test_metadata_sorted(self, tmp_path: Path) -> None:
        key, cert, _ = build_signer()
        path = _write_cades(
            tmp_path,
            build_cms(b"x", key=key, certificate=cert),
        )
        with ESigDocumentParser() as parser:
            metadata = parser.extract_metadata(path, "application/octet-stream")
        keys = [(entry["prefix"], entry["key"]) for entry in metadata]
        assert keys == sorted(keys)


class TestExtractSignerName:
    def test_cades_signer_name(self, tmp_path: Path) -> None:
        key, cert, _ = build_signer()
        path = _write_cades(tmp_path, build_cms(b"x", key=key, certificate=cert))
        assert extract_signer_name(path) == "Test Organization"

    def test_cades_signer_name_bytes(self) -> None:
        key, cert, _ = build_signer()
        assert extract_signer_name(build_cms(b"x", key=key, certificate=cert)) == (
            "Test Organization"
        )

    def test_pades_signer_name(self, tmp_path: Path) -> None:
        path = _write_pades(tmp_path, _build_signed_pdf())
        assert extract_signer_name(path) == "Test Organization"

    def test_pades_signer_name_bytes(self) -> None:
        assert extract_signer_name(_build_signed_pdf()) == "Test Organization"

    def test_unsigned_pdf_returns_none(self, tmp_path: Path) -> None:
        path = _write_pades(tmp_path, b"%PDF-1.4\n%%EOF")
        assert extract_signer_name(path) is None

    def test_garbage_returns_none(self) -> None:
        assert extract_signer_name(b"garbage") is None


class TestBerTolerance:
    def test_ber_cades_parses(self, tmp_path: Path) -> None:
        from cades_fixtures import to_ber_indefinite

        key, cert, _ = build_signer()
        ber = to_ber_indefinite(
            build_cms(b"%PDF-1.4\n%%EOF", key=key, certificate=cert),
        )
        path = _write_cades(tmp_path, ber)
        with ESigDocumentParser() as parser:
            parser.parse(path, "application/octet-stream")
            assert parser.get_archive_path().read_bytes() == b"%PDF-1.4\n%%EOF"
            metadata = parser.extract_metadata(path, "application/octet-stream")
        assert (
            _metadata_value(metadata, "signature", "signature_valid") == "true"
        )

    def test_ber_pades_parses(self, tmp_path: Path) -> None:
        from cades_fixtures import to_ber_indefinite

        key, cert, _ = build_signer()
        template = build_pades_pdf(_CONTENT_STREAM, b"\x00" * 4096)
        covered = pades_covered_bytes(template)
        cms_bytes = to_ber_indefinite(
            build_cms(covered, key=key, certificate=cert, attached=False),
        )
        pdf = build_pades_pdf(_CONTENT_STREAM, cms_bytes)
        path = _write_pades(tmp_path, pdf)
        assert ESigDocumentParser.score("application/pdf", path.name, path) == 10
        with ESigDocumentParser() as parser:
            parser.parse(path, "application/pdf")
            assert esig_pades.find_pdf_signatures(pdf)[0].subfilter is not None
            assert parser.get_signer_name() == "Test Organization"

    def test_ber_adbe_profile_parses(self, tmp_path: Path) -> None:
        """BER CMS in an adbe.pkcs7.detached signature with a signing
        time and a single embedded certificate."""
        from cades_fixtures import to_ber_indefinite

        key, cert, _ = build_signer(
            common_name="Sample Person",
            organization=None,
            country="BR",
        )
        template = build_pades_pdf(
            _CONTENT_STREAM,
            b"\x00" * 8192,
            subfilter="adbe.pkcs7.detached",
            contents_size=8192,
        )
        covered = pades_covered_bytes(template)
        cms_bytes = to_ber_indefinite(
            build_cms(
                covered,
                key=key,
                certificate=cert,
                attached=False,
                signing_time=_SIGNING_TIME,
            ),
        )
        pdf = build_pades_pdf(
            _CONTENT_STREAM,
            cms_bytes,
            subfilter="adbe.pkcs7.detached",
            contents_size=8192,
        )
        path = _write_pades(tmp_path, pdf)
        assert ESigDocumentParser.score("application/pdf", path.name, path) == 10
        with ESigDocumentParser() as parser:
            parser.parse(path, "application/pdf")
            assert parser.get_date() == _SIGNING_TIME
            assert parser.get_signer_name() == "Sample Person"
            metadata = parser.extract_metadata(path, "application/pdf")
        assert (
            _metadata_value(metadata, "signature", "pdf_subfilter")
            == "adbe.pkcs7.detached"
        )
        assert (
            _metadata_value(metadata, "signature", "document_digest_valid")
            == "true"
        )
        assert (
            _metadata_value(metadata, "signature", "signature_valid") == "true"
        )
