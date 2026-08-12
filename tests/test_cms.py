"""
Tests for the CMS (CAdES) and PAdES parsing modules.

These run against synthetically signed data built by
:mod:`cades_fixtures` (no personal data) and mirror the signature
profiles found in the wild: RSA and ECDSA, attached and detached
content, DER and BER encodings.
"""

from __future__ import annotations

import datetime

from cades_fixtures import (
    build_cms,
    build_pades_pdf,
    build_signer,
    pades_covered_bytes,
    to_ber_indefinite,
)
from paperless_esig import cms as esig_cms
from paperless_esig import pades as esig_pades


class TestIsCades:
    def test_accepts_der_signed_data(self) -> None:
        key, cert, _ = build_signer()
        blob = build_cms(b"content", key=key, certificate=cert)
        assert esig_cms.is_cades(blob) is True

    def test_accepts_ber_signed_data(self) -> None:
        key, cert, _ = build_signer()
        blob = to_ber_indefinite(build_cms(b"content", key=key, certificate=cert))
        assert esig_cms.is_cades(blob) is True

    def test_rejects_garbage(self) -> None:
        assert esig_cms.is_cades(b"") is False
        assert esig_cms.is_cades(b"not a signature at all") is False
        assert esig_cms.is_cades(bytes(range(256))) is False


class TestParseCms:
    def test_attached_content_is_returned(self) -> None:
        key, cert, _ = build_signer()
        content = b"signed pdf bytes"
        document = esig_cms.parse_cms(build_cms(content, key=key, certificate=cert))
        assert document is not None
        assert document.content == content
        assert len(document.certificates) == 1
        assert len(document.signers) == 1

    def test_detached_content_is_none(self) -> None:
        key, cert, _ = build_signer()
        document = esig_cms.parse_cms(
            build_cms(b"content", key=key, certificate=cert, attached=False),
        )
        assert document.content is None

    def test_signer_fields_are_populated(self) -> None:
        key, cert, _ = build_signer(common_name="Test Signer")
        signing_time = datetime.datetime(2026, 2, 3, 4, 5, 6, tzinfo=datetime.UTC)
        document = esig_cms.parse_cms(
            build_cms(
                b"content",
                key=key,
                certificate=cert,
                signing_time=signing_time,
            ),
        )
        signer = document.signers[0]
        assert signer.signing_time == signing_time
        assert signer.digest_algorithm == "sha256"
        assert signer.signature_algorithm == "rsassa_pkcs1v15"
        assert signer.signature_hash == "sha256"
        assert signer.message_digest is not None
        assert signer.certificate is not None
        assert not signer.timestamp_present
        assert not signer.ocsp_present

    def test_ecdsa_signature(self) -> None:
        key, cert, _ = build_signer(curve="ecdsa")
        document = esig_cms.parse_cms(
            build_cms(b"content", key=key, certificate=cert, curve="ecdsa"),
        )
        signer = document.signers[0]
        assert signer.signature_algorithm == "ecdsa"
        assert signer.signature_hash == "sha256"

    def test_missing_signing_time(self) -> None:
        key, cert, _ = build_signer()
        document = esig_cms.parse_cms(
            build_cms(
                b"content",
                key=key,
                certificate=cert,
                with_signing_time=False,
            ),
        )
        assert document.signers[0].signing_time is None

    def test_no_signed_attributes(self) -> None:
        # A signer without signed attributes signs the raw content.
        key, cert, _ = build_signer()
        content = b"the signed content"
        document = esig_cms.parse_cms(
            build_cms(
                content,
                key=key,
                certificate=cert,
                with_signed_attributes=False,
            ),
        )
        signer = document.signers[0]
        assert signer.signed_attributes_der is None
        assert signer.message_digest is None
        assert signer.signing_time is None
        assert esig_cms.verify_signature(signer, content) is True
        assert esig_cms.verify_message_digest(signer, content) is None

    def test_unsigned_timestamp_and_ocsp_flags(self) -> None:
        key, cert, _ = build_signer()
        document = esig_cms.parse_cms(
            build_cms(
                b"content",
                key=key,
                certificate=cert,
                with_timestamp=True,
                with_ocsp=True,
            ),
        )
        signer = document.signers[0]
        assert signer.timestamp_present is True
        assert signer.ocsp_present is True

    def test_unsigned_attributes_absent_by_default(self) -> None:
        key, cert, _ = build_signer()
        signer = esig_cms.parse_cms(
            build_cms(b"content", key=key, certificate=cert),
        ).signers[0]
        assert signer.timestamp_present is False
        assert signer.ocsp_present is False

    def test_ber_encoding_parses(self) -> None:
        key, cert, _ = build_signer()
        blob = to_ber_indefinite(build_cms(b"content", key=key, certificate=cert))
        assert esig_cms.parse_cms(blob) is not None

    def test_padded_contents_parse(self) -> None:
        # PAdES signers pad /Contents with zeros; the padding must not
        # break parsing.
        key, cert, _ = build_signer()
        blob = build_cms(b"content", key=key, certificate=cert)
        assert esig_cms.parse_cms(blob + b"\x00" * 512) is not None

    def test_garbage_returns_none(self) -> None:
        assert esig_cms.parse_cms(b"garbage") is None


class TestVerification:
    def test_message_digest_matches(self) -> None:
        key, cert, _ = build_signer()
        content = b"the signed content"
        signer = esig_cms.parse_cms(
            build_cms(content, key=key, certificate=cert),
        ).signers[0]
        assert esig_cms.verify_message_digest(signer, content) is True

    def test_message_digest_mismatch(self) -> None:
        key, cert, _ = build_signer()
        signer = esig_cms.parse_cms(
            build_cms(b"original", key=key, certificate=cert),
        ).signers[0]
        assert esig_cms.verify_message_digest(signer, b"tampered") is False

    def test_signature_value_valid(self) -> None:
        key, cert, _ = build_signer()
        content = b"the signed content"
        signer = esig_cms.parse_cms(
            build_cms(content, key=key, certificate=cert),
        ).signers[0]
        assert esig_cms.verify_signature(signer, content) is True

    def test_signature_value_invalid(self) -> None:
        # The sid points at a certificate that does not hold the key the
        # signature was produced with.
        key, _, _ = build_signer(common_name="Test Signer")
        _, other_cert, _ = build_signer(common_name="Wrong Key", serial=999)
        content = b"the signed content"
        forged = build_cms(
            content,
            key=key,
            certificate=other_cert,
        )
        signer = esig_cms.parse_cms(forged).signers[0]
        assert signer.certificate is not None
        assert esig_cms.verify_signature(signer, content) is False

    def test_ecdsa_signature_value_valid(self) -> None:
        key, cert, _ = build_signer(curve="ecdsa")
        content = b"the signed content"
        signer = esig_cms.parse_cms(
            build_cms(content, key=key, certificate=cert, curve="ecdsa"),
        ).signers[0]
        assert esig_cms.verify_signature(signer, content) is True

    def test_pss_signature_value_valid(self) -> None:
        key, cert, _ = build_signer()
        content = b"the signed content"
        signer = esig_cms.parse_cms(
            build_cms(content, key=key, certificate=cert, pss=True),
        ).signers[0]
        assert signer.signature_algorithm == "rsassa_pss"
        assert signer.signature_hash == "sha256"
        assert esig_cms.verify_signature(signer, content) is True

    def test_ber_signature_value_valid(self) -> None:
        key, cert, _ = build_signer()
        content = b"the signed content"
        blob = to_ber_indefinite(build_cms(content, key=key, certificate=cert))
        signer = esig_cms.parse_cms(blob).signers[0]
        assert esig_cms.verify_signature(signer, content) is True


class TestSignerCertificateResolution:
    def test_lone_certificate_is_the_signer(self) -> None:
        key, cert, _ = build_signer()
        document = esig_cms.parse_cms(build_cms(b"x", key=key, certificate=cert))
        assert document.signers[0].certificate.serial_number == cert.serial_number

    def test_sid_issuer_and_serial_resolution(self) -> None:
        key, cert, _ = build_signer(common_name="Test Signer", serial=42)
        _, other, _ = build_signer(common_name="Other Cert", serial=43)
        document = esig_cms.parse_cms(
            build_cms(
                b"x",
                key=key,
                certificate=cert,
                include_certificates=[cert, other],
            ),
        )
        assert document.signers[0].certificate.serial_number == 42

    def test_ski_sid_resolution(self) -> None:
        key, cert, _ = build_signer(common_name="Ski Signer", serial=7, add_ski=True)
        _, filler, _ = build_signer(
            common_name="Filler",
            serial=8,
            add_ski=True,
        )
        document = esig_cms.parse_cms(
            build_cms(
                b"x",
                key=key,
                certificate=cert,
                include_certificates=[cert, filler],
                sid_ski=True,
            ),
        )
        assert document.signers[0].certificate.serial_number == 7

    def test_signing_certificate_v2_resolution(self) -> None:
        # The sid does not match the embedded signer certificate (the
        # serial numbers diverge, as with some real-world producers);
        # the signingCertificateV2 digest must resolve it from the
        # embedded set.
        key, cert, _ = build_signer(common_name="Hidden Signer", serial=7)
        _, filler_one, _ = build_signer(common_name="Filler One", serial=8)
        _, filler_two, _ = build_signer(common_name="Filler Two", serial=9)
        document = esig_cms.parse_cms(
            build_cms(
                b"x",
                key=key,
                certificate=cert,
                include_certificates=[cert, filler_one, filler_two],
                signer_serial=999,
                with_signing_certificate=True,
            ),
        )
        assert document.signers[0].certificate.serial_number == 7
        assert esig_cms.signer_certificate_name(document.signers[0]) is not None

    def test_unresolvable_signer_certificate(self) -> None:
        key, cert, _ = build_signer(serial=7)
        _, filler_one, _ = build_signer(common_name="Filler One", serial=8)
        _, filler_two, _ = build_signer(common_name="Filler Two", serial=9)
        document = esig_cms.parse_cms(
            build_cms(
                b"x",
                key=key,
                certificate=cert,
                include_certificates=[filler_one, filler_two],
                with_signing_certificate=False,
            ),
        )
        assert document.signers[0].certificate is None


class TestSignerCertificateName:
    def test_organization_preferred_over_cn(self) -> None:
        key, cert, _ = build_signer(
            common_name="111111-11111",
            organization="Test Organization",
        )
        signer = esig_cms.parse_cms(
            build_cms(b"x", key=key, certificate=cert),
        ).signers[0]
        assert esig_cms.signer_certificate_name(signer) == "Test Organization"

    def test_cn_fallback(self) -> None:
        key, cert, _ = build_signer(common_name="Jānis Bērziņš", organization=None)
        signer = esig_cms.parse_cms(
            build_cms(b"x", key=key, certificate=cert),
        ).signers[0]
        assert esig_cms.signer_certificate_name(signer) == "Jānis Bērziņš"

    def test_personal_code_cn_falls_back_to_given_surname(self) -> None:
        # Some national certificates embed a personal code in the CN.
        key, cert, _ = build_signer(
            common_name="CODE1234X",
            organization=None,
            given_name="Sample",
            surname="Person",
        )
        signer = esig_cms.parse_cms(
            build_cms(b"x", key=key, certificate=cert),
        ).signers[0]
        assert esig_cms.signer_certificate_name(signer) == "Sample Person"

    def test_placeholder_cn_returns_none(self) -> None:
        key, cert, _ = build_signer(common_name="Private", organization=None)
        signer = esig_cms.parse_cms(
            build_cms(b"x", key=key, certificate=cert),
        ).signers[0]
        assert esig_cms.signer_certificate_name(signer) is None


class TestPadesExtraction:
    def _signed_pdf(self, subfilter: str = "ETSI.CAdES.detached") -> bytes:
        stream = b"BT /F1 24 Tf 72 720 Td (Hello PAdES) Tj ET"
        key, cert, _ = build_signer()
        template = build_pades_pdf(stream, b"\x00" * 4096, subfilter=subfilter)
        covered = pades_covered_bytes(template)
        cms_bytes = build_cms(
            covered,
            key=key,
            certificate=cert,
            attached=False,
        )
        return build_pades_pdf(stream, cms_bytes, subfilter=subfilter)

    def test_is_pades_pdf(self) -> None:
        assert esig_pades.is_pades_pdf(self._signed_pdf()) is True
        assert esig_pades.is_pades_pdf(b"%PDF-1.4\nnot signed") is False
        assert esig_pades.is_pades_pdf(b"not a pdf") is False

    def test_signature_fields(self) -> None:
        pdf = self._signed_pdf()
        signatures = esig_pades.find_pdf_signatures(pdf)
        assert len(signatures) == 1
        signature = signatures[0]
        assert len(signature.byte_range) == 4
        assert signature.subfilter == "ETSI.CAdES.detached"
        assert signature.m == "D:20260115103000Z"
        assert signature.reason == "Test Signer"

    def test_adbe_subfilter(self) -> None:
        pdf = self._signed_pdf(subfilter="adbe.pkcs7.detached")
        assert (
            esig_pades.find_pdf_signatures(pdf)[0].subfilter
            == "adbe.pkcs7.detached"
        )

    def test_covered_bytes_and_verification(self) -> None:
        pdf = self._signed_pdf()
        signature = esig_pades.find_pdf_signatures(pdf)[0]
        covered = esig_pades.covered_bytes(pdf, signature.byte_range)
        document = esig_cms.parse_cms(signature.contents)
        assert esig_cms.verify_message_digest(document.signers[0], covered) is True
        assert esig_cms.verify_signature(document.signers[0], covered) is True

    def test_tampered_pdf_fails_digest(self) -> None:
        pdf = self._signed_pdf()
        signature = esig_pades.find_pdf_signatures(pdf)[0]
        # Flip a byte inside the covered region (outside the signature).
        tampered = bytearray(pdf)
        position = 20
        assert position < signature.byte_range[1]
        tampered[position] ^= 0xFF
        covered = esig_pades.covered_bytes(bytes(tampered), signature.byte_range)
        document = esig_cms.parse_cms(signature.contents)
        assert esig_cms.verify_message_digest(document.signers[0], covered) is False

    def test_signature_reported_once(self) -> None:
        # The signature appears both on the page and in the AcroForm;
        # it must be deduplicated.
        pdf = self._signed_pdf()
        assert len(esig_pades.find_pdf_signatures(pdf)) == 1

    def test_byte_scan_fallback_when_pikepdf_fails(
        self,
        mocker,
    ) -> None:
        pdf = self._signed_pdf()
        mocker.patch(
            "pikepdf.open",
            side_effect=RuntimeError("pdf broken"),
        )
        signatures = esig_pades.find_pdf_signatures(pdf)
        assert len(signatures) == 1
        signature = signatures[0]
        assert len(signature.byte_range) == 4
        assert signature.subfilter == "ETSI.CAdES.detached"
        covered = esig_pades.covered_bytes(pdf, signature.byte_range)
        document = esig_cms.parse_cms(signature.contents)
        assert esig_cms.verify_message_digest(document.signers[0], covered) is True
        assert esig_cms.verify_signature(document.signers[0], covered) is True
        assert esig_pades.is_pades_pdf(pdf) is True
