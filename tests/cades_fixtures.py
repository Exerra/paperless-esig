"""
Helpers for building synthetic CAdES signatures and PAdES PDFs in tests.

The real-world samples (Italian CIE and Uruguayan TuID PDFs) contain
personal data, so the test suite constructs its own files from scratch:
a minimal PDF payload, self-signed signer certificates and genuine CMS
SignedData signatures (attached for ``.p7m``, detached for PAdES), in
both DER and BER (indefinite-length) encodings.

Two signature profiles are supported, mirroring the real-world producers:

* RSA + SHA-256 (``sha256_rsa``) with the ``ETSI.CAdES.detached``
  subfilter — the Italian CIE / PAdES convention, and
* ECDSA P-256 with the ``adbe.pkcs7.detached`` subfilter — the
  classic Adobe convention (BER-encoded in the Uruguayan samples).

The cryptographic structure mirrors what real CAdES/PAdES files look
like — the parsing code is verified against the real-world samples
(Italian CIE, Uruguayan TuID and Brazilian ICP-Brasil files) during
development.
"""

from __future__ import annotations

import datetime
import hashlib
import re
from typing import ClassVar

from asn1crypto import algos, cms, core
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

_DEFAULT_SIGNING_TIME: datetime.datetime = datetime.datetime(
    2026,
    1,
    15,
    10,
    30,
    0,
    tzinfo=datetime.UTC,
)

#: OIDs of the CAdES signed attributes.
_CONTENT_TYPE_OID: str = "1.2.840.113549.1.9.3"
_MESSAGE_DIGEST_OID: str = "1.2.840.113549.1.9.4"
_SIGNING_TIME_OID: str = "1.2.840.113549.1.9.5"
_SIGNING_CERTIFICATE_V2_OID: str = "1.2.840.113549.1.9.16.2.47"


class _EssCertIdV2(core.Sequence):
    """ESSCertIDv2 (RFC 5035)."""

    _fields: ClassVar[list[tuple[str, object, dict]]] = [
        ("hash_algorithm", algos.DigestAlgorithm, {"optional": True}),
        ("cert_hash", core.OctetString),
    ]


class _SigningCertificateV2(core.Sequence):
    """SigningCertificateV2 (RFC 5035)."""

    _fields: ClassVar[list[tuple[str, object, dict]]] = [
        ("certs", core.SequenceOf, {"spec": _EssCertIdV2}),
    ]


def build_signer(
    *,
    common_name: str = "Test Signer",
    organization: str | None = "Test Organization",
    country: str = "XX",
    given_name: str | None = None,
    surname: str | None = None,
    serial: int = 12345,
    curve: str = "rsa",
    add_ski: bool = False,
) -> tuple[object, x509.Certificate, bytes]:
    """Create a signer key, certificate and DER for tests.

    Parameters
    ----------
    add_ski:
        Whether the certificate carries a subject key identifier
        extension (needed for ``sid_ski`` signer identifiers).

    Returns
    -------
    tuple[object, cryptography.x509.Certificate, bytes]
        The private key, the certificate and its DER encoding.
    """
    if curve == "ecdsa":
        key = ec.generate_private_key(ec.SECP256R1())
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    attributes = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    if organization:
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
    if country:
        attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
    if given_name:
        attributes.append(x509.NameAttribute(NameOID.GIVEN_NAME, given_name))
    if surname:
        attributes.append(x509.NameAttribute(NameOID.SURNAME, surname))
    name = x509.Name(attributes)

    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2028, 1, 1, tzinfo=datetime.UTC))
    )
    if add_ski:
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
    certificate = builder.sign(key, hashes.SHA256())
    return key, certificate, certificate.public_bytes(serialization.Encoding.DER)


def _signed_attributes_der(signer_info: cms.SignerInfo) -> bytes:
    """Return the signed-attributes encoding a signer must sign.

    CMS computes the signature over the DER encoding of the signed
    attributes with the implicit ``[0]`` tag replaced by the SET OF tag
    (RFC 5652, Section 5.5).
    """
    return b"\x31" + signer_info["signed_attrs"].dump()[1:]


def _sign_with(
    key,
    data: bytes,
    curve: str,
    *,
    pss: bool = False,
) -> bytes:
    """Sign *data* with *key*, matching the fixture's algorithm profile."""
    if curve == "ecdsa":
        return key.sign(data, ec.ECDSA(hashes.SHA256()))
    if pss:
        return key.sign(
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
    return key.sign(data, padding.PKCS1v15(), hashes.SHA256())


def _subject_common_name(certificate: x509.Certificate) -> str:
    """Return the certificate's common name for the signer identifier."""
    attributes = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    value = attributes[0].value if attributes else "Test Signer"
    return value.decode("utf-8") if isinstance(value, bytes) else value


def build_cms(
    content: bytes,
    *,
    key,
    certificate: x509.Certificate,
    include_certificates: list[x509.Certificate] | None = None,
    attached: bool = True,
    with_signing_time: bool = True,
    with_signing_certificate: bool = True,
    with_signed_attributes: bool = True,
    with_timestamp: bool = False,
    with_ocsp: bool = False,
    signing_time: datetime.datetime = _DEFAULT_SIGNING_TIME,
    curve: str = "rsa",
    pss: bool = False,
    sid_ski: bool = False,
    signer_serial: int | None = None,
) -> bytes:
    """Build a DER-encoded CMS SignedData (CAdES) signature.

    Parameters
    ----------
    content:
        The signed content (PDF bytes for ``.p7m``, covered bytes for
        PAdES).
    key:
        The signer's private key.
    certificate:
        The signer certificate.
    include_certificates:
        Certificates embedded in the structure.  Defaults to the signer
        certificate alone.  Pass ``[]`` to omit the signer certificate
        (exercising the signingCertificateV2 resolution path).
    attached:
        Whether the content is attached in the ``encapContentInfo``
        (True for ``.p7m``, False for PAdES).
    with_signing_time:
        Whether the ``signingTime`` attribute is included.
    with_signing_certificate:
        Whether the ``signingCertificateV2`` attribute is included.
    with_signed_attributes:
        Whether the signer carries signed attributes at all (False
        produces a plain signature over the raw content).
    with_timestamp:
        Whether an unsigned RFC 3161 timestamp token attribute is
        included (the token itself is a placeholder).
    with_ocsp:
        Whether an unsigned OCSP response attribute is included (the
        response itself is a placeholder).
    signing_time:
        The value of the ``signingTime`` attribute.
    curve:
        ``"rsa"`` or ``"ecdsa"`` — selects the signature algorithm.
    pss:
        Whether to use RSASSA-PSS (with SHA-256/MGF1/salt-32) instead
        of PKCS#1 v1.5.  Only meaningful for RSA keys.
    sid_ski:
        Whether the signer identifier is a subject key identifier
        (requires the certificate to carry a SKI extension) instead of
        the issuer-and-serial-number form.
    signer_serial:
        Overrides the serial number in the signer identifier.
    """
    digest = hashlib.sha256(content).digest()

    attributes = cms.CMSAttributes()

    if with_signed_attributes:
        content_type = cms.CMSAttribute()
        content_type["type"] = _CONTENT_TYPE_OID
        content_type["values"] = [cms.ContentType("data")]
        attributes.append(content_type)

        if with_signing_time:
            signing_time_attr = cms.CMSAttribute()
            signing_time_attr["type"] = _SIGNING_TIME_OID
            signing_time_attr["values"] = [core.UTCTime(signing_time)]
            attributes.append(signing_time_attr)

        message_digest = cms.CMSAttribute()
        message_digest["type"] = _MESSAGE_DIGEST_OID
        message_digest["values"] = [core.OctetString(digest)]
        attributes.append(message_digest)

        if with_signing_certificate:
            ess = _SigningCertificateV2()
            cert_id = _EssCertIdV2()
            cert_id["cert_hash"] = hashlib.sha256(
                certificate.public_bytes(serialization.Encoding.DER),
            ).digest()
            ess["certs"] = [cert_id]
            ess_attr = cms.CMSAttribute()
            ess_attr["type"] = _SIGNING_CERTIFICATE_V2_OID
            ess_attr["values"] = [ess]
            attributes.append(ess_attr)

    signer_info = cms.SignerInfo()
    signer_info["version"] = "v1"
    if sid_ski:
        from cryptography.x509 import ExtensionOID

        ski = certificate.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER,
        )
        signer_identifier = cms.SignerIdentifier(
            name="subject_key_identifier",
            value=ski.value.digest,
        )
    else:
        signer_identifier = cms.SignerIdentifier(
            name="issuer_and_serial_number",
            value={
                "issuer": asn1_x509.Name.build(
                    {
                        "common_name": _subject_common_name(certificate),
                    },
                ),
                "serial_number": signer_serial
                if signer_serial is not None
                else certificate.serial_number,
            },
        )
    signer_info["sid"] = signer_identifier
    signer_info["digest_algorithm"] = {"algorithm": "sha256"}
    if with_signed_attributes:
        signer_info["signed_attrs"] = attributes
    if with_timestamp or with_ocsp:
        unsigned = cms.CMSAttributes()
        if with_timestamp:
            # The signatureTimeStampToken attribute value is a
            # ContentInfo (an RFC 3161 TimeStampToken).
            token = cms.ContentInfo()
            token["content_type"] = "data"
            token["content"] = core.OctetString(b"placeholder token")
            timestamp_attr = cms.CMSAttribute()
            timestamp_attr["type"] = "1.2.840.113549.1.9.16.2.14"
            timestamp_attr["values"] = [token]
            unsigned.append(timestamp_attr)
        if with_ocsp:
            ocsp_attr = cms.CMSAttribute()
            ocsp_attr["type"] = "1.2.840.113549.1.9.16.2.24"
            ocsp_attr["values"] = [core.OctetString(b"placeholder ocsp")]
            unsigned.append(ocsp_attr)
        signer_info["unsigned_attrs"] = unsigned
    if curve == "ecdsa":
        signer_info["signature_algorithm"] = {"algorithm": "sha256_ecdsa"}
    elif pss:
        signer_info["signature_algorithm"] = {
            "algorithm": "rsassa_pss",
            "parameters": {
                "hash_algorithm": {"algorithm": "sha256"},
                "mask_gen_algorithm": {
                    "algorithm": "mgf1",
                    "parameters": {"algorithm": "sha256"},
                },
                "salt_length": 32,
            },
        }
    else:
        signer_info["signature_algorithm"] = {"algorithm": "sha256_rsa"}
    if with_signed_attributes:
        signature_data = _signed_attributes_der(signer_info)
    else:
        signature_data = content
    signature = _sign_with(key, signature_data, curve, pss=pss)
    signer_info["signature"] = signature

    signed_data = cms.SignedData()
    signed_data["version"] = "v1"
    signed_data["digest_algorithms"] = [{"algorithm": "sha256"}]
    if attached:
        signed_data["encap_content_info"] = {
            "content_type": "data",
            "content": content,
        }
    else:
        signed_data["encap_content_info"] = {"content_type": "data"}
    if include_certificates is None:
        include_certificates = [certificate]
    if include_certificates:
        signed_data["certificates"] = [
            asn1_x509.Certificate.load(
                cert.public_bytes(serialization.Encoding.DER),
            )
            for cert in include_certificates
        ]
    signed_data["signer_infos"] = [signer_info]

    content_info = cms.ContentInfo()
    content_info["content_type"] = "signed_data"
    content_info["content"] = signed_data
    return content_info.dump()


def to_ber_indefinite(der: bytes) -> bytes:
    """Re-encode the top-level SEQUENCE of *der* with BER indefinite length.

    Mirrors the BER (indefinite-length) encodings some signers emit
    (e.g. the ``adbe.pkcs7.detached`` samples); the inner DER structure
    is kept intact.
    """
    if not der or der[0] != 0x30:
        raise ValueError("not a DER SEQUENCE")
    first = der[1]
    header = 2 + (first & 0x7F) if first & 0x80 else 2
    return b"\x30\x80" + der[header:] + b"\x00\x00"


def build_pades_pdf(
    content_stream: bytes,
    cms_bytes: bytes,
    *,
    subfilter: str = "ETSI.CAdES.detached",
    m: str | None = "D:20260115103000Z",
    reason: str = "Test Signer",
    name: str | None = None,
    contents_size: int = 4096,
) -> bytes:
    """Build a PAdES-signed PDF from a content stream and a detached CMS.

    *content_stream* is the raw page-content stream (e.g.
    ``b"BT /F1 24 Tf 72 720 Td (Hello) Tj ET"``).  The CMS (which must
    be built over the PDF's covered bytes, see ``pades_covered_bytes``)
    is embedded as the ``/Contents`` of the signature dictionary,
    padded with zeros to ``contents_size`` bytes.  The byte range
    covers everything except the ``/Contents`` value, mirroring real
    PAdES files.  The signature dictionary carries the given ``/M``,
    ``/Reason`` and ``/Name`` values (``/M`` is omitted when None).
    """
    if len(cms_bytes) > contents_size:
        raise ValueError("CMS too large for the configured contents size")
    padded = cms_bytes.ljust(contents_size, b"\x00")
    contents_hex = padded.hex()

    sig_extra = ""
    if m:
        sig_extra += f"   /M ({m})\n"
    if name:
        sig_extra += f"   /Name ({name})\n"

    template = (
        "1 0 obj\n"
        "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [5 0 R] /SigFlags 3 >> >>\n"
        "endobj\n"
        "2 0 obj\n"
        "<< /Type /Pages /Kids [4 0 R] /Count 1 >>\n"
        "endobj\n"
        "3 0 obj\n"
        f"<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /{subfilter}\n"
        "   /ByteRange [0 0000000000 0000000000 0000000000]\n"
        f"   /Contents <{contents_hex}>\n"
        f"{sig_extra}"
        f"   /Reason ({reason}) >>\n"
        "endobj\n"
        "4 0 obj\n"
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 6 0 R\n"
        "   /Resources << /Font << /F1 7 0 R >> >> /Annots [5 0 R] >>\n"
        "endobj\n"
        "5 0 obj\n"
        "<< /Type /Annot /Subtype /Widget /FT /Sig /T (Signature1) /V 3 0 R /F 132 >>\n"
        "endobj\n"
    )
    stream = content_stream.decode("latin-1", errors="replace")
    stream_object = (
        "6 0 obj\n"
        f"<< /Length {len(stream)} >>\n"
        "stream\n"
        f"{stream}\n"
        "endstream\n"
        "endobj\n"
        "7 0 obj\n"
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\n"
        "endobj\n"
    )

    # Assemble the body and record every object's offset for the xref.
    header = b"%PDF-1.4\n"
    template_bytes = template.encode("latin-1")
    stream_bytes = stream_object.encode("latin-1")
    parts: list[bytes] = [header, template_bytes, stream_bytes]

    object_re = re.compile(rb"(?:^|\n)(\d+) 0 obj\n")
    offsets: list[int] = []
    cursor = len(header)
    for part in parts[1:]:
        for match in object_re.finditer(part):
            if match.group(1) != b"0":
                offsets.append(cursor + match.start(1))
        cursor += len(part)
    data = b"".join(parts)

    trailer = (
        "xref\n0 8\n"
        "0000000000 65535 f \n"
        + "".join(f"{offset:010d} 00000 n \n" for offset in offsets)
        + f"trailer << /Size 8 /Root 1 0 R >>\nstartxref\n{cursor}\n%%EOF\n"
    ).encode("latin-1")

    contents_start = data.find(b"/Contents <")
    if contents_start == -1:
        raise ValueError("template did not include the Contents placeholder")
    hex_start = contents_start + len(b"/Contents <")
    hex_end = data.find(b">", hex_start)

    full = data + trailer
    first_length = contents_start
    second_start = hex_end + 1
    second_length = len(full) - second_start

    numbers = b"[0 %010d %010d %010d]" % (
        first_length,
        second_start,
        second_length,
    )
    placeholder = b"[0 0000000000 0000000000 0000000000]"
    marker = full.find(placeholder)
    if marker == -1:
        raise ValueError("ByteRange placeholder not found")
    return full[:marker] + numbers + full[marker + len(placeholder):]


def pades_covered_bytes(pdf_data: bytes) -> bytes:
    """Return the covered bytes of a PAdES PDF built by build_pades_pdf."""
    contents_start = pdf_data.find(b"/Contents <")
    if contents_start == -1:
        raise ValueError("no Contents found")
    hex_start = contents_start + len(b"/Contents <")
    hex_end = pdf_data.find(b">", hex_start)
    return pdf_data[:contents_start] + pdf_data[hex_end + 1:]
