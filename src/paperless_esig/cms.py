"""
CMS (CAdES) signature parsing and offline verification.

CAdES signatures are CMS ``SignedData`` structures (RFC 5652 / ETSI
EN 319 122): a DER- or BER-encoded ``ContentInfo`` whose content type
is ``signed_data``.  They appear in the wild as

* standalone ``.p7m`` files with the signed document (usually a PDF)
  attached inside the ``encapContentInfo``,
* the ``/Contents`` of PAdES PDF signature dictionaries, where the
  signature is *detached* and the covered bytes (``ByteRange``) take
  the role of the content.

This module parses the structure with :mod:`asn1crypto` — which, unlike
strict DER parsers, accepts the BER indefinite-length encodings produced
by some signers (e.g. ``adbe.pkcs7.detached`` signatures from older
Adobe-based signers) — and performs offline cryptographic verification
with :mod:`cryptography` primitives, mirroring the approach used for
XAdES in :mod:`paperless_esig.parser`.

Verification (all offline):

* the ``messageDigest`` signed attribute is compared against the digest
  of the signed content (attached content, or the PAdES covered bytes),
* the signature value is verified over the DER encoding of the signed
  attributes (or the content when no attributes are present) using the
  signer certificate's public key,
* the signer certificate is resolved from the ``sid`` (issuer and
  serial number, or subject key identifier) and, when the chain is not
  embedded, from the ``signingCertificateV2`` digest or a lone
  certificate.

Trust-chain and revocation validation are intentionally out of scope —
matching the XAdES parser, this reports *cryptographic* validity only.
"""

from __future__ import annotations

import datetime
import hashlib
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, ClassVar

from asn1crypto import algos, cms, core
from asn1crypto import x509 as asn1_x509

if TYPE_CHECKING:
    from cryptography.x509 import Certificate

logger = logging.getLogger("paperless_esig.cms")

#: CMS attribute OIDs used for signer metadata and verification.
_MESSAGE_DIGEST_OID: str = "1.2.840.113549.1.9.4"
_SIGNING_TIME_OID: str = "1.2.840.113549.1.9.5"
_SIGNING_CERTIFICATE_V1_OID: str = "1.2.840.113549.1.9.16.2.12"
_SIGNING_CERTIFICATE_V2_OID: str = "1.2.840.113549.1.9.16.2.47"
_SIGNATURE_TIMESTAMP_OID: str = "1.2.840.113549.1.9.16.2.14"
_REVOCATION_INFO_CHOICES_OID: str = "1.2.840.113549.1.9.16.2.24"

#: Map of asn1crypto hash algorithm names to hashlib names.
_HASH_ALGORITHMS: dict[str, str] = {
    "sha1": "sha1",
    "sha224": "sha224",
    "sha256": "sha256",
    "sha384": "sha384",
    "sha512": "sha512",
}

#: Signature algorithms understood by the verifier (asn1crypto names).
_SUPPORTED_SIGNATURE_ALGORITHMS: frozenset[str] = frozenset(
    {
        "rsassa_pkcs1v15",
        "rsassa_pss",
        "ecdsa",
        "dsa",
    },
)


def is_cades(data: bytes) -> bool:
    """Return True if *data* is a CMS SignedData (CAdES) structure.

    Handles both DER and BER (indefinite-length) encodings.
    """
    try:
        content_info = cms.ContentInfo.load(data)
    except Exception:
        return False
    return content_info["content_type"].native == "signed_data"


@dataclass(frozen=True)
class CmsSignerInfo:
    """A single ``SignerInfo`` of a CMS SignedData structure.

    Attributes
    ----------
    certificate:
        The signer certificate resolved from the ``sid``, the
        ``signingCertificateV2`` digest or a lone embedded certificate.
        None when it could not be determined.
    signing_time:
        The ``signingTime`` signed attribute, or None.
    digest_algorithm:
        hashlib name ("sha256", ...) of the message digest algorithm.
    signature_algorithm:
        Short name of the signature algorithm ("rsassa-pkcs1v15", ...).
    signature_hash:
        hashlib name of the digest used inside the signature algorithm.
    signature_value:
        Raw signature value bytes.
    message_digest:
        Value of the ``messageDigest`` signed attribute, or None.
    signed_attributes_der:
        DER encoding of the signed attributes (the signature input), or
        None when the signer carries no signed attributes.
    timestamp_present:
        Whether an unsigned RFC 3161 timestamp token is present.
    ocsp_present:
        Whether an unsigned OCSP response is present.
    """

    certificate: Certificate | None = None
    signing_time: datetime.datetime | None = None
    digest_algorithm: str | None = None
    signature_algorithm: str | None = None
    signature_hash: str | None = None
    signature_value: bytes = b""
    message_digest: bytes | None = None
    signed_attributes_der: bytes | None = None
    timestamp_present: bool = False
    ocsp_present: bool = False


@dataclass(frozen=True)
class CmsDocument:
    """A parsed CMS SignedData structure.

    Attributes
    ----------
    content:
        The attached content (``eContent`` of the ``encapContentInfo``),
        or None for detached signatures (PAdES).
    certificates:
        The X.509 certificates embedded in the structure, in order.
    signers:
        The parsed signer infos, in order.
    """

    content: bytes | None = None
    certificates: list[Certificate] = field(default_factory=list)
    signers: list[CmsSignerInfo] = field(default_factory=list)


class _EssCertIdV2(core.Sequence):
    """ESSCertIDv2 (RFC 5035): optional hash algorithm, cert hash."""

    _fields: ClassVar[list[tuple[str, object, dict]]] = [
        ("hash_algorithm", algos.DigestAlgorithm, {"optional": True}),
        ("cert_hash", core.OctetString),
        ("issuer_serial", core.Sequence, {"optional": True}),
    ]


class _SigningCertificateV2(core.Sequence):
    """SigningCertificateV2 (RFC 5035)."""

    _fields: ClassVar[list[tuple[str, object, dict]]] = [
        ("certs", core.SequenceOf, {"spec": _EssCertIdV2}),
    ]


class _EssCertId(core.Sequence):
    """ESSCertID (RFC 2634): cert hash is always SHA-1."""

    _fields: ClassVar[list[tuple[str, object, dict]]] = [
        ("cert_hash", core.OctetString),
        ("issuer_serial", core.Sequence, {"optional": True}),
    ]


class _SigningCertificate(core.Sequence):
    """SigningCertificate (RFC 2634)."""

    _fields: ClassVar[list[tuple[str, object, dict]]] = [
        ("certs", core.SequenceOf, {"spec": _EssCertId}),
    ]


def _load_certificates(
    raw_certificates: list[asn1_x509.Certificate] | None,
) -> list[Certificate]:
    """Convert asn1crypto certificates to cryptography certificates."""
    from cryptography import x509

    certificates: list[Certificate] = []
    for raw in raw_certificates or []:
        try:
            certificates.append(x509.load_der_x509_certificate(raw.dump()))
        except Exception:
            logger.warning("Could not parse an embedded CMS certificate", exc_info=True)
    return certificates


def _parse_signed_attributes(signer_info: cms.SignerInfo) -> dict[str, object]:
    """Return the signed attributes of *signer_info* keyed by OID."""
    attributes: dict[str, object] = {}
    signed_attrs = signer_info["signed_attrs"]
    if signed_attrs.native is None:
        return attributes
    for attribute in signed_attrs:
        oid = attribute["type"].dotted
        values = attribute["values"]
        if not values:
            continue
        attributes[oid] = values[0]
    return attributes


def _parse_unsigned_attribute_oids(signer_info: cms.SignerInfo) -> set[str]:
    """Return the OIDs of the unsigned attributes of *signer_info*."""
    present: set[str] = set()
    unsigned_attrs = signer_info["unsigned_attrs"]
    if unsigned_attrs.native is None:
        return present
    for attribute in unsigned_attrs:
        present.add(attribute["type"].dotted)
    return present


def _resolve_signer_certificate(
    signer_info: cms.SignerInfo,
    certificates: list[Certificate],
) -> Certificate | None:
    """Resolve the signer certificate of *signer_info*.

    Tries, in order: the ``sid`` (issuer and serial number, or subject
    key identifier), the ``signingCertificateV2``/``signingCertificate``
    digest, and — as a last resort — a lone embedded certificate.
    """
    if not certificates:
        return None
    if len(certificates) == 1:
        # Some signers (e.g. the Uruguayan TuID samples) embed only the
        # signer certificate; the sid then always refers to it.
        return certificates[0]

    from cryptography.x509 import NameOID

    sid = signer_info["sid"]
    sid_native = sid.native
    if sid_native is not None and "issuer" in sid_native:
        serial = sid_native["serial_number"]
        issuer_values = {
            str(oid): str(value)
            for oid, value in sid_native["issuer"].items()
        }
        for certificate in certificates:
            if certificate.serial_number != serial:
                continue
            certificate_issuer: dict[str, str] = {}
            for attribute in certificate.issuer:
                oid = attribute.oid.dotted_string
                value = attribute.value
                certificate_issuer[oid] = (
                    value.decode("utf-8", errors="replace")
                    if isinstance(value, bytes)
                    else str(value)
                )
            if certificate_issuer == issuer_values:
                return certificate
    elif sid_native is not None and "subject_key_identifier" in sid_native:
        expected = sid_native["subject_key_identifier"]
        for certificate in certificates:
            try:
                ski = certificate.extensions.get_extension_for_oid(
                    NameOID.SUBJECT_KEY_IDENTIFIER,
                )
            except Exception:
                continue
            if ski.value.digest == expected:
                return certificate

    return _resolve_signer_certificate_by_digest(signer_info, certificates)


def _resolve_signer_certificate_by_digest(
    signer_info: cms.SignerInfo,
    certificates: list[Certificate],
) -> Certificate | None:
    """Resolve the signer certificate via the ESS signing certificate.

    Handles both ``signingCertificateV2`` (digest algorithm chosen per
    cert, default SHA-256) and ``signingCertificate`` (always SHA-1).
    """
    from cryptography.hazmat.primitives import serialization

    attribute_oids: dict[str, tuple[type[core.Sequence], str]] = {
        _SIGNING_CERTIFICATE_V2_OID: (_SigningCertificateV2, "sha256"),
        _SIGNING_CERTIFICATE_V1_OID: (_SigningCertificate, "sha1"),
    }
    signed_attrs = signer_info["signed_attrs"]
    if signed_attrs.native is None:
        return None
    for attribute in signed_attrs:
        oid = attribute["type"].dotted
        if oid not in attribute_oids:
            continue
        model, default_digest = attribute_oids[oid]
        try:
            parsed = model.load(attribute["values"][0].dump())
        except Exception:
            continue
        for entry in parsed["certs"]:
            digest_algorithm = default_digest
            if entry["hash_algorithm"].native is not None:
                try:
                    digest_algorithm = _HASH_ALGORITHMS.get(
                        entry["hash_algorithm"]["algorithm"].native,
                        default_digest,
                    )
                except Exception:
                    digest_algorithm = default_digest
            try:
                expected = entry["cert_hash"].native
            except Exception:
                continue
            for certificate in certificates:
                try:
                    der = certificate.public_bytes(serialization.Encoding.DER)
                except Exception:  # pragma: no cover
                    continue
                if hashlib.new(digest_algorithm, der).digest() == expected:
                    return certificate
    return None


def parse_cms(data: bytes) -> CmsDocument | None:
    """Parse a CMS SignedData structure from *data*.

    Accepts DER and BER encodings (including the trailing zero padding
    PAdES signers use to fill the fixed-size ``/Contents`` field).

    Returns
    -------
    CmsDocument | None
        The parsed structure, or None when *data* is not a CMS
        SignedData.
    """
    try:
        content_info = cms.ContentInfo.load(data)
        if content_info["content_type"].native != "signed_data":
            return None
        signed_data = content_info["content"]
    except Exception:
        return None

    try:
        content = signed_data["encap_content_info"]["content"].native
    except Exception:
        content = None

    certificates = _load_certificates(signed_data["certificates"])

    signers: list[CmsSignerInfo] = []
    for signer_info in signed_data["signer_infos"]:
        signers.append(_parse_signer_info(signer_info, certificates))

    return CmsDocument(
        content=content,
        certificates=certificates,
        signers=signers,
    )


def _parse_signer_info(
    signer_info: cms.SignerInfo,
    certificates: list[Certificate],
) -> CmsSignerInfo:
    """Parse a single SignerInfo into a CmsSignerInfo."""
    attributes = _parse_signed_attributes(signer_info)

    digest_algorithm: str | None = None
    try:
        digest_algorithm = _HASH_ALGORITHMS.get(
            signer_info["digest_algorithm"]["algorithm"].native,
        )
    except Exception:
        pass

    signature_algorithm: str | None = None
    signature_hash: str | None = None
    try:
        algorithm_identifier = signer_info["signature_algorithm"]
        signature_algorithm = algorithm_identifier.signature_algo
        signature_hash = _HASH_ALGORITHMS.get(algorithm_identifier.hash_algo)
    except Exception:
        pass

    signing_time = None
    time_value = attributes.get(_SIGNING_TIME_OID)
    if time_value is not None:
        try:
            signing_time = time_value.native
        except Exception:
            signing_time = None
        if signing_time is not None and signing_time.tzinfo is None:
            signing_time = signing_time.replace(tzinfo=datetime.UTC)

    message_digest = attributes.get(_MESSAGE_DIGEST_OID)
    if message_digest is not None:
        try:
            message_digest = message_digest.native
        except Exception:
            message_digest = None

    unsigned_present = _parse_unsigned_attribute_oids(signer_info)

    certificate = _resolve_signer_certificate(signer_info, certificates)

    return CmsSignerInfo(
        certificate=certificate,
        signing_time=signing_time,
        digest_algorithm=digest_algorithm,
        signature_algorithm=signature_algorithm,
        signature_hash=signature_hash,
        signature_value=signer_info["signature"].native or b"",
        message_digest=message_digest,
        signed_attributes_der=_signed_attributes_der(signer_info),
        timestamp_present=_SIGNATURE_TIMESTAMP_OID in unsigned_present,
        ocsp_present=_REVOCATION_INFO_CHOICES_OID in unsigned_present,
    )


def _signed_attributes_der(signer_info: cms.SignerInfo) -> bytes | None:
    """Return the DER encoding of the signed attributes, or None.

    CMS signatures cover the DER encoding of the ``signedAttrs`` field.
    asn1crypto models the field as implicitly tagged ``[0]``; for
    signature computation the implicit tag is replaced with the plain
    SET OF tag (RFC 5652, Section 5.5) — verified against real-world
    CAdES/PAdES samples.
    """
    signed_attrs = signer_info["signed_attrs"]
    if signed_attrs.native is None:
        return None
    der = signed_attrs.dump()
    if der[:1] == b"\xa0":
        der = b"\x31" + der[1:]
    return der


def verify_signature(signer: CmsSignerInfo, content: bytes) -> bool | None:
    """Verify the signature value of *signer* over *content*.

    When the signer carries signed attributes the signature input is the
    DER encoding of those attributes; otherwise the raw content is used.
    Returns True/False when the algorithm is supported, None otherwise.
    """
    if signer.certificate is None:
        return None
    if signer.signature_algorithm not in _SUPPORTED_SIGNATURE_ALGORITHMS:
        return None
    data = signer.signed_attributes_der if signer.signed_attributes_der else content
    return _verify_with_key(
        signer.certificate,
        signer.signature_value,
        data,
        signer.signature_algorithm,
        signer.signature_hash,
    )


def verify_message_digest(signer: CmsSignerInfo, content: bytes) -> bool | None:
    """Verify the messageDigest attribute against *content*.

    Returns True/False when the attribute and digest algorithm are
    present, None otherwise.
    """
    if signer.message_digest is None or signer.digest_algorithm is None:
        return None
    try:
        digest = hashlib.new(signer.digest_algorithm, content).digest()
    except (ValueError, TypeError):
        return None
    return digest == signer.message_digest


def _verify_with_key(
    certificate: Certificate,
    signature_value: bytes,
    data: bytes,
    algorithm: str,
    hash_name: str | None,
) -> bool | None:
    """Verify *signature_value* over *data* with the certificate's key."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, padding, rsa

    hash_class = {
        "sha1": hashes.SHA1,
        "sha224": hashes.SHA224,
        "sha256": hashes.SHA256,
        "sha384": hashes.SHA384,
        "sha512": hashes.SHA512,
    }.get(hash_name or "")
    if hash_class is None:
        return None
    digest = hash_class()

    public_key = certificate.public_key()
    try:
        if algorithm == "rsassa_pkcs1v15" and isinstance(
            public_key,
            rsa.RSAPublicKey,
        ):
            public_key.verify(signature_value, data, padding.PKCS1v15(), digest)
        elif algorithm == "rsassa_pss" and isinstance(
            public_key,
            rsa.RSAPublicKey,
        ):
            public_key.verify(
                signature_value,
                data,
                padding.PSS(mgf=padding.MGF1(digest), salt_length=padding.PSS.AUTO),
                digest,
            )
        elif algorithm == "ecdsa" and isinstance(
            public_key,
            ec.EllipticCurvePublicKey,
        ):
            public_key.verify(signature_value, data, ec.ECDSA(digest))
        elif algorithm == "dsa" and isinstance(public_key, dsa.DSAPublicKey):
            public_key.verify(signature_value, data, digest)
        else:  # pragma: no cover - unsupported key/algorithm combination
            logger.warning(
                "Unsupported CMS signature algorithm %r for key %s",
                algorithm,
                type(public_key).__name__,
            )
            return None
        return True
    except (InvalidSignature, ValueError):
        return False
    except Exception:
        logger.warning("Signature verification failed", exc_info=True)
        return False


#: Certificate common names that do not identify the signer.
_PLACEHOLDER_CN_VALUES: frozenset[str] = frozenset(
    {"private", "privātpersona"},
)


def _certificate_name_attributes(cert) -> tuple[str | None, str | None, str | None]:
    """Return ``(common_name, organization, country)`` of a certificate subject."""
    from cryptography.x509 import NameOID

    def _name_attribute(oid) -> str | None:
        try:
            attributes = cert.subject.get_attributes_for_oid(oid)
            if not attributes:
                return None
            value = attributes[0].value
            return value.decode("utf-8") if isinstance(value, bytes) else value
        except Exception:
            return None

    return (
        _name_attribute(NameOID.COMMON_NAME),
        _name_attribute(NameOID.ORGANIZATION_NAME),
        _name_attribute(NameOID.COUNTRY_NAME),
    )


def _personal_name(cert) -> str | None:
    """Return the given-name + surname of a certificate subject, if any.

    Some national certificates (e.g. the Italian CIE) embed a personal
    code in the common name and carry the actual name in the givenName
    and surname attributes.
    """
    from cryptography.x509 import NameOID

    def _attribute(oid) -> str | None:
        try:
            attributes = cert.subject.get_attributes_for_oid(oid)
            if not attributes:
                return None
            value = attributes[0].value
            return value.decode("utf-8") if isinstance(value, bytes) else value
        except Exception:
            return None

    given_name = _attribute(NameOID.GIVEN_NAME)
    surname = _attribute(NameOID.SURNAME)
    if given_name and surname:
        return f"{given_name} {surname}"
    return None


def signer_certificate_name(signer: CmsSignerInfo) -> str | None:
    """Return a usable name for the signer of *signer*, or None.

    The certificate's organization is preferred over the common name
    (mirroring the XAdES path); placeholder common names ("Private") are
    not usable, and common names that are personal codes (e.g. the
    Italian CIE tax-code CNs) fall back to given name + surname.
    """
    if signer.certificate is None:
        return None
    common_name, organization, _ = _certificate_name_attributes(
        signer.certificate,
    )
    if organization:
        return organization
    if common_name:
        normalized = common_name.strip().lower()
        if normalized not in _PLACEHOLDER_CN_VALUES and not any(
            char.isdigit() for char in normalized
        ):
            return common_name
    return _personal_name(signer.certificate)
