"""
Helpers for building synthetic ASiC-E (EDOC 2.0) containers in tests.

The real Latvian EDOC 2.0 sample files contain personal data, so the test
suite constructs its own containers from scratch: a minimal PDF payload, a
self-signed signer certificate, a genuine XAdES signature and the full
container layout (``mimetype``, ``META-INF/signatures001.xml`` or
``META-INF/edoc-signatures-S1.xml``, ``META-INF/manifest.xml``).

Two signature profiles are supported, mirroring the real-world producers:

* exclusive c14n (``xml-exc-c14n``) with an RSA key and the
  ``signatures001.xml`` naming — the Java eDOC libraries, and
* inclusive c14n 1.1 (``xml-c14n11``) with an ECDSA P-384 key and the
  ``edoc-signatures-S1.xml`` naming — the eParaksts mobile signing
  library.

The cryptographic structure mirrors what real EDOC files look like — the
container is verified against the real-world eParaksts samples manually.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import io
import zipfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID
from lxml import etree

from paperless_edoc.parser import EDOC_CONTAINER_MIME_TYPE

_XMLDSIG_NS: str = "http://www.w3.org/2000/09/xmldsig#"
_XADES_NS: str = "http://uri.etsi.org/01903/v1.3.2#"
_OD_MANIFEST_NS: str = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"

_EXC_C14N_ALG: str = "http://www.w3.org/2001/10/xml-exc-c14n#"
_C14N11_ALG: str = "http://www.w3.org/2006/12/xml-c14n11"
_SHA256_DIGEST_ALG: str = "http://www.w3.org/2001/04/xmlenc#sha256"
_RSA_SHA256_ALG: str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
_ECDSA_SHA256_ALG: str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
_SIGNED_PROPERTIES_TYPE: str = "http://uri.etsi.org/01903#SignedProperties"

_DEFAULT_SIGNING_TIME: datetime.datetime = datetime.datetime(
    2026,
    1,
    15,
    10,
    30,
    0,
    tzinfo=datetime.UTC,
)


def build_simple_pdf(
    *,
    text: str = "Hello EDOC",
    creation_date: str = "D:20260115103000Z",
) -> bytes:
    """Build a minimal, valid single-page PDF containing *text*."""
    content = b"BT /F1 24 Tf 72 720 Td (" + text.encode("ascii") + b") Tj ET"
    stream_object = (
        b"<< /Length " + str(len(content)).encode("ascii") + b" >>\n"
        b"stream\n" + content + b"\nendstream"
    )
    objects: list[bytes] = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>"
        ),
        stream_object,
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        (
            b"<< /Producer (paperless-ngx tests) "
            b"/CreationDate (" + creation_date.encode("ascii") + b") >>"
        ),
    ]

    header = b"%PDF-1.4\n"
    body = b""
    offsets: list[int] = []
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(header) + len(body))
        body += str(index).encode("ascii") + b" 0 obj\n" + obj + b"\nendobj\n"

    xref_position = len(header) + len(body)
    xref = (
        b"xref\n0 " + str(len(objects) + 1).encode("ascii") + b"\n0000000000 65535 f \n"
    )
    for offset in offsets:
        xref += b"%010d 00000 n \n" % offset
    trailer = (
        b"trailer\n<< /Size "
        + str(len(objects) + 1).encode("ascii")
        + b" /Root 1 0 R /Info 6 0 R >>\nstartxref\n"
        + str(xref_position).encode("ascii")
        + b"\n%%EOF"
    )

    return header + body + xref + trailer


def build_simple_docx(text: str = "Hello DOCX") -> bytes:
    """Build a minimal, valid DOCX file containing *text*.

    Newlines in *text* become separate paragraphs.  The file is parseable
    by both LibreOffice/Gotenberg and the parser's local XML fallback.
    """
    paragraphs = [
        (
            f"<w:p><w:r><w:t>{line}</w:t></w:r></w:p>"
            for line in text.split("\n")
            if line
        ),
    ]
    document_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/'
        'wordprocessingml/2006/main">'
        f"<w:body>{''.join(paragraphs[0])}</w:body>"
        "</w:document>"
    )
    content_types_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/'
        'content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-'
        'package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" ContentType="application/'
        'vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        "</Types>"
    )
    rels_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/'
        'relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/'
        'officeDocument/2006/relationships/officeDocument" '
        'Target="word/document.xml"/>'
        "</Relationships>"
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types_xml)
        archive.writestr("_rels/.rels", rels_xml)
        archive.writestr("word/document.xml", document_xml)
    return buffer.getvalue()


def _office_media_type(name: str) -> str:
    """Return the media type of a common office document name."""
    suffix = name.lower().rsplit(".", 1)[-1]
    return {
        "docx": (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        ),
        "doc": "application/msword",
        "odt": "application/vnd.oasis.opendocument.text",
    }.get(suffix, "application/octet-stream")


def generate_certificate(
    *,
    common_name: str,
    organization: str | None,
    country: str,
    private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | None = None,
    key_type: str = "rsa",
) -> tuple[rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey, x509.Certificate]:
    """Generate a self-signed certificate with the given subject.

    *key_type* selects the key used when *private_key* is not supplied:
    ``"rsa"`` (default) or ``"ec"`` (P-384, mirroring the eParaksts
    mobile signing library which uses ``ecdsa-sha256``).  Pass
    *organization* as ``None`` to omit the organization attribute from
    the subject.
    """
    if private_key is None:
        if key_type == "ec":
            private_key = ec.generate_private_key(ec.SECP384R1())
        else:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name_attributes: list[x509.NameAttribute] = [
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ]
    if organization is not None:
        name_attributes.insert(
            1,
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        )
    subject = issuer = x509.Name(name_attributes)
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=30))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )
    return private_key, certificate


def _exclusive_c14n(element: etree._Element) -> bytes:
    """Canonicalise an element subtree in the exclusive XML-c14n form."""
    return etree.tostring(
        element,
        method="c14n",
        exclusive=True,
        with_comments=False,
    )


def _inclusive_c14n(element: etree._Element) -> bytes:
    """Canonicalise an element in the inclusive c14n 1.1 form.

    The element must already be attached to the document tree so that
    every namespace in scope (including those inherited from ancestors,
    e.g. the ``asic`` container namespace) is rendered, mirroring the
    eParaksts mobile signing library.
    """
    return etree.tostring(
        element,
        method="c14n",
        exclusive=False,
        with_comments=False,
    )


def _set_text(element: etree._Element, value: str) -> None:
    """Set an element's text content.

    The lxml type stubs model ``text`` via the ``Ellipsis`` sentinel, which
    static checkers cannot assign to; keep the assignment behind this helper.
    """
    element.text = value  # pyrefly: ignore[bad-assignment]


def _wrap_in_sequences(der: bytes) -> bytes:
    """Wrap DER bytes in two SEQUENCEs, mimicking a SignedData wrapper."""

    def sequence(data: bytes) -> bytes:
        if len(data) < 128:
            return b"\x30" + bytes([len(data)]) + data
        return b"\x30\x82" + len(data).to_bytes(2, "big") + data

    return sequence(sequence(der))


def _raw_ecdsa_signature(der_signature: bytes, key_size: int) -> bytes:
    """Convert a DER ECDSA signature to the raw r||s form (RFC 4051)."""
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    r, s = decode_dss_signature(der_signature)
    component_size = (key_size + 7) // 8
    return r.to_bytes(component_size, "big") + s.to_bytes(component_size, "big")


def build_xades_signature(
    *,
    document_name: str,
    document_data: bytes,
    private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    signer_certificate: x509.Certificate,
    signing_time: datetime.datetime | None = _DEFAULT_SIGNING_TIME,
    signed_document_name: str | None = None,
    digest_over: bytes | None = None,
    sign_over: bytes | None = None,
    include_timestamp: bool = True,
    include_ocsp: bool = True,
    include_certificate_values: bool = True,
    include_keyinfo_cert: bool = True,
    include_signer_in_certificate_values: bool = False,
    canonicalization: str = "exclusive",
    documents: list[tuple[str, bytes]] | None = None,
) -> bytes:
    """Build a XAdES signature XML document for *document_data*.

    *signed_document_name* is the URI used in the signature reference and
    may differ from the zip entry name (``document_name``) to exercise the
    reference-over-manifest selection logic.

    *digest_over* (document digest reference) and *sign_over* (signature
    input) allow tests to construct deliberately tampered containers: the
    digest or the signature is computed over different bytes than the
    payload actually stored in the container.

    *documents* overrides the signed payload with a list of
    ``(reference_uri, data)`` pairs, emitting one ``ds:Reference`` per
    document like the multi-document containers produced by the Latvian
    e-archive (signed DOCX companions plus the nested container).  When
    provided, *signed_document_name* and *digest_over* are ignored.

    Pass *signing_time* as ``None`` to omit the ``SigningTime`` element,
    e.g. to test the creation-date fallback.

    *canonicalization* selects the declared canonicalisation method:
    ``"exclusive"`` (``xml-exc-c14n``, the ASiC-E / Java eDOC library
    convention) or ``"inclusive"`` (``xml-c14n11``, the convention of the
    eParaksts mobile signing library; the digests are then computed over
    the canonical form of the elements inside the assembled document so
    that every in-scope namespace is rendered).  With an
    ``ec.EllipticCurvePrivateKey`` the signature is created with
    ``ecdsa-sha256`` over P-384, otherwise ``rsa-sha256``.
    """
    ds = _XMLDSIG_NS
    xa = _XADES_NS

    if canonicalization == "inclusive":
        canonicalization_algorithm = _C14N11_ALG
        canonicalize = _inclusive_c14n
    elif canonicalization == "exclusive":
        canonicalization_algorithm = _EXC_C14N_ALG
        canonicalize = _exclusive_c14n
    else:
        raise ValueError(f"Unsupported canonicalization {canonicalization!r}")

    signature_method_algorithm = (
        _ECDSA_SHA256_ALG
        if isinstance(private_key, ec.EllipticCurvePrivateKey)
        else _RSA_SHA256_ALG
    )

    def ds_tag(tag: str) -> str:
        return f"{{{ds}}}{tag}"

    def xa_tag(tag: str) -> str:
        return f"{{{xa}}}{tag}"

    def b64(data: bytes) -> str:
        return base64.b64encode(data).decode("ascii")

    if documents is None:
        documents = [
            (
                signed_document_name or document_name,
                digest_over if digest_over is not None else document_data,
            ),
        ]

    document_references: list[tuple[str, str, bytes]] = [
        (f"r-doc-{index + 1}", uri, data) for index, (uri, data) in enumerate(documents)
    ]

    signature_id = "id-sig-1"
    signed_properties_id = "xades-id-1"

    # --- SignedProperties (built first; its digest is referenced below) ---
    cert_digest = hashlib.sha256(
        signer_certificate.public_bytes(serialization.Encoding.DER),
    ).digest()

    signing_time_text = (
        signing_time.astimezone(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        if signing_time is not None
        else ""
    )

    signed_properties = etree.Element(
        xa_tag("SignedProperties"),
        nsmap={"ds": ds, "xades": xa},
    )
    signed_properties.set("Id", signed_properties_id)
    signed_signature_properties = etree.SubElement(
        signed_properties,
        xa_tag("SignedSignatureProperties"),
    )
    if signing_time is not None:
        _set_text(
            etree.SubElement(
                signed_signature_properties,
                xa_tag("SigningTime"),
            ),
            signing_time_text,
        )
    signing_certificate_v2 = etree.SubElement(
        signed_signature_properties,
        xa_tag("SigningCertificateV2"),
    )
    cert_entry = etree.SubElement(signing_certificate_v2, xa_tag("Cert"))
    cert_digest_element = etree.SubElement(cert_entry, xa_tag("CertDigest"))
    etree.SubElement(
        cert_digest_element,
        ds_tag("DigestMethod"),
        Algorithm=_SHA256_DIGEST_ALG,
    )
    _set_text(
        etree.SubElement(
            cert_digest_element,
            ds_tag("DigestValue"),
        ),
        b64(cert_digest),
    )
    _set_text(
        etree.SubElement(
            cert_entry,
            xa_tag("IssuerSerialV2"),
        ),
        b64(b"\x30\x00"),
    )
    signed_data_object_properties = etree.SubElement(
        signed_properties,
        xa_tag("SignedDataObjectProperties"),
    )
    data_object_format = etree.SubElement(
        signed_data_object_properties,
        xa_tag("DataObjectFormat"),
        ObjectReference=f"#{document_references[0][0]}",
    )
    _set_text(
        etree.SubElement(
            data_object_format,
            xa_tag("MimeType"),
        ),
        "application/pdf",
    )

    # The SignedProperties digest is computed below once the element is
    # part of the assembled document, so that the canonical form used for
    # the digest reference matches the form the verifier recomputes.

    # --- SignedInfo ---
    # The ds: namespace must be declared on this element itself so that
    # the canonical form used for signing matches the canonical form
    # of the re-parsed document (the digests are computed before the
    # element is assembled into the final tree).
    signed_info = etree.Element(ds_tag("SignedInfo"), nsmap={"ds": ds})
    etree.SubElement(
        signed_info,
        ds_tag("CanonicalizationMethod"),
        Algorithm=canonicalization_algorithm,
    )
    etree.SubElement(
        signed_info,
        ds_tag("SignatureMethod"),
        Algorithm=signature_method_algorithm,
    )
    for reference_id, uri, data in document_references:
        document_reference = etree.SubElement(
            signed_info,
            ds_tag("Reference"),
            Id=reference_id,
            URI=uri,
        )
        etree.SubElement(
            document_reference,
            ds_tag("DigestMethod"),
            Algorithm=_SHA256_DIGEST_ALG,
        )
        _set_text(
            etree.SubElement(
                document_reference,
                ds_tag("DigestValue"),
            ),
            b64(hashlib.sha256(data).digest()),
        )
    signed_properties_reference = etree.SubElement(
        signed_info,
        ds_tag("Reference"),
        Type=_SIGNED_PROPERTIES_TYPE,
        URI=f"#{signed_properties_id}",
    )
    transforms = etree.SubElement(
        signed_properties_reference,
        ds_tag("Transforms"),
    )
    etree.SubElement(
        transforms,
        ds_tag("Transform"),
        Algorithm=canonicalization_algorithm,
    )
    etree.SubElement(
        signed_properties_reference,
        ds_tag("DigestMethod"),
        Algorithm=_SHA256_DIGEST_ALG,
    )
    signed_properties_digest_value = etree.SubElement(
        signed_properties_reference,
        ds_tag("DigestValue"),
    )
    # Filled in once the SignedProperties digest is known.

    # --- Unsigned properties: timestamp, certificate values, OCSP ---
    unsigned_properties: list[etree._Element] = []
    if include_timestamp:
        _, tsa_certificate = generate_certificate(
            common_name="Test TSA",
            organization="Test TSA",
            country="LV",
        )
        timestamp_wrapper = _wrap_in_sequences(
            tsa_certificate.public_bytes(serialization.Encoding.DER),
        )
        signature_timestamp = etree.Element(
            xa_tag("SignatureTimeStamp"),
            Id="ts-1",
        )
        etree.SubElement(
            signature_timestamp,
            ds_tag("CanonicalizationMethod"),
            Algorithm=_EXC_C14N_ALG,
        )
        _set_text(
            etree.SubElement(
                signature_timestamp,
                xa_tag("EncapsulatedTimeStamp"),
                Id="ets-1",
            ),
            b64(timestamp_wrapper),
        )
        unsigned_properties.append(signature_timestamp)

    if include_certificate_values:
        _, root_ca = generate_certificate(
            common_name="Test Root CA",
            organization="Test CA",
            country="LV",
        )
        _, intermediate_ca = generate_certificate(
            common_name="Test Intermediate CA",
            organization="Test CA",
            country="LV",
        )
        certificate_values = etree.Element(xa_tag("CertificateValues"))
        chain_certificates = (
            [signer_certificate] if include_signer_in_certificate_values else []
        )
        chain_certificates.extend([root_ca, intermediate_ca])
        for cert in chain_certificates:
            _set_text(
                etree.SubElement(
                    certificate_values,
                    xa_tag("EncapsulatedX509Certificate"),
                ),
                b64(cert.public_bytes(serialization.Encoding.DER)),
            )
        unsigned_properties.append(certificate_values)

    if include_ocsp:
        revocation_values = etree.Element(xa_tag("RevocationValues"))
        ocsp_values = etree.SubElement(revocation_values, xa_tag("OCSPValues"))
        _set_text(
            etree.SubElement(
                ocsp_values,
                xa_tag("EncapsulatedOCSPValue"),
            ),
            b64(b"fake-ocsp-response-1"),
        )
        unsigned_properties.append(revocation_values)

    unsigned_signature_properties = etree.Element(
        xa_tag("UnsignedSignatureProperties"),
    )
    for element in unsigned_properties:
        unsigned_signature_properties.append(element)

    # --- Assemble the full signature document ---
    signature = etree.Element(
        ds_tag("Signature"),
        nsmap={"ds": ds, "xades": xa},
        Id=signature_id,
    )
    signature.append(signed_info)
    signature_value_element = etree.SubElement(
        signature,
        ds_tag("SignatureValue"),
        Id="value-" + signature_id,
    )
    if include_keyinfo_cert:
        key_info = etree.SubElement(signature, ds_tag("KeyInfo"))
        x509_data = etree.SubElement(key_info, ds_tag("X509Data"))
        _set_text(
            etree.SubElement(
                x509_data,
                ds_tag("X509Certificate"),
            ),
            b64(signer_certificate.public_bytes(serialization.Encoding.DER)),
        )

    object_element = etree.SubElement(signature, ds_tag("Object"))
    qualifying_properties = etree.SubElement(
        object_element,
        xa_tag("QualifyingProperties"),
        Target=f"#{signature_id}",
    )
    qualifying_properties.append(signed_properties)
    unsigned_properties_element = etree.SubElement(
        qualifying_properties,
        xa_tag("UnsignedProperties"),
    )
    unsigned_properties_element.append(unsigned_signature_properties)

    root = etree.Element(
        "{http://uri.etsi.org/02918/v1.2.1#}XAdESSignatures",
        nsmap={"asic": "http://uri.etsi.org/02918/v1.2.1#"},
    )
    root.append(signature)

    # --- Signing-time digests over the assembled document ---
    # The canonical form of the assembled elements is used so that every
    # namespace in scope (including inherited ones) is rendered, exactly
    # as a verifier recomputing the digests from the stored document will
    # see it.
    signed_properties_digest = hashlib.sha256(
        canonicalize(signed_properties),
    ).digest()
    _set_text(signed_properties_digest_value, b64(signed_properties_digest))

    signature_input = sign_over if sign_over is not None else canonicalize(signed_info)
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        signature_value = private_key.sign(
            signature_input,
            ec.ECDSA(hashes.SHA256()),
        )
        # XAdES/XMLDSIG represent ECDSA signature values as the raw
        # concatenation of r and s (RFC 4051), which is what the
        # eParaksts mobile signing library emits; cryptography's
        # ``sign`` produces DER instead.
        signature_value = _raw_ecdsa_signature(
            signature_value,
            private_key.curve.key_size,
        )
    else:
        signature_value = private_key.sign(
            signature_input,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    _set_text(signature_value_element, b64(signature_value))

    return etree.tostring(
        root,
        xml_declaration=True,
        encoding="UTF-8",
        standalone=True,
    )


def build_manifest(
    *,
    document_name: str,
    document_media_type: str = "application/pdf",
    extra_entries: list[tuple[str, str]] | None = None,
) -> bytes:
    """Build the ODF-style manifest listing the container contents.

    *document_name* is listed with *document_media_type*; *extra_entries*
    are additional ``(full_path, media_type)`` pairs, e.g. the signed
    DOCX companions of a multi-document container.
    """
    root = etree.Element(
        f"{{{_OD_MANIFEST_NS}}}manifest",
        nsmap={"manifest": _OD_MANIFEST_NS},
        version="1.2",
    )
    root_attributes: dict[str, str] = {
        f"{{{_OD_MANIFEST_NS}}}full-path": "/",
        f"{{{_OD_MANIFEST_NS}}}media-type": EDOC_CONTAINER_MIME_TYPE,
    }
    etree.SubElement(root, f"{{{_OD_MANIFEST_NS}}}file-entry", root_attributes)
    document_attributes: dict[str, str] = {
        f"{{{_OD_MANIFEST_NS}}}full-path": document_name,
        f"{{{_OD_MANIFEST_NS}}}media-type": document_media_type,
    }
    etree.SubElement(root, f"{{{_OD_MANIFEST_NS}}}file-entry", document_attributes)
    for entry_name, media_type in extra_entries or []:
        etree.SubElement(
            root,
            f"{{{_OD_MANIFEST_NS}}}file-entry",
            {
                f"{{{_OD_MANIFEST_NS}}}full-path": entry_name,
                f"{{{_OD_MANIFEST_NS}}}media-type": media_type,
            },
        )
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True)


def build_edoc_container(
    *,
    document_data: bytes | None = None,
    document_name: str = "document.pdf",
    signed_name: str | None = None,
    signer_cn: str = "Test Signer",
    signer_org: str | None = "Test Organization",
    signer_country: str = "LV",
    signing_time: datetime.datetime = _DEFAULT_SIGNING_TIME,
    digest_over: bytes | None = None,
    sign_over: bytes | None = None,
    include_timestamp: bool = True,
    include_ocsp: bool = True,
    include_certificate_values: bool = True,
    include_keyinfo_cert: bool = True,
    include_signer_in_certificate_values: bool = False,
    include_manifest: bool = True,
    include_signature: bool = True,
    container_mimetype: str = EDOC_CONTAINER_MIME_TYPE,
    extra_entries: dict[str, bytes] | None = None,
    signed_documents: list[tuple[str, bytes]] | None = None,
    document_media_type: str = "application/pdf",
    manifest_extra_entries: list[tuple[str, str]] | None = None,
    canonicalization: str = "exclusive",
    key_type: str = "rsa",
    signature_file_name: str = "META-INF/signatures001.xml",
) -> bytes:
    """Build a complete EDOC 2.0 (ASiC-E) container as bytes.

    The container layout mirrors real Latvian EDOC files: an
    uncompressed ``mimetype`` entry first, then the XAdES signature, the
    manifest and the signed PDF payload.

    *signed_name* is the URI referenced by the signature and may differ
    from *document_name* to exercise the reference-over-manifest
    document selection.

    *signed_documents* overrides the signed payload with a list of
    ``(reference_uri, data)`` pairs, producing one ``ds:Reference`` per
    document (the multi-document containers of the Latvian e-archive).
    ``document_media_type`` and *manifest_extra_entries* describe the
    container contents in the manifest accordingly.

    *canonicalization*, *key_type* and *signature_file_name* select the
    signature profile: ``"exclusive"`` canonicalisation with an RSA key
    in ``META-INF/signatures001.xml`` mirrors the Java eDOC libraries,
    while ``"inclusive"`` canonicalisation with an EC key in
    ``META-INF/edoc-signatures-S1.xml`` mirrors the eParaksts mobile
    signing library.
    """
    if document_data is None:
        document_data = build_simple_pdf()

    private_key, signer_certificate = generate_certificate(
        common_name=signer_cn,
        organization=signer_org,
        country=signer_country,
        key_type=key_type,
    )

    signature_xml = build_xades_signature(
        document_name=document_name,
        document_data=document_data,
        private_key=private_key,
        signer_certificate=signer_certificate,
        signing_time=signing_time,
        signed_document_name=signed_name,
        digest_over=digest_over,
        sign_over=sign_over,
        include_timestamp=include_timestamp,
        include_ocsp=include_ocsp,
        include_certificate_values=include_certificate_values,
        include_keyinfo_cert=include_keyinfo_cert,
        include_signer_in_certificate_values=include_signer_in_certificate_values,
        canonicalization=canonicalization,
        documents=signed_documents,
    )

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("mimetype", container_mimetype)
        if include_signature:
            archive.writestr(signature_file_name, signature_xml)
        if include_manifest:
            archive.writestr(
                "META-INF/manifest.xml",
                build_manifest(
                    document_name=document_name,
                    document_media_type=document_media_type,
                    extra_entries=manifest_extra_entries,
                ),
            )
        archive.writestr(document_name, document_data)
        for name, data in (extra_entries or {}).items():
            archive.writestr(name, data)
    return buffer.getvalue()


def build_nested_edoc_container(
    *,
    inner_document_data: bytes | None = None,
    inner_document_name: str = "document.pdf",
    nested_name: str = "nested.edoc",
    nested_media_type: str = "application/octet-stream",
    extra_entries: dict[str, bytes] | None = None,
    signing_time: datetime.datetime = _DEFAULT_SIGNING_TIME,
    signer_cn: str = "Test Signer",
    signer_org: str | None = "Test Organization",
    signer_country: str = "LV",
) -> bytes:
    """Build a nested EDOC 2.0 container ("EDOC within EDOC").

    Mirrors the bundle format produced by the Latvian e-archive: the
    outer container (inclusive c14n 1.1, ECDSA,
    ``META-INF/edoc-signatures-S1.xml``) wraps an inner EDOC container
    (exclusive c14n, RSA, ``META-INF/signatures001.xml``) that carries
    the actual PDF, plus any additional *extra_entries* (e.g. signed
    DOCX companions such as a decision document and its protocol).  The
    outer XAdES signature covers every wrapped entry with its own
    ``ds:Reference``, so the digest verification in the parser stays
    valid.
    """
    inner_bytes = build_edoc_container(
        document_data=inner_document_data,
        document_name=inner_document_name,
        signing_time=signing_time,
    )

    documents: list[tuple[str, bytes]] = []
    manifest_extra_entries: list[tuple[str, str]] = []
    for name, data in (extra_entries or {}).items():
        documents.append((name, data))
        manifest_extra_entries.append((name, _office_media_type(name)))
    # The nested container is referenced last, mirroring the real
    # e-archive bundles (companion documents first, container last).
    documents.append((nested_name, inner_bytes))

    return build_edoc_container(
        document_data=inner_bytes,
        document_name=nested_name,
        signed_name=nested_name,
        signing_time=signing_time,
        signer_cn=signer_cn,
        signer_org=signer_org,
        signer_country=signer_country,
        canonicalization="inclusive",
        key_type="ec",
        signature_file_name="META-INF/edoc-signatures-S1.xml",
        signed_documents=documents,
        document_media_type=nested_media_type,
        manifest_extra_entries=manifest_extra_entries,
        extra_entries=extra_entries,
    )
