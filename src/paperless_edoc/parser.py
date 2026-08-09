"""
Third-party EDOC 2.0 / ETSI ASiC-E parser for Paperless-ngx.

EDOC 2.0 is the Latvian electronic signature format specified by
"EDOC Elektroniskā paraksta formāts 2.0".  It is a XAdES signature
(long-term validation level, parallel signature) packaged inside an
ETSI ASiC-E container: a ZIP archive containing

* a ``mimetype`` entry set to ``application/vnd.etsi.asic-e+zip``,
* ``META-INF/signatures001.xml`` carrying the XAdES signature
  (signing time, signer certificate, RFC 3161 timestamp, OCSP values),
* ``META-INF/manifest.xml`` listing the container contents, and
* the signed data object itself (a PDF for real-world EDOC documents).

The same container layout is used by the other EU member-state formats
``.asice`` (Estonia), ``.bdoc`` (Estonia) and ``.adoc`` (Lithuania);
the parser is format-agnostic and only verifies the container's
``mimetype`` entry.  The Latvian e-archive additionally produces
*nested* containers ("EDOC within EDOC") whose outer container wraps
documents plus an inner EDOC container that carries the actual PDF; the
parser descends into nested containers to reach the PDF (see
:meth:`EdocDocumentParser._extract_inner_pdf`).  Every document inside a
container is ingested: the inner PDFs are merged with the office
documents (DOCX, ODT, ...) converted via Gotenberg into a single
rendition PDF, and the text of every document is combined for search
(see :meth:`EdocDocumentParser.parse`).

Detection
---------
libmagic does not recognise ASiC containers, so ``python-magic`` reports
``application/zip`` for these files.  Since a third-party parser can
only declare the MIME type libmagic actually reports, this parser
declares ``application/zip`` and uses content inspection (the
container's ``mimetype`` entry, see :func:`is_edoc_container`) in
:meth:`EdocDocumentParser.score` to only claim actual ASiC-E containers.
Consequences:

* documents are stored with ``document.mime_type == "application/zip"``;
* plain ZIP files pass the API/mail validation (``score`` cannot inspect
  a file without a path) but are rejected during consumption with a
  clear error message.

The parser extracts the signed PDF and stores it as the archive
rendition (the frontend cannot display ZIP containers natively), keeps
the original container as the source file, extracts the PDF text for
search and exposes the XAdES signature metadata — signer, signing time,
certificate chain, timestamps and cryptographic verification results —
through :meth:`EdocDocumentParser.extract_metadata`.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import io
import logging
import mimetypes
import re
import shutil
import tempfile
import urllib.parse
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Self

from django.conf import settings
from documents.parsers import ParseError, make_thumbnail_from_pdf

from paperless_edoc import __version__

if TYPE_CHECKING:
    from types import TracebackType

    from cryptography.hazmat.primitives.asymmetric import ec
    from paperless.parsers import MetadataEntry, ParserContext

logger = logging.getLogger("paperless_edoc")

#: The official media type of an ETSI ASiC-E container, as stored in the
#: ``mimetype`` entry of every EDOC 2.0 file.
EDOC_CONTAINER_MIME_TYPE: str = "application/vnd.etsi.asic-e+zip"

#: File extensions that are recognised as ASiC-E containers even though
#: libmagic reports them as ``application/zip``.  ``.asice`` is the
#: standard ETSI extension; ``.edoc`` is the Latvian one, ``.bdoc`` the
#: Estonian one and ``.adoc`` the Lithuanian one.
_EDOC_FILE_EXTENSIONS: tuple[str, ...] = (".edoc", ".asice", ".bdoc", ".adoc")

#: libmagic reports ASiC containers as ``application/zip``; a third-party
#: parser cannot influence detection, so this is the MIME type this
#: parser declares.  Content inspection in ``score()`` keeps it from
#: claiming plain ZIP archives.  The official ASiC-E media type is
#: declared as well so that get_supported_file_extensions() (which only
#: queries declared types) adds the member-state extensions to the
#: consumption-directory filter.
_SUPPORTED_MIME_TYPES: dict[str, str] = {
    "application/zip": ".edoc",
    EDOC_CONTAINER_MIME_TYPE: ".asice",
}

# Register the member-state extensions so that
# get_supported_file_extensions() (and thus the consumption-directory
# filter) accepts them and stored files keep a sensible extension.
mimetypes.add_type(EDOC_CONTAINER_MIME_TYPE, ".edoc")
mimetypes.add_type(EDOC_CONTAINER_MIME_TYPE, ".asice")
mimetypes.add_type(EDOC_CONTAINER_MIME_TYPE, ".bdoc")
mimetypes.add_type(EDOC_CONTAINER_MIME_TYPE, ".adoc")

# XML namespaces used inside XAdES signature files and the ODF manifest.
_XMLDSIG_NS: str = "http://www.w3.org/2000/09/xmldsig#"
_XADES_NS: str = "http://uri.etsi.org/01903/v1.3.2#"
_OD_MANIFEST_NS: str = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"

#: XAdES signature files live in ``META-INF/signaturesNNN.xml`` (the
#: ASiC-E / BDOC convention used by the Java eDOC libraries) or
#: ``META-INF/edoc-signatures-S1.xml`` (the naming mandated by the
#: Latvian EDOC 2.0 specification and used by the eParaksts mobile
#: signing library).
_SIGNATURE_FILE_RE: re.Pattern[str] = re.compile(
    r"^META-INF/(?:edoc-)?signatures(?:[-\w]+)?\.xml$",
)

#: Map of XMLDSig signature method URIs to their short names.
_SIGNATURE_ALGORITHMS: dict[str, str] = {
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": "rsa-sha256",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384": "rsa-sha384",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": "rsa-sha512",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha1": "rsa-sha1",
    "http://www.w3.org/2000/09/xmldsig#rsa-sha1": "rsa-sha1",
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256": "ecdsa-sha256",
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384": "ecdsa-sha384",
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512": "ecdsa-sha512",
}

#: Map of XMLDSig digest method URIs to ``hashlib`` names.
_DIGEST_ALGORITHMS: dict[str, str] = {
    "http://www.w3.org/2001/04/xmlenc#sha256": "sha256",
    "http://www.w3.org/2001/04/xmlenc#sha384": "sha384",
    "http://www.w3.org/2001/04/xmlenc#sha512": "sha512",
    "http://www.w3.org/2000/09/xmldsig#sha1": "sha1",
}

#: URIs of the inclusive canonicalisation methods (c14n 1.0 and 1.1).
#: Signatures produced with the eParaksts mobile signing library use
#: c14n 1.1, whose canonical form renders every in-scope namespace on
#: each element.
_INCLUSIVE_C14N_ALGORITHMS: frozenset[str] = frozenset(
    {
        "http://www.w3.org/2006/12/xml-c14n11",
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
    },
)

#: Matches the leading date/time of PDF date strings ("D:YYYYMMDDHHMMSS...").
_PDF_DATE_RE: re.Pattern[str] = re.compile(
    r"^D:(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})",
)

#: XML namespace of the WordprocessingML main document part.
_WORD_MAIN_NS: str = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"

#: Fragments of ``[Content_Types].xml`` that identify OpenXML and ODF
#: office documents (DOCX/XLSX/PPTX/ODT/...).
_OFFICE_OPENXML_FRAGMENTS: tuple[str, ...] = (
    "wordprocessingml",
    "spreadsheetml",
    "presentationml",
    "application/vnd.oasis.opendocument",
)


def is_edoc_container(source: Path | bytes) -> bool:
    """Return True if *source* is an EDOC 2.0 (ASiC-E) container.

    *source* may be a filesystem path or the raw file contents.  The
    check reads the container's ``mimetype`` entry, which must be
    ``application/vnd.etsi.asic-e+zip``.

    Parameters
    ----------
    source:
        Path to the file, or the file contents as bytes.

    Returns
    -------
    bool
        True when the ZIP container declares the EDOC/ASiC-E media type.
    """
    try:
        with zipfile.ZipFile(
            io.BytesIO(source)
            if isinstance(source, (bytes, bytearray))
            else Path(source),
        ) as archive:
            mimetype = (
                archive.read("mimetype").decode("utf-8", errors="replace").strip()
            )
    except (
        KeyError,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
        OSError,
        RuntimeError,
        UnicodeDecodeError,
    ):
        # RuntimeError covers encrypted containers, which ASiC-E explicitly
        # permits ("File ... is encrypted, password required for extraction").
        return False
    return mimetype == EDOC_CONTAINER_MIME_TYPE


def extract_signer_name(source: Path | bytes) -> str | None:
    """Return the signer name of the first signature, or None.

    *source* may be a filesystem path or the raw file contents.  The
    signer's organization is preferred over the certificate common name
    (Latvian individual certificates embed a personal code in the CN),
    and placeholder common names ("Private", "Privātpersona") are not
    usable as a name.  Best effort — any failure is logged and None is
    returned so that callers never crash because of it.

    Parameters
    ----------
    source:
        Path to the container, or the file contents as bytes.

    Returns
    -------
    str | None
        The signer's organization or common name, or None.
    """
    if not is_edoc_container(source):
        return None
    try:
        with (
            EdocDocumentParser() as parser,
            zipfile.ZipFile(
                io.BytesIO(source)
                if isinstance(source, (bytes, bytearray))
                else Path(source),
            ) as archive,
        ):
            signature_name = EdocDocumentParser._find_signature_file(
                archive,
                Path("container"),
            )
            return parser._signer_certificate_name(archive, signature_name)
    except Exception:
        logger.warning(
            "Could not extract signer name from container",
            exc_info=True,
        )
        return None


def _as_text(value: bytes | str) -> str:
    """Coerce a certificate name attribute value to text.

    X.509 name attributes may be returned as ``bytes`` by ``cryptography``
    when the string type is not UTF-8; decode those so metadata values are
    always JSON-serialisable strings.
    """
    return value.decode("utf-8") if isinstance(value, bytes) else value


def _certificate_name_attributes(cert) -> tuple[str | None, str | None, str | None]:
    """Return ``(common_name, organization, country)`` of a certificate subject.

    Used both for the signature metadata tab and for resolving the signer
    as a potential correspondent during consumption.
    """
    from cryptography.x509 import NameOID

    def _name_attribute(oid) -> str | None:
        try:
            attributes = cert.subject.get_attributes_for_oid(oid)
            return _as_text(attributes[0].value) if attributes else None
        except Exception:  # pragma: no cover
            return None

    return (
        _name_attribute(NameOID.COMMON_NAME),
        _name_attribute(NameOID.ORGANIZATION_NAME),
        _name_attribute(NameOID.COUNTRY_NAME),
    )


def _parse_xml_datetime(value: str) -> datetime.datetime | None:
    """Parse an XML date/time string into an aware datetime.

    XAdES timestamps are typically given in UTC ("2026-07-02T09:52:01Z")
    but may carry a numeric offset.  Naive values are interpreted as UTC.

    Parameters
    ----------
    value:
        The date/time string.

    Returns
    -------
    datetime.datetime | None
        The parsed, timezone-aware datetime, or None on failure.
    """
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.UTC)
    return parsed


def _parse_pdf_date(value: str) -> datetime.datetime | None:
    """Parse a PDF date string ("D:YYYYMMDDHHMMSS+HH'mm'") into a datetime.

    Parameters
    ----------
    value:
        The PDF date string.

    Returns
    -------
    datetime.datetime | None
        The parsed UTC datetime, or None on failure.
    """
    match = _PDF_DATE_RE.match(value.strip())
    if match is None:
        return None
    year, month, day, hour, minute, second = (int(g) for g in match.groups())
    try:
        return datetime.datetime(
            year,
            month,
            day,
            hour,
            minute,
            second,
            tzinfo=datetime.UTC,
        )
    except ValueError:
        return None


#: Certificate common names that do not identify the signer.  Some
#: eParaksts mobile signing certificates use a generic subject
#: ("Private" / "Privātpersona") instead of the person's name, so the
#: common name alone cannot serve as a correspondent name then.
_PLACEHOLDER_CN_VALUES: frozenset[str] = frozenset(
    {"private", "privātpersona"},
)


def _find_embedded_certificates(der: bytes) -> list:
    """Extract X.509 certificates embedded in an arbitrary DER blob.

    Used to surface the timestamping authority certificate from an
    RFC 3161 timestamp token without a full ASN.1 parser: every plausible
    ``SEQUENCE`` length prefix is probed with ``cryptography`` and valid
    certificates are collected.  Best effort — invalid or truncated
    structures are skipped silently.

    Parameters
    ----------
    der:
        DER-encoded data (e.g. an encapsulated timestamp token).

    Returns
    -------
    list
        List of ``cryptography.x509.Certificate`` objects, in order of
        appearance.
    """
    from cryptography import x509

    found: list = []
    index = 0
    while index < len(der) - 4:
        if der[index] == 0x30 and der[index + 1] == 0x82:
            length = int.from_bytes(der[index + 2 : index + 4], "big")
            end = index + 4 + length
            if end <= len(der):
                try:
                    found.append(x509.load_der_x509_certificate(der[index:end]))
                except Exception:  # pragma: no cover - garbage data
                    index += 1
                    continue
                index = end
                continue
        index += 1
    return found


class EdocDocumentParser:
    """Parse EDOC 2.0 (ASiC-E) signed containers for Paperless-ngx.

    The signed PDF inside the container is extracted and used as the
    archive rendition, since browsers cannot display ZIP containers
    natively (``requires_pdf_rendition=True``).  The original container
    is archived untouched.  Text is extracted from the inner PDF, the
    document date is taken from the XAdES signing time, and the
    signature metadata (signer, certificate chain, timestamps,
    verification results) is exposed via ``extract_metadata``.

    Class attributes
    ----------------
    name : str
        Human-readable parser name.
    version : str
        Semantic version string, kept in sync with Paperless-ngx releases.
    author : str
        Maintainer name.
    url : str
        Issue tracker / source URL.
    """

    name: str = "Paperless-ngx EDOC Parser"
    version: str = __version__
    author: str = "Exerra"
    url: str = "https://github.com/Exerra/paperless-ngx-edoc"

    # ------------------------------------------------------------------
    # Class methods
    # ------------------------------------------------------------------

    @classmethod
    def supported_mime_types(cls) -> dict[str, str]:
        """Return the MIME types this parser handles.

        Returns
        -------
        dict[str, str]
            Mapping of MIME type to preferred file extension.
        """
        return _SUPPORTED_MIME_TYPES

    @classmethod
    def score(
        cls,
        mime_type: str,
        filename: str,
        path: Path | None = None,
    ) -> int | None:
        """Return the priority score for handling this file.

        The MIME type is ``application/zip`` for every ZIP archive, so
        the file's actual content decides: when *path* is available the
        container's ``mimetype`` entry is inspected (:func:`is_edoc_container`).
        When no path is given (the API/mail validation paths call this
        with ``filename=""``), the filename extension is the only signal
        and any ``application/zip`` file is accepted so that ASiC-E
        uploads pass validation; plain ZIPs are then rejected during
        consumption with a clear error message.

        Parameters
        ----------
        mime_type:
            Detected MIME type of the file.
        filename:
            Original filename including extension.
        path:
            Optional filesystem path of the file.

        Returns
        -------
        int | None
            10 when the file is (or may be) an ASiC-E container,
            otherwise None.
        """
        if mime_type not in _SUPPORTED_MIME_TYPES:
            return None
        if path is not None:
            return 10 if is_edoc_container(path) else None
        return 10

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def can_produce_archive(self) -> bool:
        """Whether this parser can produce a searchable PDF archive copy.

        Returns
        -------
        bool
            Always False — the EDOC parser produces a display PDF
            (requires_pdf_rendition=True), not an optional OCR archive.
        """
        return False

    @property
    def requires_pdf_rendition(self) -> bool:
        """Whether the parser must produce a PDF for the frontend to display.

        Returns
        -------
        bool
            Always True — EDOC containers (ZIP archives) cannot be
            rendered natively in a browser, so the inner PDF is always
            extracted for display.
        """
        return True

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def __init__(self, logging_group: object = None) -> None:
        settings.SCRATCH_DIR.mkdir(parents=True, exist_ok=True)
        self._tempdir = Path(
            tempfile.mkdtemp(prefix="paperless-", dir=settings.SCRATCH_DIR),
        )
        self._text: str | None = None
        self._date: datetime.datetime | None = None
        self._archive_path: Path | None = None
        self._signer_name: str | None = None

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        logger.debug("Cleaning up temporary directory %s", self._tempdir)
        shutil.rmtree(self._tempdir, ignore_errors=True)

    # ------------------------------------------------------------------
    # Core parsing interface
    # ------------------------------------------------------------------

    def configure(self, context: ParserContext) -> None:
        pass

    def parse(
        self,
        document_path: Path,
        mime_type: str,
        *,
        produce_archive: bool = True,
    ) -> None:
        """Extract the signed PDF(s) and text from the EDOC container.

        Every document inside the container is ingested: the inner PDFs
        (directly, or inside nested EDOC containers) are merged with the
        office documents (DOCX, ODT, ...) converted to PDF via Gotenberg
        into a single rendition PDF, and the text of every document is
        combined for search.  When Gotenberg/Tika are unavailable the
        DOCX text is still extracted locally and the affected pages are
        omitted from the rendition (with a warning) — consumption never
        fails because of a missing external service.

        The ``produce_archive`` flag is accepted for protocol
        compatibility but always honoured — the PDF rendition is always
        produced since EDOC containers cannot be displayed natively.
        Nested containers ("EDOC within EDOC", as produced by the Latvian
        e-archive) are descended into to reach the actual PDF.

        Parameters
        ----------
        document_path:
            Absolute path to the ``.edoc`` file.
        mime_type:
            Detected MIME type of the document.
        produce_archive:
            Accepted for protocol compatibility; the rendition is always
            produced.

        Raises
        ------
        documents.parsers.ParseError
            If the container is invalid or contains no PDF document.
        """
        logger.debug("Parsing file %s into an EDOC container", document_path.name)

        archive_path: Path | None = None
        pdf_parts: list[Path] = []
        text_parts: list[tuple[str, str]] = []
        try:
            with zipfile.ZipFile(document_path) as archive:
                self._validate_container(archive, document_path)

                signature_name = self._find_signature_file(archive, document_path)
                # The signing time of the first signature is used as the
                # document date. EDOC 2.0 supports parallel signatures
                # (multiple co-signers); later signatures are still exposed
                # via extract_metadata (signature_count).
                self._date = self._signing_time(archive, signature_name)
                # The signer of the first signature is exposed as a
                # potential correspondent for consumption-time assignment.
                self._signer_name = self._signer_certificate_name(
                    archive,
                    signature_name,
                )

                for index, name in enumerate(
                    self._collect_documents(archive, signature_name),
                ):
                    pdf_bytes = self._document_pdf_bytes(
                        archive,
                        name,
                        document_path,
                    )
                    part_path: Path | None = None
                    if pdf_bytes is not None:
                        part_path = self._tempdir / f"document-part-{index}.pdf"
                        part_path.write_bytes(pdf_bytes)
                        pdf_parts.append(part_path)
                    text = self._document_text(archive, name, part_path)
                    if text:
                        text_parts.append((name, text))

            if not pdf_parts:
                raise ParseError(
                    f"{document_path}: container contains no PDF document",
                )
            archive_path = self._tempdir / "document.pdf"
            self._merge_pdfs(pdf_parts, archive_path)
        except ParseError:
            raise
        except Exception as err:
            raise ParseError(
                f"Could not parse EDOC container {document_path}: {err}",
            ) from err

        self._archive_path = archive_path

        if self._date is None:
            self._date = self._pdf_creation_date(archive_path)

        from paperless.parsers.utils import post_process_text

        if len(text_parts) == 1:
            self._text = post_process_text(text_parts[0][1]) or ""
        elif text_parts:
            self._text = (
                post_process_text(
                    "\n\n".join(f"=== {name} ===\n{text}" for name, text in text_parts),
                )
                or ""
            )
        else:
            self._text = ""

        if not self._text:
            logger.warning(
                "No text extracted from the documents inside %s — they "
                "may be scanned images",
                document_path.name,
            )

    # ------------------------------------------------------------------
    # Result accessors
    # ------------------------------------------------------------------

    def get_text(self) -> str:
        """Return the plain-text content extracted during parse.

        Returns
        -------
        str
            Text of the documents inside the container (PDFs and office
            documents, merged with per-document headers), or an empty
            string if no text could be found.
        """
        return self._text or ""

    def get_date(self) -> datetime.datetime | None:
        """Return the document date detected during parse.

        Returns
        -------
        datetime.datetime | None
            The XAdES signing time (falling back to the inner PDF's
            creation date), or None if neither could be determined.
        """
        return self._date

    def get_archive_path(self) -> Path | None:
        """Return the path to the extracted PDF rendition, or None.

        Returns
        -------
        Path | None
            Path to the extracted inner PDF, or None if parse() has not
            been called yet.
        """
        return self._archive_path

    def get_signer_name(self) -> str | None:
        """Return a name for the signer of the first signature, or None.

        The signer's organization is preferred over the certificate
        common name, since Latvian individual certificates embed a
        personal code in the CN.

        Returns
        -------
        str | None
            The signer's organization or common name, or None if parse()
            has not been called yet or the signer could not be resolved.
        """
        return self._signer_name

    # ------------------------------------------------------------------
    # Thumbnail and metadata
    # ------------------------------------------------------------------

    def get_thumbnail(
        self,
        document_path: Path,
        mime_type: str,
        file_name: str | None = None,
    ) -> Path:
        """Generate a thumbnail from the PDF rendition.

        Extracts the inner PDF first if not already done.

        Parameters
        ----------
        document_path:
            Absolute path to the source document.
        mime_type:
            Detected MIME type of the document.
        file_name:
            Kept for backward compatibility; not used.

        Returns
        -------
        Path
            Path to the generated WebP thumbnail inside the temporary
            directory.
        """
        if not self._archive_path:
            self.parse(document_path, mime_type)

        return make_thumbnail_from_pdf(
            self._archive_path or document_path,
            self._tempdir,
        )

    def get_page_count(
        self,
        document_path: Path,
        mime_type: str,
    ) -> int | None:
        """Return the number of pages in the document.

        Counts pages in the extracted PDF from a preceding parse() call.
        Returns ``None`` if parse() has not been called yet or if no
        rendition was produced.

        Returns
        -------
        int | None
            Page count of the inner PDF, or ``None``.
        """
        if self._archive_path is not None:
            from paperless.parsers.utils import get_page_count_for_pdf

            return get_page_count_for_pdf(self._archive_path, log=logger)
        return None

    def extract_metadata(
        self,
        document_path: Path,
        mime_type: str,
    ) -> list[MetadataEntry]:
        """Extract container and XAdES signature metadata.

        Returns container entries (mimetype, manifest file list) and
        signature entries (signing time, signer certificate, certificate
        chain, algorithms, timestamp and OCSP information, and
        cryptographic verification results).  Verification is performed
        offline: the signed PDF's digest is compared against the
        signature reference and the signature value is checked against
        the canonicalised ``SignedInfo``.

        Returns
        -------
        list[MetadataEntry]
            Sorted list of metadata entries, or ``[]`` on parse failure.
        """
        result: list[MetadataEntry] = []

        if mime_type == "application/pdf":
            return result

        try:
            with zipfile.ZipFile(document_path) as archive:
                self._append_container_metadata(archive, result)
                signature_name = self._find_signature_file(archive, document_path)
                self._append_signature_metadata(archive, signature_name, result)
        except Exception as err:
            logger.warning(
                "Error while fetching document metadata for %s: %s",
                document_path,
                err,
            )
            return result

        result.sort(key=lambda item: (item["prefix"], item["key"]))
        return result

    # ------------------------------------------------------------------
    # Container helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_container(archive: zipfile.ZipFile, path: Path) -> None:
        """Raise ParseError unless the archive is a valid EDOC 2.0 container."""
        try:
            mimetype = (
                archive.read("mimetype").decode("utf-8", errors="replace").strip()
            )
        except KeyError:
            raise ParseError(
                f"{path}: not an EDOC 2.0 container: missing 'mimetype' entry",
            )
        if mimetype != EDOC_CONTAINER_MIME_TYPE:
            raise ParseError(
                f"{path}: not an EDOC 2.0 container: "
                f"'mimetype' entry is {mimetype!r}, expected "
                f"{EDOC_CONTAINER_MIME_TYPE!r}",
            )

    @staticmethod
    def _find_signature_file(
        archive: zipfile.ZipFile,
        path: Path,
    ) -> str:
        """Return the name of the XAdES signature file inside the container."""
        signature_files = [
            name for name in archive.namelist() if _SIGNATURE_FILE_RE.match(name)
        ]
        if not signature_files:
            raise ParseError(f"{path}: container contains no XAdES signature file")
        return signature_files[0]

    @staticmethod
    def _is_pdf_entry(archive: zipfile.ZipFile, name: str) -> bool:
        """Return True if the zip entry starts with PDF magic bytes.

        Reads only the first four bytes instead of loading the whole entry.
        """
        try:
            with archive.open(name) as entry:
                return entry.read(4) == b"%PDF"
        except Exception:  # pragma: no cover
            return False

    @staticmethod
    def _is_nested_edoc_entry(archive: zipfile.ZipFile, name: str) -> bool:
        """Return True if the zip entry is itself an EDOC container.

        Used for the nested containers ("EDOC within EDOC") produced by
        the Latvian e-archive: the outer container wraps documents and
        one or more inner containers that carry the actual PDFs.
        """
        try:
            return is_edoc_container(archive.read(name))
        except Exception:  # pragma: no cover
            return False

    def _extract_inner_pdf(
        self,
        container_data: bytes,
        path: Path,
        *,
        _depth: int = 0,
    ) -> bytes:
        """Return the bytes of the PDF inside a nested EDOC container.

        Nested containers hold the actual signed PDF one or more levels
        down; the same document-selection rules as at the top level are
        applied inside each nested container.

        Parameters
        ----------
        container_data:
            Raw bytes of the nested EDOC container.
        path:
            Path of the outermost container, used in error messages.

        Raises
        ------
        documents.parsers.ParseError
            If no PDF can be found inside the nested container.
        """
        if _depth > 8:  # pragma: no cover - defensive
            raise ParseError(f"{path}: EDOC containers nested too deeply")
        with zipfile.ZipFile(io.BytesIO(container_data)) as inner:
            signature_names = [
                name for name in inner.namelist() if _SIGNATURE_FILE_RE.match(name)
            ]
            signature_name = signature_names[0] if signature_names else ""
            entry = self._find_document_file(inner, path, signature_name)
            if self._is_pdf_entry(inner, entry):
                return inner.read(entry)
            return self._extract_inner_pdf(
                inner.read(entry),
                path,
                _depth=_depth + 1,
            )

    @staticmethod
    def _is_office_entry(archive: zipfile.ZipFile, name: str) -> bool:
        """Return True if the zip entry is an office document.

        Detects OpenXML documents (DOCX/XLSX/PPTX) via their
        ``[Content_Types].xml``, ODF documents via their ``mimetype``
        entry, and legacy OLE compound documents (DOC/XLS/PPT) via their
        magic bytes.
        """
        try:
            with archive.open(name) as entry:
                head = entry.read(8)
            if head[:4] == b"PK\x03\x04":
                with zipfile.ZipFile(io.BytesIO(archive.read(name))) as inner:
                    if "[Content_Types].xml" in inner.namelist():
                        content_types = (
                            inner.read(
                                "[Content_Types].xml",
                            )
                            .decode("utf-8", errors="replace")
                            .lower()
                        )
                        return any(
                            fragment in content_types
                            for fragment in _OFFICE_OPENXML_FRAGMENTS
                        )
                    if "mimetype" in inner.namelist():
                        mimetype = inner.read("mimetype").decode(
                            "utf-8",
                            errors="replace",
                        )
                        return mimetype.startswith(
                            "application/vnd.oasis.opendocument",
                        )
            elif head[:4] == b"\xd0\xcf\x11\xe0":
                # Legacy OLE compound documents (DOC/XLS/PPT).
                return True
        except Exception:  # pragma: no cover
            pass
        return False

    @staticmethod
    def _is_docx_data(data: bytes) -> bool:
        """Return True if *data* is a DOCX (OpenXML wordprocessing) file."""
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                if "[Content_Types].xml" not in archive.namelist():
                    return False
                return b"wordprocessingml" in archive.read("[Content_Types].xml")
        except Exception:
            return False

    @staticmethod
    def _docx_text(data: bytes) -> str:
        """Extract plain text from a DOCX file without external services.

        Reads ``word/document.xml`` and concatenates the text of every
        paragraph (``<w:p>`` / ``<w:t>``).  Returns an empty string when
        the file is not a readable DOCX.
        """
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                if "word/document.xml" not in archive.namelist():
                    return ""
                root = ET.fromstring(archive.read("word/document.xml"))
        except Exception:
            return ""
        paragraphs: list[str] = []
        for paragraph in root.iter(f"{{{_WORD_MAIN_NS}}}p"):
            text = "".join(
                node.text or "" for node in paragraph.iter(f"{{{_WORD_MAIN_NS}}}t")
            )
            if text.strip():
                paragraphs.append(text)
        return "\n".join(paragraphs)

    @classmethod
    def _collect_documents(
        cls,
        archive: zipfile.ZipFile,
        signature_name: str,
    ) -> list[str]:
        """Return every document entry inside the container, in order.

        The entries are ordered by preference:

        1. the entries referenced by the XAdES signature (signing order),
        2. the entries listed in the ODF-style manifest,
        3. any remaining non-metadata entries.

        Duplicates are removed.  The list may contain PDFs, nested EDOC
        containers and office documents; see :meth:`_document_pdf_bytes`.
        """
        result: list[str] = []
        for name in cls._signed_document_candidates(archive, signature_name):
            if name not in result:
                result.append(name)

        manifest_names = [
            name for name in archive.namelist() if name == "META-INF/manifest.xml"
        ]
        if manifest_names:
            try:
                manifest_root = ET.fromstring(archive.read(manifest_names[0]))
            except Exception:
                manifest_root = None
            if manifest_root is not None:
                for entry in manifest_root.iter(f"{{{_OD_MANIFEST_NS}}}file-entry"):
                    entry_path = entry.get(f"{{{_OD_MANIFEST_NS}}}full-path")
                    if (
                        entry_path
                        and entry_path != "/"
                        and entry_path in archive.namelist()
                        and entry_path not in result
                    ):
                        result.append(entry_path)

        for name in archive.namelist():
            if name == "mimetype" or name.startswith("META-INF/") or name.endswith("/"):
                continue
            if name not in result:
                result.append(name)
        return result

    def _document_pdf_bytes(
        self,
        archive: zipfile.ZipFile,
        name: str,
        path: Path,
    ) -> bytes | None:
        """Return PDF bytes for a container entry, or None if not renderable.

        PDF entries are used directly, nested EDOC containers are
        descended into, and office documents are converted to PDF via
        Gotenberg (None when the conversion is unavailable).
        """
        if self._is_pdf_entry(archive, name):
            with archive.open(name) as entry:
                return entry.read()
        if self._is_nested_edoc_entry(archive, name):
            return self._extract_inner_pdf(archive.read(name), path)
        if self._is_office_entry(archive, name):
            return self._office_to_pdf(archive, name)
        return None

    def _document_text(
        self,
        archive: zipfile.ZipFile,
        name: str,
        pdf_path: Path | None,
    ) -> str:
        """Return the text of a container entry, or an empty string.

        Office documents are sent to Tika when available and fall back to
        a local DOCX XML extraction; PDF-derived entries are read from
        *pdf_path* with pdftotext.
        """
        if self._is_office_entry(archive, name):
            return self._office_text(archive, name)
        if pdf_path is not None:
            from paperless.parsers.utils import extract_pdf_text

            return extract_pdf_text(pdf_path, log=logger) or ""
        return ""

    def _office_text(self, archive: zipfile.ZipFile, name: str) -> str:
        """Best-effort text for an office entry: Tika, then DOCX fallback."""
        data = archive.read(name)
        if settings.TIKA_ENDPOINT:
            try:
                from tika_client import TikaClient

                with TikaClient(
                    tika_url=settings.TIKA_ENDPOINT,
                    timeout=settings.CELERY_TASK_TIME_LIMIT,
                ) as client:
                    parsed = client.tika.as_text.from_buffer(
                        data,
                        mimetypes.guess_type(name)[0],
                    )
                if parsed.content and parsed.content.strip():
                    return parsed.content
            except Exception as err:
                logger.warning(
                    "Tika text extraction failed for %s: %s",
                    name,
                    err,
                )
        if self._is_docx_data(data):
            return self._docx_text(data)
        return ""

    def _office_to_pdf(
        self,
        archive: zipfile.ZipFile,
        name: str,
    ) -> bytes | None:
        """Convert an office entry to PDF via Gotenberg, or None on failure."""
        if not settings.TIKA_GOTENBERG_ENDPOINT:
            return None
        source_path = self._tempdir / Path(name).name
        try:
            source_path.write_bytes(archive.read(name))

            from gotenberg_client import GotenbergClient

            with (
                GotenbergClient(
                    host=settings.TIKA_GOTENBERG_ENDPOINT,
                    timeout=settings.CELERY_TASK_TIME_LIMIT,
                ) as client,
                client.libre_office.to_pdf() as route,
            ):
                # Preserve document fields as authored (see the Tika
                # parser for details).
                route.update_indexes(update_indexes=False)
                route.convert(source_path)
                response = route.run()
            return response.content
        except Exception as err:
            logger.warning(
                "Could not convert %s to PDF via Gotenberg: %s",
                name,
                err,
            )
            return None

    @staticmethod
    def _merge_pdfs(pdf_paths: list[Path], target: Path) -> None:
        """Merge PDF files into *target*.

        A single input is copied verbatim; multiple inputs are combined
        by appending pages with pikepdf (local, no external services).
        """
        if len(pdf_paths) == 1:
            shutil.copyfile(pdf_paths[0], target)
            return
        import pikepdf

        with pikepdf.open(pdf_paths[0]) as merged:
            for path in pdf_paths[1:]:
                with pikepdf.open(path) as other:
                    merged.pages.extend(other.pages)
            merged.save(target)

    @classmethod
    def _signed_document_candidates(
        cls,
        archive: zipfile.ZipFile,
        signature_name: str,
    ) -> list[str]:
        """Return the container entries referenced by the XAdES signature.

        The signature's ``ds:Reference`` URI identifies the signed data
        object; preferring it over the manifest prevents extracting the
        wrong file from multi-file containers.  Percent-encoding, fragments
        and leading slashes are tolerated.  Returns an empty list when the
        signature cannot be parsed or references nothing inside the
        container.
        """
        try:
            root = ET.fromstring(archive.read(signature_name))
        except Exception:
            return []
        candidates: list[str] = []
        for reference in root.findall(f".//{{{_XMLDSIG_NS}}}Reference"):
            uri = reference.get("URI", "")
            if not uri or uri.startswith("#") or "://" in uri:
                continue
            raw_name = uri.split("#", 1)[0].split("?", 1)[0].lstrip("/")
            for candidate in (raw_name, urllib.parse.unquote(raw_name)):
                if candidate and candidate in archive.namelist():
                    candidates.append(candidate)
        return list(dict.fromkeys(candidates))

    @classmethod
    def _find_document_file(
        cls,
        archive: zipfile.ZipFile,
        path: Path,
        signature_name: str,
    ) -> str:
        """Return the name of the signed document inside the container.

        The document is located in order of preference:

        1. the entry referenced by the XAdES signature,
        2. PDF entries listed in the ODF-style manifest,
        3. any remaining non-metadata entry with PDF magic bytes.

        The entry may be the PDF itself or a nested EDOC container
        ("EDOC within EDOC", as produced by the Latvian e-archive); in
        the latter case :meth:`parse` descends into the nested container
        to extract the PDF it contains.
        """
        for candidate in cls._signed_document_candidates(archive, signature_name):
            if cls._is_pdf_entry(archive, candidate):
                return candidate
            if cls._is_nested_edoc_entry(archive, candidate):
                return candidate

        manifest_names = [
            name for name in archive.namelist() if name == "META-INF/manifest.xml"
        ]
        if manifest_names:
            try:
                manifest_root = ET.fromstring(archive.read(manifest_names[0]))
            except Exception as err:
                raise ParseError(f"{path}: could not parse container manifest: {err}")
            for entry in manifest_root.iter(f"{{{_OD_MANIFEST_NS}}}file-entry"):
                entry_path = entry.get(f"{{{_OD_MANIFEST_NS}}}full-path")
                media_type = entry.get(f"{{{_OD_MANIFEST_NS}}}media-type")
                if (
                    entry_path
                    and entry_path != "/"
                    and entry_path in archive.namelist()
                ):
                    if media_type == "application/pdf" and cls._is_pdf_entry(
                        archive,
                        entry_path,
                    ):
                        return entry_path
                    if cls._is_nested_edoc_entry(archive, entry_path):
                        return entry_path

        for name in archive.namelist():
            if name == "mimetype" or name.startswith("META-INF/") or name.endswith("/"):
                continue
            if cls._is_pdf_entry(archive, name):
                return name
            if cls._is_nested_edoc_entry(archive, name):
                return name

        raise ParseError(f"{path}: container contains no PDF document")

    @staticmethod
    def _pdf_creation_date(pdf_path: Path) -> datetime.datetime | None:
        """Return the creation date of a PDF, if present."""
        try:
            import pikepdf

            with pikepdf.open(pdf_path) as pdf:
                creation_date = pdf.docinfo.get("/CreationDate")
                if creation_date is None:
                    return None
                return _parse_pdf_date(str(creation_date))
        except Exception:
            return None

    @staticmethod
    def _signing_time(
        archive: zipfile.ZipFile,
        signature_name: str,
    ) -> datetime.datetime | None:
        """Return the XAdES signing time, or None."""
        try:
            root = ET.fromstring(archive.read(signature_name))
            element = root.find(f".//{{{_XADES_NS}}}SigningTime")
            if element is not None and element.text:
                return _parse_xml_datetime(element.text.strip())
        except Exception:
            logger.warning(
                "Could not read signing time from %s",
                signature_name,
                exc_info=True,
            )
        return None

    def _signer_certificate_name(
        self,
        archive: zipfile.ZipFile,
        signature_name: str,
    ) -> str | None:
        """Return the signer's organization or common name, or None.

        Resolves the signer certificate of the first signature (via
        ``KeyInfo`` or the ``SigningCertificate`` digest) and prefers the
        organization attribute over the common name, mirroring the
        metadata exposed by ``_append_certificate_metadata``.  Placeholder
        common names (e.g. "Private" on some eParaksts mobile certificates)
        are not usable as a name.  Best effort — any failure is logged and
        None is returned so that parsing itself never fails because of it.
        """
        try:
            from lxml import etree

            root = etree.fromstring(archive.read(signature_name))
            signatures = root.findall(f"{{{_XMLDSIG_NS}}}Signature")
            if not signatures:
                return None
            signature = signatures[0]
            cert_der = signature.findtext(
                f"{{{_XMLDSIG_NS}}}KeyInfo/{{{_XMLDSIG_NS}}}X509Data/"
                f"{{{_XMLDSIG_NS}}}X509Certificate",
            )
            signer_cert = self._find_signer_cert(signature, cert_der)
            if signer_cert is None:
                return None
            from cryptography import x509

            cert = x509.load_der_x509_certificate(base64.b64decode(signer_cert))
            common_name, organization, _ = _certificate_name_attributes(cert)
            if organization:
                return organization
            if (
                common_name
                and common_name.strip().lower() not in _PLACEHOLDER_CN_VALUES
            ):
                return common_name
            return None
        except Exception as err:
            logger.warning("Could not resolve signer name: %s", err)
            return None

    # ------------------------------------------------------------------
    # Metadata helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _append_container_metadata(
        archive: zipfile.ZipFile,
        result: list[MetadataEntry],
    ) -> None:
        """Append container-level metadata (mimetype, manifest entries)."""
        mimetype = archive.read("mimetype").decode("utf-8", errors="replace").strip()
        result.append(
            {
                "namespace": "",
                "prefix": "container",
                "key": "mimetype",
                "value": mimetype,
            },
        )

        manifest_names = [
            name for name in archive.namelist() if name == "META-INF/manifest.xml"
        ]
        if not manifest_names:
            return
        try:
            manifest_root = ET.fromstring(archive.read(manifest_names[0]))
        except Exception as err:  # pragma: no cover
            logger.warning("Could not parse container manifest: %s", err)
            return
        for entry in manifest_root.iter(f"{{{_OD_MANIFEST_NS}}}file-entry"):
            entry_path = entry.get(f"{{{_OD_MANIFEST_NS}}}full-path")
            media_type = entry.get(f"{{{_OD_MANIFEST_NS}}}media-type")
            if entry_path and entry_path != "/":
                result.append(
                    {
                        "namespace": "",
                        "prefix": "container",
                        "key": entry_path,
                        "value": media_type or "unknown",
                    },
                )

    def _append_signature_metadata(
        self,
        archive: zipfile.ZipFile,
        signature_name: str,
        result: list[MetadataEntry],
    ) -> None:
        """Append XAdES signature metadata and verification results."""
        try:
            # lxml elements are required for the exclusive-c14n
            # verification step; its find/findall/findtext API matches
            # xml.etree.ElementTree.
            from lxml import etree

            root = etree.fromstring(archive.read(signature_name))
        except Exception as err:
            logger.warning("Could not parse XAdES signature file: %s", err)
            return

        signatures = root.findall(f"{{{_XMLDSIG_NS}}}Signature")
        if not signatures:
            return
        signature = signatures[0]

        result.append(
            {
                "namespace": "",
                "prefix": "signature",
                "key": "signature_count",
                "value": str(len(signatures)),
            },
        )

        signing_time = signature.find(
            f".//{{{_XADES_NS}}}SigningTime",
        )
        if signing_time is not None and isinstance(signing_time.text, str):
            result.append(
                {
                    "namespace": "",
                    "prefix": "signature",
                    "key": "signing_time",
                    "value": signing_time.text.strip(),
                },
            )

        signature_method = signature.find(
            f".//{{{_XMLDSIG_NS}}}SignatureMethod",
        )
        if signature_method is not None:
            algorithm = signature_method.get("Algorithm", "")
            result.append(
                {
                    "namespace": "",
                    "prefix": "signature",
                    "key": "signature_algorithm",
                    "value": _SIGNATURE_ALGORITHMS.get(algorithm, algorithm),
                },
            )

        signed_info = signature.find(f"{{{_XMLDSIG_NS}}}SignedInfo")
        signature_value = signature.findtext(f"{{{_XMLDSIG_NS}}}SignatureValue")
        cert_der = signature.findtext(
            f"{{{_XMLDSIG_NS}}}KeyInfo/{{{_XMLDSIG_NS}}}X509Data/"
            f"{{{_XMLDSIG_NS}}}X509Certificate",
        )

        # The signer certificate usually sits in KeyInfo, but XAdES also
        # allows it to live only in the CertificateValues; resolve it via
        # the SigningCertificate digest in that case.
        signer_cert = self._find_signer_cert(signature, cert_der)

        self._append_certificate_metadata(signer_cert, result)

        if (
            signed_info is not None
            and signature_value is not None
            and signer_cert is not None
        ):
            self._append_verification_metadata(
                archive,
                signature,
                signature_value,
                signer_cert,
                result,
            )

        self._append_unsigned_metadata(signature, result)

    def _find_signer_cert(
        self,
        signature,
        cert_der_b64: str | None,
    ) -> str | None:
        """Return the base64 signer certificate for the signature.

        Returns *cert_der_b64* directly when KeyInfo carries the
        certificate; otherwise the certificate listed in
        ``CertificateValues`` whose digest matches the
        ``SigningCertificate``/``SigningCertificateV2`` digest is
        returned.  Returns None if it cannot be determined.
        """
        if cert_der_b64:
            return cert_der_b64
        try:
            cert_digest = signature.find(
                f".//{{{_XADES_NS}}}SigningCertificateV2/"
                f"{{{_XADES_NS}}}Cert/{{{_XADES_NS}}}CertDigest",
            )
            if cert_digest is None:
                cert_digest = signature.find(
                    f".//{{{_XADES_NS}}}SigningCertificate/"
                    f"{{{_XADES_NS}}}Cert/{{{_XADES_NS}}}CertDigest",
                )
            if cert_digest is None:
                return None
            digest_method = cert_digest.find(f"{{{_XMLDSIG_NS}}}DigestMethod")
            digest_algorithm = (
                digest_method.get("Algorithm", "") if digest_method is not None else ""
            )
            digest_name = _DIGEST_ALGORITHMS.get(digest_algorithm)
            digest_value = cert_digest.findtext(f"{{{_XMLDSIG_NS}}}DigestValue")
            if digest_name is None or digest_value is None:
                return None
            expected = base64.b64decode(digest_value)
            for encoded in signature.findall(
                f".//{{{_XADES_NS}}}CertificateValues/"
                f"{{{_XADES_NS}}}EncapsulatedX509Certificate",
            ):
                der = base64.b64decode(encoded.text or "")
                if hashlib.new(digest_name, der).digest() == expected:
                    return base64.b64encode(der).decode("ascii")
        except Exception as err:  # pragma: no cover
            logger.warning("Could not resolve signer certificate: %s", err)
        return None

    def _append_certificate_metadata(
        self,
        cert_der_b64: str | None,
        result: list[MetadataEntry],
    ) -> None:
        """Append signer certificate details."""
        if not cert_der_b64:
            return
        try:
            from cryptography import x509
            from cryptography.x509 import NameOID

            cert = x509.load_der_x509_certificate(base64.b64decode(cert_der_b64))
        except Exception as err:  # pragma: no cover
            logger.warning("Could not parse signer certificate: %s", err)
            return

        common_name, organization, country = _certificate_name_attributes(cert)

        if common_name:
            result.append(
                {
                    "namespace": "",
                    "prefix": "signature",
                    "key": "signer_name",
                    "value": common_name,
                },
            )
        if organization and organization != common_name:
            result.append(
                {
                    "namespace": "",
                    "prefix": "signature",
                    "key": "signer_organization",
                    "value": organization,
                },
            )
        if country:
            result.append(
                {
                    "namespace": "",
                    "prefix": "signature",
                    "key": "signer_country",
                    "value": country,
                },
            )

        issuer = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        if issuer:
            result.append(
                {
                    "namespace": "",
                    "prefix": "signature",
                    "key": "signer_certificate_issuer",
                    "value": _as_text(issuer[0].value),
                },
            )
        result.append(
            {
                "namespace": "",
                "prefix": "signature",
                "key": "signer_certificate_serial",
                "value": str(cert.serial_number),
            },
        )
        result.append(
            {
                "namespace": "",
                "prefix": "signature",
                "key": "signer_certificate_valid_from",
                "value": cert.not_valid_before_utc.isoformat(),
            },
        )
        result.append(
            {
                "namespace": "",
                "prefix": "signature",
                "key": "signer_certificate_valid_to",
                "value": cert.not_valid_after_utc.isoformat(),
            },
        )

    def _append_unsigned_metadata(
        self,
        signature,
        result: list[MetadataEntry],
    ) -> None:
        """Append timestamp / certificate chain / revocation metadata."""
        unsigned_props = signature.find(
            f".//{{{_XADES_NS}}}UnsignedProperties/"
            f"{{{_XADES_NS}}}UnsignedSignatureProperties",
        )
        if unsigned_props is None:
            return

        certificate_values = unsigned_props.findall(
            f"{{{_XADES_NS}}}CertificateValues/"
            f"{{{_XADES_NS}}}EncapsulatedX509Certificate",
        )
        if certificate_values:
            result.append(
                {
                    "namespace": "",
                    "prefix": "signature",
                    "key": "certificate_count",
                    "value": str(len(certificate_values)),
                },
            )
            try:
                from cryptography import x509
                from cryptography.x509 import NameOID

                chain: list[str] = []
                seen: set[bytes] = set()
                for encoded in certificate_values:
                    der = base64.b64decode(encoded.text or "")
                    if der in seen:  # pragma: no cover
                        continue
                    seen.add(der)
                    cert = x509.load_der_x509_certificate(der)
                    names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                    if names:
                        value = names[0].value
                        chain.append(
                            value.decode("utf-8")
                            if isinstance(value, bytes)
                            else value,
                        )
                    else:
                        chain.append(str(cert.serial_number))
                if chain:
                    result.append(
                        {
                            "namespace": "",
                            "prefix": "signature",
                            "key": "certificate_chain",
                            "value": " > ".join(chain),
                        },
                    )
            except Exception as err:  # pragma: no cover
                logger.warning("Could not parse certificate chain: %s", err)

        ocsp_values = unsigned_props.findall(
            f"{{{_XADES_NS}}}RevocationValues/"
            f"{{{_XADES_NS}}}OCSPValues/"
            f"{{{_XADES_NS}}}EncapsulatedOCSPValue",
        )
        if ocsp_values:
            result.append(
                {
                    "namespace": "",
                    "prefix": "signature",
                    "key": "ocsp_response_count",
                    "value": str(len(ocsp_values)),
                },
            )

        signature_timestamp = unsigned_props.find(
            f"{{{_XADES_NS}}}SignatureTimeStamp",
        )
        if signature_timestamp is not None:
            result.append(
                {
                    "namespace": "",
                    "prefix": "timestamp",
                    "key": "signature_timestamp",
                    "value": "present",
                },
            )
            timestamp_token = signature_timestamp.findtext(
                f"{{{_XADES_NS}}}EncapsulatedTimeStamp",
            )
            if timestamp_token:
                try:
                    from cryptography import x509
                    from cryptography.x509 import NameOID

                    certificates = _find_embedded_certificates(
                        base64.b64decode(timestamp_token),
                    )
                    for cert in certificates:
                        names = cert.subject.get_attributes_for_oid(
                            NameOID.COMMON_NAME,
                        )
                        if names:
                            result.append(
                                {
                                    "namespace": "",
                                    "prefix": "timestamp",
                                    "key": "timestamp_authority",
                                    "value": _as_text(names[0].value),
                                },
                            )
                            break
                except Exception as err:  # pragma: no cover
                    logger.warning("Could not parse timestamp token: %s", err)

    def _append_verification_metadata(
        self,
        archive: zipfile.ZipFile,
        signature,
        signature_value: str,
        cert_der_b64: str,
        result: list[MetadataEntry],
    ) -> None:
        """Append offline cryptographic verification results.

        Three checks are performed, all without any network access:

        * the digest of every referenced document inside the container is
          compared against its ``ds:DigestValue``,
        * the digest of the ``SignedProperties`` element is compared
          against its ``ds:DigestValue``, and
        * the signature value is verified against the canonicalisation
          of ``SignedInfo`` declared in ``ds:CanonicalizationMethod``
          (exclusive c14n or inclusive c14n 1.0/1.1) using the signer
          certificate.
        """
        signed_info = signature.find(f"{{{_XMLDSIG_NS}}}SignedInfo")
        if signed_info is None:  # pragma: no cover
            return

        digest_method = signed_info.find(
            f".//{{{_XMLDSIG_NS}}}DigestMethod",
        )
        digest_algorithm = (
            digest_method.get("Algorithm", "") if digest_method is not None else ""
        )
        digest_name = _DIGEST_ALGORITHMS.get(digest_algorithm)
        if digest_name:
            result.append(
                {
                    "namespace": "",
                    "prefix": "signature",
                    "key": "digest_algorithm",
                    "value": digest_name,
                },
            )

        document_digest_valid: bool | None = None
        for reference in signed_info.findall(f"{{{_XMLDSIG_NS}}}Reference"):
            uri = reference.get("URI", "")
            if uri.startswith("#"):
                continue
            digest_value = reference.findtext(f"{{{_XMLDSIG_NS}}}DigestValue")
            ref_digest_method = reference.find(f"{{{_XMLDSIG_NS}}}DigestMethod")
            ref_digest_name = _DIGEST_ALGORITHMS.get(
                ref_digest_method.get("Algorithm", "")
                if ref_digest_method is not None
                else "",
            )
            if digest_value is None or ref_digest_name is None:
                continue
            try:
                digest = hashlib.new(ref_digest_name)
                with archive.open(uri) as entry:
                    for chunk in iter(lambda: entry.read(65536), b""):
                        digest.update(chunk)
                valid = digest.digest() == base64.b64decode(digest_value)
                document_digest_valid = (
                    valid
                    if document_digest_valid is None
                    else document_digest_valid and valid
                )
            except Exception as err:  # pragma: no cover
                logger.warning("Could not verify document digest %s: %s", uri, err)
        if document_digest_valid is not None:
            result.append(
                {
                    "namespace": "",
                    "prefix": "signature",
                    "key": "document_digest_valid",
                    "value": str(document_digest_valid).lower(),
                },
            )

        signed_properties_valid = self._verify_signed_properties_digest(
            signature,
            signed_info,
        )
        if signed_properties_valid is not None:
            result.append(
                {
                    "namespace": "",
                    "prefix": "signature",
                    "key": "signed_properties_valid",
                    "value": str(signed_properties_valid).lower(),
                },
            )

        signature_valid = self._verify_signature_value(
            signed_info,
            signature_value,
            cert_der_b64,
        )
        if signature_valid is not None:
            result.append(
                {
                    "namespace": "",
                    "prefix": "signature",
                    "key": "signature_valid",
                    "value": str(signature_valid).lower(),
                },
            )

    @staticmethod
    def _canonicalization_exclusive(signed_info) -> bool:
        """Return whether the declared canonicalisation is exclusive.

        XAdES signatures declare their canonicalisation method in
        ``ds:CanonicalizationMethod``.  Signatures produced with the
        eParaksts mobile signing library use inclusive c14n 1.1, whose
        canonical form differs from the exclusive form whenever
        inherited namespaces are in scope (e.g. the ``asic`` namespace
        declared on the container root).  Unknown or missing methods
        fall back to exclusive, the most common choice.
        """
        try:
            method = signed_info.find(f"{{{_XMLDSIG_NS}}}CanonicalizationMethod")
            algorithm = method.get("Algorithm", "") if method is not None else ""
        except Exception:
            return True
        return algorithm not in _INCLUSIVE_C14N_ALGORITHMS

    @staticmethod
    def _verify_signed_properties_digest(
        signature,
        signed_info,
    ) -> bool | None:
        """Verify the digest of the SignedProperties reference.

        Returns True/False when the referenced element and a supported
        digest algorithm were found, None otherwise.
        """
        try:
            from lxml import etree

            reference = next(
                (
                    ref
                    for ref in signed_info.findall(f"{{{_XMLDSIG_NS}}}Reference")
                    if ref.get("URI", "").startswith("#")
                ),
                None,
            )
            if reference is None:
                return None
            target_id = reference.get("URI", "")[1:]
            target = next(
                (
                    element
                    for element in signature.iter()
                    if element.get("Id") == target_id
                ),
                None,
            )
            if target is None:
                return None
            digest_value = reference.findtext(f"{{{_XMLDSIG_NS}}}DigestValue")
            digest_method = reference.find(f"{{{_XMLDSIG_NS}}}DigestMethod")
            digest_name = _DIGEST_ALGORITHMS.get(
                digest_method.get("Algorithm", "") if digest_method is not None else "",
            )
            if digest_value is None or digest_name is None:
                return None
            canonicalized = etree.tostring(
                target,
                method="c14n",
                exclusive=EdocDocumentParser._canonicalization_exclusive(
                    signed_info,
                ),
                with_comments=False,
            )
            return hashlib.new(digest_name, canonicalized).digest() == base64.b64decode(
                digest_value,
            )
        except Exception as err:  # pragma: no cover
            logger.warning("Could not verify SignedProperties digest: %s", err)
            return None

    @staticmethod
    def _verify_signature_value(
        signed_info,
        signature_value: str,
        cert_der_b64: str,
    ) -> bool | None:
        """Verify SignatureValue over the canonical form of SignedInfo.

        The canonicalisation declared in ``ds:CanonicalizationMethod``
        (exclusive c14n or inclusive c14n 1.0/1.1) is applied.
        Returns True/False when the signature algorithm is supported,
        None when verification could not be performed.
        """
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
            from lxml import etree

            signature_method = signed_info.find(
                f"{{{_XMLDSIG_NS}}}SignatureMethod",
            )
            algorithm = (
                signature_method.get("Algorithm", "")
                if signature_method is not None
                else ""
            )

            signature_padding: padding.PKCS1v15 | None = None
            signature_hash: hashes.HashAlgorithm | None = None
            signature_ecdsa: ec.ECDSA | None = None

            if algorithm == "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":
                signature_padding, signature_hash = padding.PKCS1v15(), hashes.SHA256()
            elif algorithm == "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384":
                signature_padding, signature_hash = padding.PKCS1v15(), hashes.SHA384()
            elif algorithm == "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512":
                signature_padding, signature_hash = padding.PKCS1v15(), hashes.SHA512()
            elif algorithm in {
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha1",
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
            }:
                signature_padding, signature_hash = padding.PKCS1v15(), hashes.SHA1()
            elif algorithm == "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256":
                signature_ecdsa = ec.ECDSA(hashes.SHA256())
            elif algorithm == "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384":
                signature_ecdsa = ec.ECDSA(hashes.SHA384())
            elif algorithm == "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512":
                signature_ecdsa = ec.ECDSA(hashes.SHA512())
            else:  # pragma: no cover
                logger.warning(
                    "Unsupported XAdES signature algorithm %r",
                    algorithm,
                )
                return None

            canonicalized = etree.tostring(
                signed_info,
                method="c14n",
                exclusive=EdocDocumentParser._canonicalization_exclusive(
                    signed_info,
                ),
                with_comments=False,
            )
            cert = x509.load_der_x509_certificate(base64.b64decode(cert_der_b64))
            public_key = cert.public_key()
            signature_bytes = base64.b64decode(signature_value)
            if (
                signature_padding is not None
                and signature_hash is not None
                and isinstance(public_key, rsa.RSAPublicKey)
            ):
                public_key.verify(
                    signature_bytes,
                    canonicalized,
                    signature_padding,
                    signature_hash,
                )
            elif signature_ecdsa is not None and isinstance(
                public_key,
                ec.EllipticCurvePublicKey,
            ):
                public_key.verify(
                    EdocDocumentParser._normalize_ecdsa_signature(
                        signature_bytes,
                        public_key,
                    ),
                    canonicalized,
                    signature_ecdsa,
                )
            else:  # pragma: no cover
                logger.warning(
                    "Unsupported signer public key type %s",
                    type(public_key).__name__,
                )
                return None
            return True
        except Exception as err:
            logger.warning("Signature verification failed: %s", err)
            return False

    @staticmethod
    def _normalize_ecdsa_signature(
        signature: bytes,
        public_key: ec.EllipticCurvePublicKey,
    ) -> bytes:
        """Return an ECDSA signature in the DER form expected by cryptography.

        XAdES/XMLDSIG represent ECDSA signature values as the raw
        concatenation of the ``r`` and ``s`` integers (RFC 4051), which
        is what the eParaksts mobile signing library emits.  The
        ``cryptography`` library only verifies DER-encoded signatures,
        so the raw form is converted here; DER signatures are passed
        through unchanged.
        """
        try:
            from cryptography.hazmat.primitives.asymmetric.utils import (
                encode_dss_signature,
            )
        except ImportError:  # pragma: no cover
            return signature
        component_size = (public_key.curve.key_size + 7) // 8
        if len(signature) == 2 * component_size:
            r = int.from_bytes(signature[:component_size], "big")
            s = int.from_bytes(signature[component_size:], "big")
            return encode_dss_signature(r, s)
        return signature


# Imported for its side effect: connecting the signer-as-correspondent
# handler to the document_consumption_finished signal when this module is
# loaded (which happens at parser entrypoint discovery).
from paperless_edoc import correspondent  # noqa: E402, F401
