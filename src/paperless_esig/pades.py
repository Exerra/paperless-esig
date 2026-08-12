"""
PAdES signature extraction from signed PDFs.

PAdES signatures live in PDF signature dictionaries (``/Type /Sig``
objects referenced from form field widgets).  The dictionary carries

* ``/ByteRange`` — the four numbers delimiting the covered byte ranges,
* ``/Contents`` — the CMS (CAdES) signature value, as a hex string that
  may live in a separate stream object,
* ``/SubFilter`` — ``ETSI.CAdES.detached`` or ``adbe.pkcs7.detached``
  (both wrap a CMS ``SignedData``; the CAdES flavour is what makes the
  signature a *PAdES* one),
* ``/M`` — the claimed signing time (not cryptographically protected),
* ``/Reason`` and ``/Name`` — human-readable signer info.

Extraction prefers pikepdf (already a dependency, tolerant of broken
xref tables and incremental updates) and falls back to a byte-level scan
for files pikepdf cannot open.  The covered bytes — the CMS
``messageDigest`` is computed over them — are the concatenation of the
two ``ByteRange`` segments.
"""

from __future__ import annotations

import io
import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

logger = logging.getLogger("paperless_esig.pades")

#: ByteRange of a PAdES signature: four non-negative integers.
_BYTE_RANGE_RE: re.Pattern[bytes] = re.compile(
    rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]",
)


@dataclass(frozen=True)
class PdfSignature:
    """A PAdES signature dictionary extracted from a PDF.

    Attributes
    ----------
    byte_range:
        The four ``/ByteRange`` integers ``(start, length, start,
        length)`` of the covered byte segments.
    contents:
        The raw CMS bytes of the ``/Contents`` value.
    subfilter:
        The ``/SubFilter`` name, or None.
    m:
        The ``/M`` signing-time string (not cryptographically
        protected), or None.
    reason:
        The ``/Reason`` string, or None.
    name:
        The ``/Name`` string, or None.
    """

    byte_range: tuple[int, int, int, int]
    contents: bytes
    subfilter: str | None = None
    m: str | None = None
    reason: str | None = None
    name: str | None = None


def is_pades_pdf(data: bytes) -> bool:
    """Return True if *data* is a PDF carrying a signed signature dict."""
    if not data.startswith(b"%PDF"):
        return False
    if _BYTE_RANGE_RE.search(data) is None:
        return False
    try:
        return bool(find_pdf_signatures(data))
    except Exception:
        return False


def covered_bytes(pdf_data: bytes, byte_range: tuple[int, int, int, int]) -> bytes:
    """Return the bytes of *pdf_data* covered by the signature range."""
    first_start, first_length, second_start, second_length = byte_range
    return (
        pdf_data[first_start : first_start + first_length]
        + pdf_data[second_start : second_start + second_length]
    )


def find_pdf_signatures(pdf_data: bytes) -> list[PdfSignature]:
    """Return every signature dictionary found in *pdf_data*.

    Tries pikepdf first (robust against incremental updates and broken
    xref tables) and falls back to a byte-level scan for files pikepdf
    cannot open (e.g. xref streams it rejects).  Signatures referenced
    both from a page's ``/Annots`` and from ``/AcroForm`` are reported
    once.

    Parameters
    ----------
    pdf_data:
        The raw PDF bytes.

    Returns
    -------
    list[PdfSignature]
        The extracted signatures, in document order.  Empty when the
        PDF is unsigned or unparseable.
    """
    signatures: list[PdfSignature] = []
    try:
        signatures = _find_signatures_with_pikepdf(pdf_data)
    except Exception as err:
        logger.debug("pikepdf signature extraction failed: %s", err)
        signatures = []
    if not signatures:
        signatures = _find_signatures_byte_scan(pdf_data)

    # The same signature appears both on the page's /Annots and in
    # /AcroForm /Fields; deduplicate on the covered byte range.
    seen: set[tuple[int, int, int, int]] = set()
    unique: list[PdfSignature] = []
    for signature in signatures:
        if signature.byte_range in seen:
            continue
        seen.add(signature.byte_range)
        unique.append(signature)
    return unique


def _find_signatures_with_pikepdf(pdf_data: bytes) -> list[PdfSignature]:
    """Extract signature dictionaries via pikepdf."""
    import pikepdf

    signatures: list[PdfSignature] = []
    try:
        with pikepdf.open(io.BytesIO(pdf_data)) as pdf:
            for page in pdf.pages:
                annots = page.get("/Annots")
                if annots is None:
                    continue
                for annot in annots:
                    signatures.extend(_signature_from_annotation(annot))
            form = pdf.Root.get("/AcroForm")
            if form is not None:
                fields = form.get("/Fields")
                if fields is not None:
                    for field in fields:
                        signatures.extend(_signature_from_annotation(field))
    except Exception as err:
        raise RuntimeError(f"could not open PDF: {err}") from err
    return signatures


def _signature_from_annotation(annot: Any) -> list[PdfSignature]:
    """Return the PdfSignature carried by a signature annotation."""
    import pikepdf

    signatures: list[PdfSignature] = []
    try:
        if not isinstance(annot, pikepdf.Dictionary):
            return signatures
        # Widget fields carry /FT /Sig and reference their signature
        # value through /V; some PDFs use the signature dictionary
        # itself as the field (no /FT, no /V).
        value = annot.get("/V")
        if value is None:
            value = annot
        if value is None or not isinstance(value, pikepdf.Dictionary):
            return signatures
        byte_range = value.get("/ByteRange")
        contents = value.get("/Contents")
        if byte_range is None or contents is None:
            return signatures
        try:
            numbers = tuple(int(number) for number in byte_range)
        except Exception:
            return signatures
        if len(numbers) != 4:
            return signatures
        raw = bytes(contents)
        signatures.append(
            PdfSignature(
                byte_range=numbers,  # type: ignore[arg-type]
                contents=raw,
                subfilter=_string_or_none(value.get("/SubFilter")),
                m=_string_or_none(value.get("/M")),
                reason=_string_or_none(value.get("/Reason")),
                name=_string_or_none(value.get("/Name")),
            ),
        )
    except Exception as err:
        logger.debug("Could not parse signature annotation: %s", err)
    return signatures


def _string_or_none(value: Any) -> str | None:
    """Coerce a pikepdf string/name value to str, or None."""
    if value is None:
        return None
    try:
        text = str(value).removeprefix("/")
        return text or None
    except Exception:  # pragma: no cover
        return None


def _find_signatures_byte_scan(pdf_data: bytes) -> list[PdfSignature]:
    """Byte-level fallback: find every /ByteRange + /Contents pair.

    The signature dictionary layout varies: ``/Contents`` may follow
    ``/ByteRange`` directly or after other keys, and ``/SubFilter`` may
    appear before ``/ByteRange`` or after a multi-kilobyte
    ``/Contents``, so a window spanning the dictionary is scanned.
    """
    signatures: list[PdfSignature] = []
    for match in _BYTE_RANGE_RE.finditer(pdf_data):
        numbers = tuple(int(group) for group in match.groups())
        window_start = max(0, match.start() - 1024)
        window = pdf_data[window_start:]
        subfilter_match = re.search(rb"/SubFilter\s*/([A-Za-z0-9._]+)", window)
        subfilter = (
            subfilter_match.group(1).decode("ascii", errors="replace")
            if subfilter_match
            else None
        )
        contents_match = re.search(rb"/Contents\s*<([0-9A-Fa-f]*)>", window)
        contents: bytes = b""
        if contents_match:
            try:
                contents = bytes.fromhex(contents_match.group(1).decode("ascii"))
            except ValueError:
                contents = b""
        signatures.append(
            PdfSignature(
                byte_range=numbers,  # type: ignore[arg-type]
                contents=contents,
                subfilter=subfilter,
            ),
        )
    return signatures
