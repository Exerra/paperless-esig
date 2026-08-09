"""
Signer-as-correspondent support for Paperless-ngx.

Paperless-ngx's consumption pipeline has no hook for a third-party
package to suggest a correspondent *before* the document is saved — the
correspondent is assigned by content matching and workflow rules inside
the consumer.  This module listens to the
``document_consumption_finished`` signal instead and assigns the XAdES
signer of an ASiC-E container as the correspondent when no correspondent
was determined during consumption.

The consumer fires ``document_consumption_finished`` with the document
and the path of the consumed file *before* the files are moved to their
final location.  The handler therefore

* reads the signer from the original container (via
  :func:`paperless_edoc.parser.extract_signer_name`),
* updates the database row directly (``QuerySet.update``) so that the
  ``post_save`` filename handlers do not run while the files are not in
  place yet, and sets the in-memory attribute on the document so the
  consumer generates the stored filename with the correspondent in mind
  (when a filename template uses it),
* re-indexes the document so searches for the correspondent match
  immediately (the built-in ``add_to_index`` receiver already ran for
  this signal).

Known limitations:

* the assignment is not recorded in the audit log (the row is updated
  with ``QuerySet.update``),
* the frontend may show the new correspondent as "Private" until the
  page is reloaded, because the UI's name-list caches are not invalidated
  when a correspondent is created server-side.

The feature can be disabled with
``PAPERLESS_EDOC_ASSIGN_SIGNER_AS_CORRESPONDENT=false`` (default: on).
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from documents.signals import document_consumption_finished

logger = logging.getLogger("paperless_edoc.correspondent")


def _assign_signer_as_correspondent_enabled() -> bool:
    """Return whether signer-as-correspondent assignment is enabled."""
    return os.getenv(
        "PAPERLESS_EDOC_ASSIGN_SIGNER_AS_CORRESPONDENT", "yes"
    ).strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def _load_correspondent_model():
    from documents.models import Correspondent

    return Correspondent


def _load_document_model():
    from documents.models import Document

    return Document


def _search_backend():
    from documents.search import get_backend

    return get_backend()


def _on_document_consumption_finished(
    sender: Any,
    document,
    original_file=None,
    **kwargs: Any,
) -> None:
    """Assign the signer of a consumed ASiC-E container as correspondent.

    The assignment only happens when the document has no correspondent
    yet (i.e. content matching and workflow rules found nothing) and the
    container actually carries a usable signer name.
    """
    if not _assign_signer_as_correspondent_enabled():
        return
    if getattr(document, "correspondent_id", None) is not None:
        return
    if getattr(document, "mime_type", None) != "application/zip":
        return
    if original_file is None:
        return

    # Imported lazily: this module is imported from parser.py (which is
    # loaded at entrypoint discovery), so a module-level import would
    # create a circular import.
    from paperless_edoc.parser import extract_signer_name

    signer_name = extract_signer_name(Path(original_file))
    if not signer_name:
        return

    try:
        Correspondent = _load_correspondent_model()
        Document = _load_document_model()

        selected = Correspondent.objects.filter(name__iexact=signer_name).first()
        if selected is None:
            # Created without a matching rule: the signer name is not part
            # of the searchable content, so a content match rule would be
            # inert and could cause false positives when the name appears
            # in unrelated text.
            selected = Correspondent.objects.create(
                name=signer_name,
                matching_algorithm=Correspondent.MATCH_NONE,
            )

        # Update the row without triggering the post_save filename/move
        # handlers (the files are not in their final location yet) and
        # set the in-memory attribute so the consumer picks the
        # correspondent up when generating the stored filename.
        Document.objects.filter(pk=document.pk).update(correspondent=selected)
        document.correspondent = selected

        # The built-in add_to_index receiver already ran for this signal;
        # re-index so the new correspondent is searchable immediately.
        _search_backend().add_or_update(
            document,
            effective_content=document.get_effective_content(),
        )

        logger.info(
            "Assigned signer %s as correspondent %s to document %s",
            signer_name,
            selected,
            document,
        )
    except Exception:
        logger.exception(
            "Could not assign signer %s as correspondent to document %s",
            signer_name,
            document,
        )


document_consumption_finished.connect(
    _on_document_consumption_finished,
    dispatch_uid="paperless_edoc.signer_as_correspondent",
)
