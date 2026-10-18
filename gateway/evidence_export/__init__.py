"""Gateway evidence export — provider-neutral EvidenceEvent and exporters.

Import graph (acyclic — do not alter without checking for cycles):

  __init__
  ├── event          (no internal deps)
  ├── exporters      (→ event, outbox)
  ├── drata_connector (→ event, exporters, hermes.drata_state)
  └── dispatch       (→ drata_connector, event, exporters, outbox)

``drata_connector`` imports ``exporters`` via
``from gateway.evidence_export import exporters`` which goes through this
__init__ on first load.  Python's re-entrant import guard (sys.modules
partial object) prevents a hard ImportError, but the ordering above must
be maintained: always import ``exporters`` before ``drata_connector``.
Do NOT add imports from this __init__ into ``exporters`` or ``event``.
"""

from gateway.evidence_export.dispatch import dispatch_evidence_export, try_export_evidence
from gateway.evidence_export.drata_connector import ConnectionResult, DrataConnector
from gateway.evidence_export.event import EvidenceEvent, build_evidence_event
from gateway.evidence_export.exporters import (
    DrataExporter,
    ExportResult,
    WebhookExporter,
    get_configured_exporters,
)

__all__ = [
    "ConnectionResult",
    "DrataConnector",
    "DrataExporter",
    "EvidenceEvent",
    "ExportResult",
    "WebhookExporter",
    "build_evidence_event",
    "dispatch_evidence_export",
    "get_configured_exporters",
    "try_export_evidence",
]
