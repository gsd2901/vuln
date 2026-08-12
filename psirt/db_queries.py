"""
psirt/db_queries.py
────────────────────
PostgreSQL helpers for the advisory_applicability collection.

Schema (JSONB document per row):
{
  "advisoryId":           str,          # Cisco advisory ID
  "deviceId":             str,          # DNAC instanceUuid
  "hostname":             str,
  "managementIpAddress":  str,
  "dnac_id":              str | null,   # which DNAC instance
  "platform":             str,
  "softwareVersion":      str,

  "applicability_checked": bool,        # ← the flag you asked for
  "verdict":              str,          # AFFECTED | NOT_AFFECTED | NEEDS_REVIEW | MITIGATED
                                         # (rows written before the terminology rename may still
                                         # contain the legacy APPLICABLE/NOT_APPLICABLE values --
                                         # every read helper below normalizes those transparently,
                                         # see _normalize_verdict()/_expand_verdict_filter())
  "summary":              str,
  "evidence":             str,
  "layer1":               str,
  "layer2":               str,
  "layer3":               str,
  "collection_method":    str,          # dnac_command_runner | ssh_fallback | version_only | pending
  "remediation":          dict | null,  # Tier-1 fix guidance, extracted verbatim
                                         # from the advisory (fixed_in, fixed_releases,
                                         # workaround). Never LLM-generated -- see
                                         # build_remediation_tier1() in psirt_native_views.py.

  "checked_at":           str,          # ISO-8601 UTC timestamp of last check
  "scan_triggered_at":    str,          # ISO-8601 UTC timestamp when the scan was kicked off
}

The compound key is (advisoryId + deviceId + dnac_id).
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

COLLECTION_NAME = "advisory_applicability"


@contextmanager
def _collection():
    try:
        from vulnerebility_management.db.database_postgresql import PostgreSQLConnector
    except Exception:
        from db.database_postgresql import PostgreSQLConnector

    db = PostgreSQLConnector("AdvisoryDatabase")
    try:
        yield db.collection(COLLECTION_NAME)
    finally:
        db.close()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Backward-compatible verdict aliasing ──────────────────────────────────────
#
# The verdict terminology was renamed: APPLICABLE -> AFFECTED,
# NOT_APPLICABLE -> NOT_AFFECTED. Rows already written to Postgres before this
# rename still contain the old values and were NOT migrated, so every read
# path below normalizes legacy values to their current name, and every
# verdict filter expands to also match the legacy alias -- both transparently,
# so callers only ever need to think in terms of AFFECTED/NOT_AFFECTED.

_VERDICT_LEGACY_TO_CURRENT = {
    "APPLICABLE": "AFFECTED",
    "NOT_APPLICABLE": "NOT_AFFECTED",
}
_VERDICT_CURRENT_TO_LEGACY = {v: k for k, v in _VERDICT_LEGACY_TO_CURRENT.items()}


def _normalize_verdict(verdict: str | None) -> str | None:
    """Map a legacy verdict value to its current name. NEEDS_REVIEW, PENDING,
    MITIGATED, and already-current values pass through unchanged."""
    if verdict is None:
        return verdict
    return _VERDICT_LEGACY_TO_CURRENT.get(verdict, verdict)


def _expand_verdict_filter(verdicts: list[str]) -> list[str]:
    """Given current verdict names to filter by, add their legacy aliases too
    so rows written before the rename still match."""
    expanded = list(verdicts)
    for v in verdicts:
        legacy = _VERDICT_CURRENT_TO_LEGACY.get(v)
        if legacy and legacy not in expanded:
            expanded.append(legacy)
    return expanded


def _normalize_row(row: dict | None) -> dict | None:
    if row is not None and "verdict" in row:
        row = {**row, "verdict": _normalize_verdict(row.get("verdict"))}
    return row


def _normalize_rows(rows: list[dict]) -> list[dict]:
    return [_normalize_row(r) for r in rows]


# ── Write helpers ──────────────────────────────────────────────────────────────

def upsert_applicability_pending(
    advisory_id: str,
    device_id: str,
    hostname: str,
    management_ip: str,
    platform: str,
    software_version: str,
    dnac_id: str | None,
    scan_triggered_at: str,
) -> None:
    """
    Insert a 'pending' placeholder row when a scan is triggered.
    If a row already exists for this (advisoryId, deviceId, dnac_id),
    reset it to pending so callers know re-analysis is in progress.
    """
    with _collection() as col:
        existing = col.find_one(
            _key_filter(advisory_id, device_id, dnac_id)
        )
        doc = {
            "advisoryId": advisory_id,
            "deviceId": device_id,
            "hostname": hostname,
            "managementIpAddress": management_ip,
            "dnac_id": dnac_id,
            "platform": platform,
            "softwareVersion": software_version,
            "applicability_checked": False,
            "verdict": "PENDING",
            "summary": "Applicability check in progress.",
            "evidence": "",
            "layer1": "",
            "layer2": "",
            "layer3": "",
            "collection_method": "pending",
            "checked_at": None,
            "scan_triggered_at": scan_triggered_at,
        }
        if existing:
            col.update_one(_key_filter(advisory_id, device_id, dnac_id), {"$set": doc})
        else:
            col.insert_one(doc)


def build_remediation_tier1(advisory_profile: dict) -> dict:
    """
    Tier-1 remediation guidance: extracted verbatim from the advisory itself
    (fixed_in / fixed_releases / workaround). Never LLM-generated -- zero
    hallucination risk since nothing here is synthesized.

    Shared by both scan paths (psirt_native_views.py's on-demand Assess flow
    and background_scanner.py's automated DNAC-triggered scan) so both write
    the same "remediation" field to the applicability_results collection.
    """
    advisory_profile = advisory_profile or {}
    fixed_releases = advisory_profile.get("fixed_releases") or {}
    workaround     = (advisory_profile.get("workaround") or "").strip()
    fixed_in       = (advisory_profile.get("fixed_in") or "").strip()
    return {
        "source":            "advisory_verbatim",
        "fixed_in":          fixed_in or None,
        "fixed_releases":    fixed_releases or None,
        "workaround":        workaround or None,
        "has_workaround":    bool(workaround),
        "has_fixed_release": bool(fixed_releases or fixed_in),
    }


def update_applicability_result(
    advisory_id: str,
    device_id: str,
    dnac_id: str | None,
    verdict: str,
    summary: str,
    evidence: str,
    layer1: str = "",
    layer2: str = "",
    layer3: str = "",
    layer4: str = "",
    collection_method: str = "",
    action: str = "",
    mitigation: dict | None = None,
    judge: dict | None = None,
    needs_review_reason: str = "",
    remediation: dict | None = None,
) -> None:
    """
    Write the final verdict for an (advisoryId, deviceId, dnac_id) pair.
    Sets applicability_checked = True.
    New fields: layer4 (workaround check), action (operator recommendation),
                mitigation (compensating controls dict),
                judge (LLM-as-judge consistency check dict: {consistent,
                       corrected_verdict, judge_reasoning} -- runs on every
                       verdict and auto-corrects verdict/summary upstream in
                       background_scanner.py when it finds a genuine
                       contradiction between the stated verdict and the
                       summary/evidence/layer results; corrected_verdict is
                       non-null only when a correction was actually applied),
                needs_review_reason (why NEEDS_REVIEW: no_fixed_release |
                                     collection_failed | insufficient_data),
                remediation (Tier-1 fix guidance extracted verbatim from the
                             advisory itself -- fixed_in / fixed_releases /
                             workaround -- NOT LLM-generated. See
                             build_remediation_tier1() in psirt_native_views.py.
                             Any LLM-synthesized, device-specific commands are
                             generated on-demand via a separate endpoint and
                             are never silently merged into this field).
    """
    with _collection() as col:
        col.update_one(
            _key_filter(advisory_id, device_id, dnac_id),
            {
                "$set": {
                    "applicability_checked": True,
                    "verdict":              verdict,
                    "summary":              summary,
                    "evidence":             evidence,
                    "layer1":               layer1,
                    "layer2":               layer2,
                    "layer3":               layer3,
                    "layer4":               layer4,
                    "collection_method":    collection_method,
                    "action":               action,
                    "mitigation":           mitigation,
                    "judge":                judge,
                    "needs_review_reason":  needs_review_reason,
                    "remediation":          remediation,
                    "checked_at":           _now_iso(),
                }
            },
        )


# ── Read helpers ───────────────────────────────────────────────────────────────

def get_applicable_advisories_for_device(
    device_id: str,
    dnac_id: str | None = None,
) -> list[dict]:
    """
    Return only the AFFECTED (or NEEDS_REVIEW) advisories for a device
    where applicability_checked = True.

    This is the 'filtered' path used on subsequent queries — NOT_AFFECTED
    advisories are silently excluded.
    """
    with _collection() as col:
        base_filter: dict = {
            "deviceId": device_id,
            "applicability_checked": True,
            "verdict": {"$in": _expand_verdict_filter(["AFFECTED", "NEEDS_REVIEW", "MITIGATED"])},
        }
        if dnac_id is not None:
            base_filter["dnac_id"] = dnac_id
        return _normalize_rows(col.find(base_filter))


def get_applicable_advisories_for_hostname_or_ip(
    token: str,
    dnac_id: str | None = None,
) -> list[dict]:
    """
    Same as get_applicable_advisories_for_device() (AFFECTED/NEEDS_REVIEW/
    MITIGATED only) but resolves the device by hostname or management IP
    instead of requiring a deviceId.

    This exists because callers such as the RAG chatbot's device lookup
    (rag_langchain_agent.py) resolve devices against a separate legacy
    Postgres 'impacted_devices' table first to get a deviceId -- and that
    table may simply not have a given device (e.g. it was only ever
    discovered via the PSIRT background scanner's per-advisory affected-
    device fetch, never through the separate "fetch impacted devices"
    action). Querying this collection directly by hostname/IP means a
    device that's clearly present in the PSIRT Scan DB results can still
    be found even when that legacy lookup comes up empty.

    'token' can be a clean hostname/IP, or an entire raw natural-language
    query string (e.g. straight from a chatbot message) -- matching handles
    both: exact hostname/IP match, token-contains-hostname (token is a full
    sentence that mentions the hostname somewhere), and hostname-contains-
    token (token is a short/partial hostname), each tried in that order.
    """
    token_norm = (token or "").strip().lower()
    if not token_norm:
        return []
    with _collection() as col:
        base_filter: dict = {
            "applicability_checked": True,
            "verdict": {"$in": _expand_verdict_filter(["AFFECTED", "NEEDS_REVIEW", "MITIGATED"])},
        }
        if dnac_id is not None:
            base_filter["dnac_id"] = dnac_id
        rows = _normalize_rows(col.find(base_filter))

    exact_host = [r for r in rows if str(r.get("hostname") or "").strip().lower() == token_norm]
    if exact_host:
        return exact_host

    exact_ip = [r for r in rows if str(r.get("managementIpAddress") or "").strip().lower() == token_norm]
    if exact_ip:
        return exact_ip

    # token is a whole sentence/phrase that contains the device's hostname or IP
    # somewhere in it (e.g. the raw chatbot message) -- require hostname length
    # >= 6 to avoid short/generic hostnames spuriously matching inside prose.
    contains_host = [
        r for r in rows
        if len(str(r.get("hostname") or "")) >= 6
        and str(r.get("hostname") or "").strip().lower() in token_norm
    ]
    if contains_host:
        return contains_host

    contains_ip = [
        r for r in rows
        if str(r.get("managementIpAddress") or "").strip()
        and str(r.get("managementIpAddress") or "").strip().lower() in token_norm
    ]
    if contains_ip:
        return contains_ip

    # token is a short/partial hostname fragment
    substr_host = [r for r in rows if token_norm in str(r.get("hostname") or "").strip().lower()]
    return substr_host


def get_all_advisories_for_device(
    device_id: str,
    dnac_id: str | None = None,
) -> list[dict]:
    """Return every row for a device regardless of verdict (admin / debug use)."""
    with _collection() as col:
        f: dict = {"deviceId": device_id}
        if dnac_id is not None:
            f["dnac_id"] = dnac_id
        return _normalize_rows(col.find(f))


def get_applicability_record(
    advisory_id: str,
    device_id: str,
    dnac_id: str | None = None,
) -> dict | None:
    """Fetch a single record for an (advisory, device, dnac_id) triple."""
    with _collection() as col:
        return _normalize_row(col.find_one(_key_filter(advisory_id, device_id, dnac_id)))


def is_applicability_checked(
    advisory_id: str,
    device_id: str,
    dnac_id: str | None = None,
) -> bool:
    """Return True if the pair has already been fully assessed."""
    rec = get_applicability_record(advisory_id, device_id, dnac_id)
    return bool(rec and rec.get("applicability_checked"))


def get_applicable_advisories_for_dnac(
    dnac_id: str | None = None,
    verdicts: list[str] | None = None,
) -> list[dict]:
    """
    Return all AFFECTED (and optionally NEEDS_REVIEW) advisories
    for an entire DNAC instance, grouped usefully for dashboards.
    """
    if verdicts is None:
        verdicts = ["AFFECTED", "NEEDS_REVIEW"]
    with _collection() as col:
        f: dict = {
            "applicability_checked": True,
            "verdict": {"$in": _expand_verdict_filter(verdicts)},
        }
        if dnac_id is not None:
            f["dnac_id"] = dnac_id
        return _normalize_rows(col.find(f))


def get_summary_counts(dnac_id: str | None = None) -> dict:
    """Return verdict count summary for a DNAC instance."""
    with _collection() as col:
        f: dict = {"applicability_checked": True}
        if dnac_id is not None:
            f["dnac_id"] = dnac_id
        rows = col.find(f)

    counts: dict = {
        "AFFECTED": 0,
        "NOT_AFFECTED": 0,
        "NEEDS_REVIEW": 0,
        "MITIGATED": 0,
        "PENDING": 0,
    }
    for row in rows:
        v = _normalize_verdict(row.get("verdict", "PENDING"))
        counts[v] = counts.get(v, 0) + 1
    return counts


# ── Internal ───────────────────────────────────────────────────────────────────

def _key_filter(
    advisory_id: str,
    device_id: str,
    dnac_id: str | None,
) -> dict:
    f: dict = {"advisoryId": advisory_id, "deviceId": device_id}
    if dnac_id is not None:
        f["dnac_id"] = dnac_id
    return f


def clear_applicability_results(dnac_id: str | None) -> int:
    """
    Delete all advisory_applicability rows for a given dnac_id before a new scan.
    Returns the number of rows deleted.
    """
    with _collection() as col:
        f: dict = {"dnac_id": dnac_id} if dnac_id is not None else {}
        result = col.delete_many(f)
        deleted = getattr(result, "deleted_count", 0)
        logger.info(
            "[PSIRT] Cleared %d stale applicability rows for dnac_id=%s",
            deleted, dnac_id,
        )
        return deleted


def get_needs_review_detail(dnac_id: str | None = None) -> list[dict]:
    """
    Return all NEEDS_REVIEW rows with full detail — for debugging why
    verdicts are not resolving to AFFECTED / NOT_AFFECTED.
    """
    with _collection() as col:
        f: dict = {
            "applicability_checked": True,
            "verdict": "NEEDS_REVIEW",
        }
        if dnac_id is not None:
            f["dnac_id"] = dnac_id
        return _normalize_rows(col.find(f))


def get_verdict_breakdown(dnac_id: str | None = None) -> list[dict]:
    """
    Return every checked row with just the fields needed to diagnose
    collection_method distribution and failure patterns.
    Fields: advisoryId, hostname, softwareVersion, verdict,
            collection_method, summary, layer1, layer2, layer3
    """
    with _collection() as col:
        f: dict = {"applicability_checked": True}
        if dnac_id is not None:
            f["dnac_id"] = dnac_id
        rows = col.find(f)
    return [
        {
            "advisoryId":        r.get("advisoryId"),
            "hostname":          r.get("hostname"),
            "softwareVersion":   r.get("softwareVersion"),
            "verdict":           _normalize_verdict(r.get("verdict")),
            "collection_method": r.get("collection_method"),
            "summary":           r.get("summary"),
            "layer1":            r.get("layer1"),
            "layer2":            r.get("layer2"),
            "layer3":            r.get("layer3"),
            "layer4":            r.get("layer4", ""),
            "evidence":          r.get("evidence"),
            "action":            r.get("action", ""),
            "mitigation":        r.get("mitigation"),
            "remediation":       r.get("remediation"),
        }
        for r in rows
    ]