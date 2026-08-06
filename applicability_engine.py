"""
psirt/applicability_engine.py
──────────────────────────────
Core applicability analysis engine.

Updated from app_psirtlm.py (working reference):
  - fetch_cisco_advisory_text: JSON endpoint first, section-targeted HTML fallback
  - FEATURE_COMMANDS: expanded (secure boot, tls, ssl, privesc, ikev2, nbar, bootp, tacacs…)
  - FEATURE_ALIASES: maps advisory text to feature keys (e.g. "web ui" → "http")
  - COMPENSATING_CONTROLS + check_compensating_controls()
  - analyse_applicability: 4-layer GPT prompt (Layer 4 = workaround check) + action field
  - version_only_verdict: cleaner letter-suffix stripping
  - ChromaDB profile cache (unchanged)
"""

from __future__ import annotations

import json
import logging
import re
import os
from typing import Optional

import httpx
import requests

logger = logging.getLogger(__name__)

# ── Azure OpenAI (LangChain) ──────────────────────────────────────────────────
_llm = None

def _get_llm():
    global _llm
    if _llm is None:
        from langchain_openai import AzureChatOpenAI
        try:
            from rag_agent_project.config import AZURE_OPENAI_API_KEY
        except Exception:
            from config import AZURE_OPENAI_API_KEY
        _llm = AzureChatOpenAI(
            azure_deployment="gpt-4.1",
            api_version="2025-04-01-preview",
            azure_endpoint="https://git-nw-openai-llm-prod.openai.azure.com/",
            http_client=httpx.Client(verify=False),
            temperature=0,
            api_key=AZURE_OPENAI_API_KEY,
        )
    return _llm


# ── ChromaDB advisory-profile cache ───────────────────────────────────────────
_chroma_client = None
_advisory_collection = None
CHROMA_DB_PATH  = os.environ.get("PSIRT_CHROMA_DB_PATH", "./psirt_chroma_db")
CHROMA_COLLECTION = "psirt_advisory_profiles"


def _get_chroma_collection():
    global _chroma_client, _advisory_collection
    if _advisory_collection is None:
        try:
            import chromadb
            _chroma_client = chromadb.PersistentClient(path=CHROMA_DB_PATH)
            _advisory_collection = _chroma_client.get_or_create_collection(
                name=CHROMA_COLLECTION,
                metadata={"hnsw:space": "cosine"},
            )
        except Exception as exc:
            logger.error("ChromaDB init failed: %s", exc)
            return None
    return _advisory_collection


def get_advisory_profile_from_cache(advisory_id: str) -> Optional[dict]:
    try:
        col = _get_chroma_collection()
        if col is None:
            return None
        result = col.get(ids=[advisory_id], include=["metadatas"])
        if result and result.get("ids") and result["ids"][0] == advisory_id:
            raw = result["metadatas"][0].get("profile_json", "")
            if raw:
                profile = json.loads(raw)
                # Invalidate stale entries with no version data
                if profile.get("affected_versions") or profile.get("fixed_releases"):
                    return profile
    except Exception as exc:
        logger.warning("ChromaDB cache read failed for %s: %s", advisory_id, exc)
    return None


def clear_advisory_profile_cache() -> int:
    """
    Delete every advisory profile stored in ChromaDB and reset the in-process
    client so the next read starts completely fresh.
    Returns the number of entries that were deleted (0 if cache was already empty).
    """
    global _chroma_client, _advisory_collection
    deleted = 0
    try:
        col = _get_chroma_collection()
        if col is not None:
            all_ids = col.get(include=[])["ids"]
            deleted = len(all_ids)
            if all_ids:
                col.delete(ids=all_ids)
                logger.info("[PSIRT] ChromaDB cache cleared — deleted %d advisory profiles.", deleted)
            else:
                logger.info("[PSIRT] ChromaDB cache was already empty.")
    except Exception as exc:
        logger.warning("[PSIRT] ChromaDB cache clear failed: %s", exc)
    finally:
        # Reset module-level singletons so next call re-initialises cleanly
        _advisory_collection = None
        _chroma_client = None
    return deleted


def save_advisory_profile_to_cache(advisory_id: str, profile: dict) -> None:
    try:
        col = _get_chroma_collection()
        if col is None:
            return
        summary_doc = (
            f"Advisory: {advisory_id} | "
            f"CVE: {profile.get('cve', 'N/A')} | "
            f"Feature: {profile.get('vulnerable_feature', 'N/A')} | "
            f"Impact: {profile.get('impact', 'N/A')} | "
            f"Platforms: {', '.join(profile.get('affected_platforms', []))}"
        )
        col.upsert(
            ids=[advisory_id],
            documents=[summary_doc],
            metadatas=[{
                "advisory_id":   advisory_id,
                "cve":           profile.get("cve", ""),
                "feature":       profile.get("vulnerable_feature", ""),
                "profile_json":  json.dumps(profile, default=str),
            }],
        )
    except Exception as exc:
        logger.warning("ChromaDB cache write failed for %s: %s", advisory_id, exc)


# ── Cisco PSIRT openVuln API ──────────────────────────────────────────────────
import time as _time
_openvuln_token_cache: dict = {"token": None, "expires_at": 0.0}


def _get_openvuln_token() -> str:
    """Return a cached OAuth2 bearer token for the Cisco PSIRT openVuln API."""
    if (_openvuln_token_cache["token"]
            and _time.time() < _openvuln_token_cache["expires_at"] - 60):
        return _openvuln_token_cache["token"]
    try:
        from rag_agent_project.config import API_CLIENT_ID, API_CLIENT_SECRET, API_GRANT_TYPE
    except Exception:
        from config import API_CLIENT_ID, API_CLIENT_SECRET, API_GRANT_TYPE
    resp = requests.post(
        "https://id.cisco.com/oauth2/default/v1/token",
        data={
            "grant_type": API_GRANT_TYPE,
            "client_id": API_CLIENT_ID,
            "client_secret": API_CLIENT_SECRET,
        },
        timeout=15,
        verify=False,
    )
    resp.raise_for_status()
    data = resp.json()
    _openvuln_token_cache["token"] = data["access_token"]
    _openvuln_token_cache["expires_at"] = _time.time() + data.get("expires_in", 3600)
    logger.info("[PSIRT OPENVULN] OAuth token refreshed, expires_in=%s", data.get("expires_in"))
    return _openvuln_token_cache["token"]


def fetch_fixed_releases_openvuln(advisory_id: str) -> dict:
    """
    Query Cisco PSIRT openVuln API v2 for an advisory.
    Returns a fixed_releases dict  e.g. {'17.9': '17.9.5', '17.12': '17.12.4'}
    or {} on failure / no data.
    """
    try:
        token = _get_openvuln_token()
        resp = requests.get(
            f"https://apix.cisco.com/security/advisories/v2/advisory/{advisory_id}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            timeout=15,
            verify=False,
        )
        resp.raise_for_status()
        raw = resp.json()
        # The API may return a single advisory dict or wrap it in {"advisories": [...]}
        adv = raw if isinstance(raw, dict) and "advisoryId" in raw else (
            raw.get("advisories", [raw])[0] if isinstance(raw, dict) else raw[0]
        )
        logger.info("[PSIRT OPENVULN] %s: API response keys=%s", advisory_id, list(adv.keys()))

        fixed: dict = {}

        # ── Try structured firstFixed / fixedVersions fields ──────────────────
        for field in ("firstFixed", "fixedVersions", "fixedReleases"):
            val = adv.get(field)
            if val:
                logger.info("[PSIRT OPENVULN] %s: %s=%s", advisory_id, field, val)
                # val may be a list of version strings; build train→version mapping
                ver_re = re.compile(r"(\d+\.\d+)[\.\d]*[a-zA-Z]?")
                for v in (val if isinstance(val, list) else [val]):
                    m = ver_re.match(str(v).strip())
                    if m:
                        train = m.group(1)
                        if train not in fixed:
                            fixed[train] = str(v).strip()
                if fixed:
                    return fixed

        # ── Fallback: parse summary HTML for version table ─────────────────────
        summary_html = adv.get("summary", "") or adv.get("advisorySummary", "")
        if summary_html:
            summary_text = _html_table_to_text(summary_html)
            logger.info("[PSIRT OPENVULN] %s: summary text len=%d, preview=%.300r",
                        advisory_id, len(summary_text), summary_text[:300])
            # Look for "train: X.Y | first fixed: X.Y.Z" style table rows
            row_re = re.compile(
                r"(\d{2}\.\d{1,2})(?:\.\w+)?\s*\|\s*([\d]+\.[\d]+\.[\d]+[a-zA-Z]?)",
                re.MULTILINE,
            )
            for m in row_re.finditer(summary_text):
                train = m.group(1)
                if train not in fixed:
                    fixed[train] = m.group(2)
            if fixed:
                logger.info("[PSIRT OPENVULN] %s: extracted from summary: %s", advisory_id, fixed)
                return fixed

        # ── Try CSAF document (contains structured product version tree) ─────────
        _raw_csaf = adv.get("csafUrl")
        _raw_cvrf = adv.get("cvrfUrl") or ""
        csaf_url = _raw_csaf or (str(_raw_cvrf).replace("/cvrf/", "/csaf/").replace(".xml", ".json") if _raw_cvrf else "")
        logger.info("[PSIRT CSAF-URL] %s: csafUrl=%r  cvrfUrl=%r  → csaf_url=%r",
                    advisory_id, _raw_csaf, _raw_cvrf, csaf_url)
        if csaf_url:
            csaf_fixed = _fetch_fixed_releases_from_csaf(csaf_url, advisory_id)
            if csaf_fixed:
                return csaf_fixed

        # ── Last resort: scrape advisory HTML/JSON and ask GPT to parse the
        #    Fixed Software table — mirrors the working approach in app.py ──────
        logger.info("[PSIRT OPENVULN] %s: falling back to HTML scrape + GPT extraction", advisory_id)
        advisory_text = fetch_cisco_advisory_text(advisory_id)
        if advisory_text:
            llm_fixed = _extract_fixed_releases_from_text(advisory_text, advisory_id)
            if llm_fixed:
                return llm_fixed

        logger.warning("[PSIRT OPENVULN] %s: all strategies exhausted, no fixed_releases found", advisory_id)
        return {}
    except Exception as exc:
        logger.warning("[PSIRT OPENVULN] %s: API call failed: %s", advisory_id, exc)
        return {}


def _extract_fixed_releases_from_text(advisory_text: str, advisory_id: str) -> dict:
    """
    Last-resort fallback: ask GPT to parse the Fixed Software section from
    scraped advisory prose and return a {train: first_fixed} dict.
    Mirrors the extract_advisory_profile() approach from app.py but is
    cheaper — only extracts fixed_releases, skips the full profile.
    """
    try:
        llm = _get_llm()
        prompt = (
            "You are a Cisco PSIRT version parser. Extract ONLY the fixed_releases "
            "mapping from this advisory text.\n\n"
            "Rules:\n"
            "- fixed_releases maps software train → first fixed version "
            "(e.g. {\"17.9\": \"17.9.5\", \"17.12\": \"17.12.4\"}).\n"
            "- Parse every row in the 'Fixed Software' or 'Software Versions' table.\n"
            "- Use the major.minor train (e.g. '17.9') as the key.\n"
            "- Use the exact first-fixed version string as the value.\n"
            "- Return ONLY a JSON object — no prose, no markdown fences.\n"
            "- If no Fixed Software table is present, return {}.\n\n"
            f"ADVISORY TEXT:\n{advisory_text[:15_000]}"
        )
        resp = llm.invoke([{"role": "user", "content": prompt}])
        raw = resp.content.replace("```json", "").replace("```", "").strip()
        result = json.loads(raw)
        if isinstance(result, dict) and result:
            logger.info("[PSIRT LLM-FALLBACK] %s: extracted fixed_releases=%s", advisory_id, result)
            return result
        logger.warning("[PSIRT LLM-FALLBACK] %s: GPT returned empty or non-dict: %r", advisory_id, raw[:200])
        return {}
    except Exception as exc:
        logger.warning("[PSIRT LLM-FALLBACK] %s: GPT extraction failed: %s", advisory_id, exc)
        return {}


def _fetch_fixed_releases_from_csaf(csaf_url: str, advisory_id: str) -> dict:
    """
    Fetch and parse a Cisco CSAF JSON document.
    Extracts first-fixed version strings and maps them to train→version dict.
    """
    try:
        token = _get_openvuln_token()
        resp = requests.get(
            csaf_url,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            timeout=90,   # 1.7 MB CSAFs need more than 20s on slow links
            verify=False,
        )
        resp.raise_for_status()
        csaf = resp.json()
        logger.info("[PSIRT CSAF] %s: fetched %s, size=%d", advisory_id, csaf_url, len(resp.content))

        # Build a map of CSAF product ID → version string from the product_tree.
        # Cisco CSAF uses various branch categories — capture any branch with a product_id.
        pid_to_version: dict = {}
        def _walk_branches(branches: list, parent_name: str = "") -> None:
            for branch in (branches or []):
                name = branch.get("name", "")
                prod = branch.get("product", {}) or {}
                pid = prod.get("product_id", "")
                if pid:
                    pid_to_version[pid] = name
                _walk_branches(branch.get("branches", []), name)

        _walk_branches(csaf.get("product_tree", {}).get("branches", []))
        # Also check full_product_names at the top level (flat list with every product+version)
        for fp in csaf.get("product_tree", {}).get("full_product_names", []):
            pid = fp.get("product_id", "")
            if pid:
                pid_to_version.setdefault(pid, fp.get("name", ""))
        # Also check relationships — Cisco often places combined platform+version IDs here
        for rel in csaf.get("product_tree", {}).get("relationships", []):
            fpn = rel.get("full_product_name", {}) or {}
            pid = fpn.get("product_id", "")
            if pid:
                pid_to_version.setdefault(pid, fpn.get("name", ""))
        # Log a sample of the pid_to_version map for debugging
        if pid_to_version:
            sample = dict(list(pid_to_version.items())[:5])
            logger.info("[PSIRT CSAF] %s: pid_to_version sample=%s", advisory_id, sample)

        logger.info("[PSIRT CSAF] %s: mapped %d product IDs", advisory_id, len(pid_to_version))

        # Extract first_fixed product IDs from vulnerabilities
        fixed_versions: list = []
        for vuln in csaf.get("vulnerabilities", []):
            status = vuln.get("product_status", {})
            # Diagnostic: log which product_status keys are present (first vuln only)
            if vuln is csaf.get("vulnerabilities", [None])[0]:
                status_keys = {k: len(v) for k, v in status.items() if isinstance(v, list)}
                logger.info("[PSIRT CSAF] %s: product_status keys=%s", advisory_id, status_keys)
            for pid in status.get("first_fixed", []) + status.get("fixed", []):
                v = pid_to_version.get(pid, "")
                if v:
                    fixed_versions.append(v)
            # Also mine remediations (vendor_fix category) for additional fixed version IDs
            for rem in vuln.get("remediations", []):
                if rem.get("category") == "vendor_fix":
                    for pid in rem.get("product_ids", []):
                        v = pid_to_version.get(pid, "")
                        if v:
                            fixed_versions.append(v)

        logger.info("[PSIRT CSAF] %s: first_fixed versions=%s", advisory_id, fixed_versions[:10])

        # Build train → first_fixed_version map.
        # v may be a clean version string ("17.9.1") or a full product string
        # ("Cisco Secure Firewall...6.6.0 when installed on...") — extract just
        # the version number in either case.
        fixed: dict = {}
        ver_re  = re.compile(r"(\d+\.\d+)[\.\d]*[a-zA-Z]?")
        # Matches a standalone version token like 6.6.0 or 17.9.1a
        clean_re = re.compile(r'\b(\d+\.\d+(?:\.\d+)*[a-zA-Z]?\d*)\b')
        for v in fixed_versions:
            m = ver_re.search(str(v))
            if m:
                train = m.group(1)
                # Extract clean version number (strip surrounding product prose)
                cm = clean_re.search(str(v))
                clean_v = cm.group(1) if cm else str(v)
                # Keep the lowest (earliest) fixed version per train
                if train not in fixed:
                    fixed[train] = clean_v
                else:
                    try:
                        if _parse_ver(clean_v) < _parse_ver(fixed[train]):
                            fixed[train] = clean_v
                    except Exception:
                        pass

        if fixed:
            logger.info("[PSIRT CSAF] %s: extracted fixed_releases=%s", advisory_id, fixed)
        else:
            logger.warning("[PSIRT CSAF] %s: no first_fixed versions found in CSAF", advisory_id)
        return fixed
    except Exception as exc:
        logger.warning("[PSIRT CSAF] %s: CSAF fetch/parse failed: %s", advisory_id, exc)
        return {}


# ── Cisco advisory text fetch ─────────────────────────────────────────────────
# In-memory cache so Cisco is only called once per advisory per process run
_cisco_advisory_cache: dict[str, str] = {}


def _html_table_to_text(html_fragment: str) -> str:
    """Convert HTML to readable text, preserving table row/column structure."""
    text = re.sub(r"</tr\s*>", "\n", html_fragment, flags=re.IGNORECASE)
    text = re.sub(r"<t[dh][^>]*>", " | ", text, flags=re.IGNORECASE)
    text = re.sub(r"</t[dh]\s*>", "", text, flags=re.IGNORECASE)
    text = re.sub(r"<br\s*/?>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"<p[^>]*>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"[ \t]{2,}", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return text


def fetch_cisco_advisory_text(advisory_id: str) -> str:
    """
    Fetch advisory content from Cisco portal.
    Strategy:
      1. Try the JSON endpoint  (/advisory/{id}/json)  — structured, no HTML noise
      2. Fallback: section-targeted HTML scrape
      3. Last resort: strip all HTML
    Results are cached in memory.
    """
    if advisory_id in _cisco_advisory_cache:
        return _cisco_advisory_cache[advisory_id]

    headers = {"User-Agent": "Mozilla/5.0"}
    json_url = (
        f"https://sec.cloudapps.cisco.com/security/center/content/"
        f"CiscoSecurityAdvisory/{advisory_id}/json"
    )
    html_url = (
        f"https://sec.cloudapps.cisco.com/security/center/content/"
        f"CiscoSecurityAdvisory/{advisory_id}"
    )
    html_url_alt = (
        f"https://tools.cisco.com/security/center/content/"
        f"CiscoSecurityAdvisory/{advisory_id}"
    )

    # ── Try JSON endpoint first ───────────────────────────────────────────────
    try:
        resp = requests.get(json_url, timeout=15, headers=headers)
        logger.info("[PSIRT FETCH] %s: JSON endpoint status=%s content-type=%s",
                    advisory_id, resp.status_code, resp.headers.get("content-type", ""))
        if resp.status_code == 200 and "json" in resp.headers.get("content-type", ""):
            data = resp.json()
            present_fields = [f for f in ("summary", "affectedProducts", "vulnerableProducts",
                          "indicatorsOfCompromise", "workarounds",
                          "fixedSoftware", "softwareVersions") if data.get(f)]
            logger.info("[PSIRT FETCH] %s: JSON fields present: %s", advisory_id, present_fields)
            parts = []
            for field in ("summary", "affectedProducts", "vulnerableProducts",
                          "indicatorsOfCompromise", "workarounds",
                          "fixedSoftware", "softwareVersions"):
                val = data.get(field, "")
                if val:
                    clean = re.sub(r"<[^>]+>", " ", str(val))
                    clean = re.sub(r"[ \t]{2,}", " ", clean).strip()
                    parts.append(f"=== {field} ===\n{clean}")
            text = "\n\n".join(parts)
            if text:
                logger.info("[PSIRT FETCH] %s: JSON path OK, text_len=%d, preview=%.300r",
                            advisory_id, len(text), text[:300])
                _cisco_advisory_cache[advisory_id] = text
                return text
            else:
                logger.warning("[PSIRT FETCH] %s: JSON endpoint returned no usable text", advisory_id)
    except Exception as exc:
        logger.warning("[PSIRT FETCH] %s: JSON endpoint error: %s", advisory_id, exc)

    # ── Shared section pattern (reused by HTML and alt-URL fallbacks) ─────────
    target_sections = [
        "Summary", "Affected Products", "Vulnerable Products",
        "Products Confirmed Not Vulnerable", "Indicators of Compromise",
        "Workarounds", "Fixed Software", "Software Versions",
    ]
    section_pattern = re.compile(
        r'<(?:h[123]|div[^>]*)[^>]*>\s*(' +
        '|'.join(re.escape(s) for s in target_sections) +
        r')\s*</(?:h[123]|div)>(.*?)(?=<(?:h[123]|div[^>]*)[^>]*>\s*(?:' +
        '|'.join(re.escape(s) for s in target_sections) +
        r')|$)',
        re.IGNORECASE | re.DOTALL,
    )

    # ── Fallback: section-targeted HTML scrape ────────────────────────────────
    try:
        resp = requests.get(html_url, timeout=15, headers=headers)
        resp.raise_for_status()
        html = resp.text
        parts = []
        for m in section_pattern.finditer(html):
            heading = m.group(1).strip()
            clean   = _html_table_to_text(m.group(2))
            if clean:
                parts.append(f"=== {heading} ===\n{clean}")

        if parts:
            text = "\n\n".join(parts)
            logger.info("[PSIRT FETCH] %s: HTML section-targeted OK, sections=%s, text_len=%d, preview=%.300r",
                        advisory_id, [m.group(1).strip() for m in section_pattern.finditer(html)], len(text), text[:300])
        else:
            text = re.sub(r"<[^>]+>", " ", html)
            text = re.sub(r"[ \t]{2,}", " ", text)
            text = re.sub(r"\n{3,}", "\n\n", text).strip()
            text = text[:30_000]
            logger.warning("[PSIRT FETCH] %s: HTML section-targeted matched nothing — using raw strip, text_len=%d, preview=%.300r",
                           advisory_id, len(text), text[:300])

        _cisco_advisory_cache[advisory_id] = text
        return text
    except Exception as exc:
        logger.warning("[PSIRT FETCH] %s: HTML fetch failed: %s", advisory_id, exc)

    # ── Last resort: try tools.cisco.com alternate URL ────────────────────────
    if html_url_alt != html_url:
        try:
            resp = requests.get(html_url_alt, timeout=15, headers=headers)
            resp.raise_for_status()
            html = resp.text
            parts = []
            for m in section_pattern.finditer(html):
                heading = m.group(1).strip()
                clean   = _html_table_to_text(m.group(2))
                if clean:
                    parts.append(f"=== {heading} ===\n{clean}")
            if parts:
                text = "\n\n".join(parts)
                logger.info("[PSIRT FETCH] %s: tools.cisco.com fallback OK, text_len=%d", advisory_id, len(text))
                _cisco_advisory_cache[advisory_id] = text
                return text
        except Exception as exc2:
            logger.warning("[PSIRT FETCH] %s: tools.cisco.com fallback failed: %s", advisory_id, exc2)

    _cisco_advisory_cache[advisory_id] = ""
    return ""


# ── Feature → verification commands ──────────────────────────────────────────
FEATURE_COMMANDS: dict[str, list[str]] = {
    "snmp": [
        "show running-config | include snmp-server community",
        "show running-config | include snmp-server group",
        "show snmp user",
        "show snmp community",
        "show running-config | section snmp-server",
    ],
    "secure boot": [
        "show version",
        "show platform integrity",
        "show software authenticity running",
        "show platform sudi certificate",
        "show rom-monitor",
        "show platform integrity sign nonce 12345",
    ],
    "tls": [
        "show running-config | include ip http",
        "show running-config | include ip http secure-server",
        "show running-config | section line vty",
        "show running-config | include transport input",
        "show running-config | include ssl",
        "show ip http server status",
        "show ip http secure-status",
    ],
    "ssl": [
        "show running-config | include ip http",
        "show ip http server status",
        "show ip http secure-status",
        "show running-config | include ssl",
    ],
    "privilege escalation": [
        "show running-config | include privilege",
        "show running-config | section username",
        "show running-config | include aaa",
        "show privilege",
        "tclsh",
        "show running-config | include tclsh",
    ],
    "bgp": [
        "show running-config | include router bgp",
        "show bgp summary",
    ],
    "ospf": [
        "show running-config | include router ospf",
        "show ip ospf",
    ],
    "ssh": [
        "show running-config | include ip ssh",
        "show ip ssh",
    ],
    "http": [
        "show running-config | include ip http",
        "show ip http server status",
        "show ip http secure-status",
    ],
    "nat": [
        "show running-config | include ip nat",
        "show ip nat translations",
    ],
    "ipsec": [
        "show running-config | include crypto map",
        "show crypto session",
    ],
    "ikev2": [
        "show running-config | include crypto ikev2",
        "show crypto ikev2 sa",
        "show running-config | section crypto ikev2",
    ],
    "mpls": [
        "show running-config | include mpls",
        "show mpls interfaces",
    ],
    "ntp": [
        "show running-config | include ntp server",
        "show ntp status",
    ],
    "aaa": [
        "show running-config | include aaa",
        "show aaa servers",
    ],
    "tacacs": [
        "show running-config | include tacacs",
        "show running-config | section aaa",
        "show aaa servers",
    ],
    "netconf": [
        "show running-config | include netconf",
        "show netconf-yang sessions",
    ],
    "restconf": [
        "show running-config | include restconf",
    ],
    "bootp": [
        "show running-config | include ip bootp",
        "show running-config | include no ip bootp server",
    ],
    "nbar": [
        "show running-config | include ip nbar",
        "show running-config | section policy-map",
        "show ip nbar protocol-discovery",
    ],
    "default": [
        "show version",
        "show running-config | include version",
    ],
}

# Keyword aliases: advisory feature text → FEATURE_COMMANDS key
FEATURE_ALIASES: dict[str, str] = {
    "transport layer security":   "tls",
    "secure sockets layer":       "ssl",
    "privilege":                  "privilege escalation",
    "privilege escalation":       "privilege escalation",
    "privesc":                    "privilege escalation",
    "cli":                        "privilege escalation",
    "command line interface":     "privilege escalation",
    "command injection":          "http",
    "web ui":                     "http",
    "web management":             "http",
    "boot":                       "secure boot",
    "secure boot bypass":         "secure boot",
    "rommon":                     "secure boot",
    "ikev2":                      "ikev2",
    "ike":                        "ikev2",
    "tacacs+":                    "tacacs",
    "bootp":                      "bootp",
    "nbar":                       "nbar",
}

ALWAYS_RUN = ["show version"]


def resolve_feature_commands(feature_key: str) -> list[str]:
    """Return verification commands for a feature, applying aliases."""
    key = FEATURE_ALIASES.get(feature_key.lower(), feature_key.lower())
    return FEATURE_COMMANDS.get(key, FEATURE_COMMANDS["default"])


# ── Compensating controls ─────────────────────────────────────────────────────
COMPENSATING_CONTROLS: dict[str, list[str]] = {
    "snmp": [
        "show running-config | include snmp-server community",
        "show running-config | include snmp-server group",
        "show running-config | include snmp-server user",
        "show snmp user",
        "show running-config | include access-list",
        "show running-config | section snmp-server",
        "show running-config | include ip access-group",
    ],
    "tls": [
        "show ip http secure-status",
        "show running-config | include ip http secure-server",
        "show running-config | include ip http max-connections",
        "show running-config | include ip http access-class",
        "show running-config | section line vty",
        "show running-config | include transport input",
        "show running-config | include access-class",
    ],
    "ssl": [
        "show ip http secure-status",
        "show running-config | include ip http access-class",
        "show running-config | include ssl",
    ],
    "http": [
        "show ip http server status",
        "show ip http secure-status",
        "show running-config | include ip http access-class",
        "show running-config | include ip http max-connections",
        "show running-config | section ip http",
    ],
    "ikev2": [
        "show running-config | section crypto ikev2",
        "show running-config | include crypto ikev2 policy",
        "show running-config | include crypto ikev2 profile",
        "show running-config | include ip access-list",
        "show crypto ikev2 sa",
    ],
    "bgp": [
        "show running-config | section router bgp",
        "show running-config | include neighbor.*password",
        "show running-config | include neighbor.*ttl-security",
        "show running-config | include bgp.*log",
    ],
    "ssh": [
        "show ip ssh",
        "show running-config | include ip ssh version",
        "show running-config | include ip ssh time-out",
        "show running-config | include ip ssh authentication-retries",
        "show running-config | include access-class",
        "show running-config | section line vty",
    ],
    "secure boot": [
        "show platform integrity",
        "show software authenticity running",
        "show running-config | include secure boot",
        "show rom-monitor",
    ],
    "privilege escalation": [
        "show running-config | include privilege",
        "show running-config | section username",
        "show running-config | include aaa authentication",
        "show running-config | include aaa authorization",
        "show running-config | include service password",
        "show running-config | include enable secret",
    ],
    "bootp": [
        "show running-config | include ip bootp server",
        "show running-config | include no ip bootp server",
    ],
    "nbar": [
        "show running-config | section policy-map",
        "show running-config | section class-map",
        "show ip nbar protocol-discovery",
    ],
    "tacacs": [
        "show running-config | section aaa",
        "show running-config | include tacacs",
        "show aaa servers",
    ],
    "default": [
        "show running-config | include access-class",
        "show running-config | include access-group",
        "show running-config | include service",
    ],
}


def get_compensating_control_commands(feature_key: str) -> list[str]:
    key = FEATURE_ALIASES.get(feature_key.lower(), feature_key.lower())
    return COMPENSATING_CONTROLS.get(key, COMPENSATING_CONTROLS["default"])


def check_compensating_controls(
    advisory_profile: dict,
    device: dict,
    command_outputs: dict,
) -> dict:
    """
    For an AFFECTED device, check whether existing security configuration
    substantially reduces exploitability.

    IMPORTANT: the caller (background_scanner.py) treats "mitigated": true
    as authoritative — it reclassifies the device's verdict from AFFECTED to
    NOT_AFFECTED based on this result alone, with no separate confidence
    threshold applied in code. Be conservative: only return mitigated=true
    when the configuration evidence genuinely blocks exploitation of this
    specific vulnerability, not merely reduces its likelihood.

    Returns:
    {
        "mitigated": bool,
        "controls_found": [...],
        "controls_missing": [...],
        "mitigation_summary": str,
        "mitigation_confidence": "HIGH"|"MEDIUM"|"LOW"
    }
    """
    outputs_text = "\n".join(f"$ {cmd}\n{out}" for cmd, out in command_outputs.items())
    llm = _get_llm()

    prompt = f"""You are a Cisco IOS XE security analyst. A device is confirmed AFFECTED
for a PSIRT advisory. Determine whether existing security configuration already
compensates for (mitigates) this vulnerability.

Your "mitigated" answer directly reclassifies this device's verdict from
AFFECTED to NOT_AFFECTED — there is no additional human or confidence check
downstream. Treat this as a real security determination, not a suggestion.

ADVISORY PROFILE:
{json.dumps(advisory_profile, indent=2)}

DEVICE:
Hostname: {device.get('hostname', device.get('host', 'unknown'))}
Platform: {device.get('platform', 'Unknown')}
Version:  {device.get('version', 'Unknown')}

CONFIGURATION / COMMAND OUTPUTS:
{outputs_text}

Analyse the configuration for compensating controls that would prevent exploitation
of this specific vulnerability. Examples:
- SNMP: SNMPv3 with authPriv, ACL restricting SNMP source IPs, no default community strings
- HTTP/HTTPS: ip http access-class restricting management access, no ip http server
- SSH: SSHv2 only, access-class on VTY lines, restricted source IPs
- IKEv2: no peers configured, strict crypto policy, ACL restricting IKE sources
- Privilege escalation: AAA authentication/authorization enforced, no default enable password
- Secure boot: integrity verification enabled, SUDI certificate present
- BGP: MD5/SHA authentication on all peers, TTL security enabled

Return ONLY valid JSON:
{{
  "mitigated": true | false,
  "controls_found": ["specific controls actively configured that reduce exploitability"],
  "controls_missing": ["specific controls NOT configured that would further reduce risk"],
  "mitigation_summary": "2-3 sentence plain English explanation",
  "mitigation_confidence": "HIGH" | "MEDIUM" | "LOW"
}}

Rules:
- mitigated=true only if existing controls SUBSTANTIALLY BLOCK exploitability of THIS vulnerability —
  not merely "helpful" or "reduces risk somewhat". When in doubt, return false.
- Be specific — cite exact config lines visible in outputs
- controls_missing should be actionable recommendations
- mitigated=true will cause this device to be reclassified NOT_AFFECTED and removed from
  active vulnerability tracking for this advisory — false positives here have real
  operational consequences, so require clear, direct evidence before returning true"""

    try:
        resp = llm.invoke([{"role": "user", "content": prompt}])
        raw  = resp.content.replace("```json", "").replace("```", "").strip()
        return json.loads(raw)
    except Exception as exc:
        logger.error("check_compensating_controls failed: %s", exc)
        return {
            "mitigated": False,
            "controls_found": [],
            "controls_missing": [],
            "mitigation_summary": f"Compensating controls check failed: {exc}",
            "mitigation_confidence": "LOW",
        }


# ── Advisory profile extraction ───────────────────────────────────────────────
_EXTRACT_PROMPT = """\
Extract structured info from this Cisco PSIRT advisory. Return ONLY valid JSON, no markdown fences.

ADVISORY:
{advisory_text}

Return JSON:
{{
  "advisory_id": "...",
  "cve": "CVE-XXXX-XXXXX",
  "title": "...",
  "vulnerable_feature": "main feature name in lowercase (e.g. snmp, bgp, ssh, secure boot, tls, privilege escalation)",
  "affected_platforms": ["list of platform families, e.g. IOS XE, IOS, NX-OS"],
  "affected_versions": ["IMPORTANT: extract ALL version trains listed as vulnerable. Cisco uses a table: train 16.12.x → fixed in 16.12.10, meaning all versions before 16.12.10 are vulnerable. List as '17.9.x before 17.9.5'. Do NOT leave empty if Fixed Software section exists."],
  "fixed_releases": {{"train": "first_fixed_version"}},
  "fixed_in": "earliest recommended fixed release",
  "impact": "brief impact description",
  "workaround": "verbatim operator-actionable guidance from the advisory's Workarounds AND/OR Mitigations section, else null",
  "verification_commands": ["exact IOS/IOS-XE show commands from the advisory that verify vulnerability or feature presence"]
}}

CRITICAL rules:
- For fixed_releases: parse every row of the Fixed Software table. Key = train (e.g. "17.9"), value = first fixed version.
- For affected_versions: express each as 'X.Y.x before X.Y.Z'. Never leave empty if a table exists.
- For verification_commands: extract ONLY actual device CLI commands. No prose.
- Do NOT hallucinate version numbers — only extract what is explicitly written.
- For workaround: Cisco advisories often write "There are no workarounds that address this
  vulnerability. However, there is a mitigation." followed by concrete mitigation steps/commands.
  Do NOT return null in that case — extract the mitigation guidance (including any example CLI
  config shown) into the workaround field verbatim, since it is still actionable operator guidance
  short of upgrading. Only return null if the advisory has NEITHER a workaround NOR a mitigation
  section with actionable guidance."""


def extract_advisory_profile(advisory_text: str, advisory_id: str = "") -> dict:
    """
    Parse a Cisco PSIRT advisory into a structured profile.
    Checks ChromaDB cache first; persists result to cache on miss.
    """
    # Cache lookup
    if advisory_id:
        cached = get_advisory_profile_from_cache(advisory_id)
        if cached:
            return cached

    llm  = _get_llm()
    logger.info("[PSIRT EXTRACT] %s: advisory_text len=%d, preview=%.500r",
                advisory_id, len(advisory_text), advisory_text[:500])
    _fs_match = re.search(r'=== Fixed Software ===\n(.*?)(?====|\Z)', advisory_text, re.DOTALL)
    if _fs_match:
        logger.info("[PSIRT EXTRACT] %s: Fixed Software section: %.3000r",
                    advisory_id, _fs_match.group(1)[:3000])
    else:
        logger.warning("[PSIRT EXTRACT] %s: No 'Fixed Software' section found in advisory text", advisory_id)
    prompt = _EXTRACT_PROMPT.format(advisory_text=advisory_text[:30_000])
    try:
        resp = llm.invoke([{"role": "user", "content": prompt}])
        raw  = resp.content.replace("```json", "").replace("```", "").strip()
        profile = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("GPT returned non-JSON for profile extraction (%s)", advisory_id)
        profile = {}
    except Exception as exc:
        logger.error("extract_advisory_profile failed (%s): %s", advisory_id, exc)
        profile = {}

    cache_key = advisory_id or profile.get("advisory_id", "")
    if cache_key and profile:
        save_advisory_profile_to_cache(cache_key, profile)

    return profile


# ── 4-layer applicability analysis ───────────────────────────────────────────
_ANALYSE_PROMPT = """\
You are a Cisco PSIRT applicability engine. Run a 4-layer check. Return ONLY valid JSON — no markdown fences.

ADVISORY PROFILE:
{profile_json}

DEVICE:
Hostname: {hostname}
Platform/Model: {platform}
Software Version: {version}

COMMAND OUTPUTS:
{outputs_text}

Run these 4 layers:
Layer 1 - Platform Check: Is the device platform in advisory affected_platforms?
Layer 2 - Software Version Check: Is the software version in the vulnerable range?
Layer 3 - Feature Check: Is the vulnerable feature configured/active? Use command outputs.
Layer 4 - Mitigation Check: ONLY if Layers 1-3 → AFFECTED. Does the advisory's documented workaround already exist on this device?

Return JSON:
{{
  "verdict": "AFFECTED" | "NOT_AFFECTED" | "NEEDS_REVIEW",
  "layer1": {{"result": "PASS"|"FAIL"|"UNKNOWN", "detail": "..."}},
  "layer2": {{"result": "PASS"|"FAIL"|"UNKNOWN", "detail": "..."}},
  "layer3": {{"result": "PASS"|"FAIL"|"UNKNOWN", "detail": "..."}},
  "layer4": {{"result": "MITIGATED"|"NOT_MITIGATED"|"NO_WORKAROUND"|"UNKNOWN", "detail": "..."}},
  "summary": "2-3 sentence explanation",
  "action": "recommended next step for operator",
  "evidence": "key facts from output that led to verdict"
}}

Verdict rules:
- AFFECTED     = Layers 1+2+3 all PASS (Layer 4 is informational only — never changes verdict)
- NOT_AFFECTED = any layer clearly FAIL
- NEEDS_REVIEW   = genuinely insufficient data (use sparingly)

CRITICAL Layer 2 version rules:
- Parse fixed_releases dict: train → first_fixed (e.g. {{"17.9": "17.9.5", "17.12": "17.12.4"}})
- Extract device train from show version (e.g. 17.09.06a → train 17.9)
- device version >= first_fixed → Layer 2 FAIL → NOT_AFFECTED (patched)
- device version <  first_fixed → Layer 2 PASS (vulnerable range)
- device train NOT in fixed_releases but other trains are → Layer 2 FAIL → NOT_AFFECTED
- Compare numerically: 17.9.6 > 17.9.5, 17.12.1 > 17.9.x
- Layer 2 UNKNOWN only if NO version data exists anywhere

CRITICAL Layer 3 rules:
- For 'privilege escalation' or 'cli': always PASS on IOS XE devices
- For 'secure boot': PASS if show platform integrity has Boot Loader Hash and OS Version present
- For 'tls'/'ssl': PASS if show ip http secure-status shows HTTPS enabled
- Layer 3 UNKNOWN acceptable ONLY when no command output at all
- When Layer 3 is UNKNOWN: use Layer 1+2 alone — both PASS → AFFECTED, either FAIL → NOT_AFFECTED

CRITICAL Layer 4 rules (informational only):
- If workaround is null/empty → layer4.result = "NO_WORKAROUND"
- If verdict is not AFFECTED → layer4.result = "UNKNOWN", detail = "Not evaluated"
- If workaround exists and verdict AFFECTED: check if that EXACT config change is already present
  - Evidence found → "MITIGATED" with specific output line cited
  - Evidence absent → "NOT_MITIGATED" explaining what is still exposed
  - Insufficient output → "UNKNOWN" explaining what command would be needed
- Only credit the specific Cisco-documented workaround — not general hardening"""


def analyse_applicability(
    advisory_profile: dict,
    device: dict,
    command_outputs: dict,
) -> dict:
    """
    Run 4-layer GPT applicability check.
    Returns dict with verdict/layer1/layer2/layer3/layer4/summary/action/evidence.
    """
    llm = _get_llm()
    outputs_text = "\n".join(f"$ {cmd}\n{out}" for cmd, out in (command_outputs or {}).items())

    prompt = _ANALYSE_PROMPT.format(
        profile_json=json.dumps(advisory_profile, indent=2),
        hostname=device.get("hostname", device.get("host", "unknown")),
        platform=device.get("platform", "Unknown"),
        version=device.get("version", "Unknown"),
        outputs_text=outputs_text or "(none collected)",
    )
    try:
        resp = llm.invoke([{"role": "user", "content": prompt}])
        raw  = resp.content.replace("```json", "").replace("```", "").strip()
        return json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("GPT returned non-JSON for applicability analysis")
        return {
            "verdict": "NEEDS_REVIEW",
            "summary": "GPT response was not valid JSON.",
            "evidence": "",
            "action": "Re-run the scan or review manually.",
        }
    except Exception as exc:
        logger.error("analyse_applicability failed: %s", exc)
        return {
            "verdict": "NEEDS_REVIEW",
            "summary": f"Analysis error: {exc}",
            "evidence": "",
            "action": "Check server logs.",
        }


# ── Version-only verdict (fallback when command collection unavailable) ────────

def _parse_ver(v: str) -> tuple[int, ...]:
    """
    Parse Cisco version string to a comparable int tuple.

    Handles two common formats:
      IOS-style:    15.2(7)E13  →  (15, 2, 7, 13)
      Flat-style:   17.9.6a     →  (17, 9, 6)
      Train-only:   15.2        →  (15, 2)
    """
    v = (v or "").strip()

    # IOS parenthetical: major.minor(maint[opt_letter])[train_letter][patch]
    # e.g. 15.2(7)E13  or  12.4(25e)  or  15.2(6)E2
    # The letter may appear inside OR outside the parens (or both).
    ios_m = re.match(r"^(\d+)\.(\d+)\((\d+)[a-zA-Z]?\)[a-zA-Z]*(\d*)$", v)
    if ios_m:
        parts = [int(ios_m.group(1)), int(ios_m.group(2)), int(ios_m.group(3))]
        if ios_m.group(4):  # patch number after the train letter
            parts.append(int(ios_m.group(4)))
        return tuple(parts)

    # Flat / IOS XE style: strip trailing letter suffix, then remaining letters,
    # split on . or - and collect numeric components.
    v_clean = re.sub(r"[a-zA-Z]+\d*$", "", v)   # drop trailing 'a', 'b2' etc.
    v_clean = re.sub(r"[a-zA-Z]", "", v_clean)   # drop any remaining letters
    result = []
    for p in re.split(r"[.\-]", v_clean):
        p = p.strip()
        if p:
            try:
                result.append(int(p))
            except ValueError:
                pass
    return tuple(result)


def _ver_train(v: str) -> str:
    """Extract major.minor train prefix, e.g. '17.9.6a' → '17.9'."""
    m = re.match(r"(\d+\.\d+)", v or "")
    return m.group(1) if m else ""


def version_only_verdict(
    profile: dict,
    device_version: str,
    platform: str = "",
    software_type: str = "",
) -> str:
    """
    Layer 1 + Layer 2 verdict when command collection failed.

    Parameters
    ----------
    profile       : advisory profile dict (from ChromaDB / CSAF)
    device_version: software version string from DNAC (e.g. "15.2(7)E13")
    platform      : hardware model string from DNAC platformId (e.g. "WS-C2960X-48FPS-L")
    software_type : OS-type string from DNAC softwareType field (e.g. "IOS", "IOS-XE")

    Returns 'AFFECTED', 'NOT_AFFECTED', or 'NEEDS_REVIEW'.
    """
    # Layer 1: platform check
    # affected_platforms in advisory profiles are OS-type names like "IOS", "IOS XE 3E",
    # "ASA", "NX-OS" — NOT hardware model strings.  We therefore check both the hardware
    # platform string AND the DNAC softwareType field (which IS the OS type).
    affected_platforms = [p.lower() for p in (profile.get("affected_platforms") or [])]
    if affected_platforms:
        plat_lower = platform.lower()
        # Normalise softwareType: "IOS-XE" → "ios xe" so it can substring-match "ios xe 3e"
        sw_type_lower = software_type.lower().replace("-", " ")

        def _ap_match(ap: str) -> bool:
            # hardware model match (legacy behaviour)
            if ap in plat_lower or plat_lower in ap:
                return True
            # OS-type match — the fix for WS-C2960X vs "ios"
            if sw_type_lower and (ap in sw_type_lower or sw_type_lower in ap):
                return True
            return False

        l1_pass = any(_ap_match(ap) for ap in affected_platforms)
        if not l1_pass:
            logger.info(
                "[PSIRT VERSION] Layer1 FAIL: platform=%s sw_type=%s not in "
                "affected_platforms=%s → NOT_AFFECTED",
                platform, software_type, affected_platforms,
            )
            return "NOT_AFFECTED"

    # Layer 2: version check
    fixed_releases: dict = profile.get("fixed_releases") or {}
    if not fixed_releases or not device_version:
        return "NEEDS_REVIEW"

    device_train = _ver_train(device_version)
    if not device_train:
        return "NEEDS_REVIEW"

    # Match train key (handles "17.9.x", "17.9", "17.09" variants)
    matched_first_fixed = None
    for train_key, first_fixed in fixed_releases.items():
        train_norm = _ver_train(train_key.replace(".x", ""))
        if train_norm == device_train:
            matched_first_fixed = first_fixed
            break

    if matched_first_fixed is None:
        # Device train not in fixed_releases → not affected by this advisory
        logger.info(
            "[PSIRT VERSION] device_version=%s train=%s not in advisory fixed_releases=%s → NOT_AFFECTED (train not affected)",
            device_version, device_train, list(fixed_releases.keys()),
        )
        return "NOT_AFFECTED"

    # Detect placeholder first_fixed: CSAF sometimes emits only the train prefix
    # (e.g. "15.2") when no specific patch number is known (remediations-only CSAF).
    # Comparing a device version to a bare "15.2" is meaningless.
    # Rule (matching UI scan behaviour): when no specific fix is known, treat all
    # versions in affected scope as potentially vulnerable → return AFFECTED.
    if _ver_train(matched_first_fixed) == matched_first_fixed.strip():
        logger.info(
            "[PSIRT VERSION] device_version=%s first_fixed=%s is a train placeholder "
            "(no specific patch in CSAF) — no fix known, assume vulnerable → AFFECTED",
            device_version, matched_first_fixed,
        )
        return "AFFECTED"

    dev_parsed   = _parse_ver(device_version)
    fixed_parsed = _parse_ver(matched_first_fixed)

    if not dev_parsed or not fixed_parsed:
        return "NEEDS_REVIEW"

    if dev_parsed >= fixed_parsed:
        logger.info(
            "[PSIRT VERSION] device_version=%s (train=%s) >= first_fixed=%s → NOT_AFFECTED (already patched)",
            device_version, device_train, matched_first_fixed,
        )
        return "NOT_AFFECTED"  # patched
    logger.info(
        "[PSIRT VERSION] device_version=%s (train=%s) < first_fixed=%s → AFFECTED (vulnerable)",
        device_version, device_train, matched_first_fixed,
    )
    return "AFFECTED"          # in vulnerable range