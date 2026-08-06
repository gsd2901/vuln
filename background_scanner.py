"""
psirt/background_scanner.py
────────────────────────────
Background applicability scanner.

Updated from app_psirtlm.py (working reference):
  - _dnac_device_type(): proper lookup table (cisco_xe / cisco_nxos / cisco_xr)
    fixes "Unsupported device_type" Netmiko error
  - Compensating controls check after AFFECTED verdict
  - Layer 4 (workaround check) result surfaced in DB record
  - SSH creds injection pattern (don't mutate shared device dicts)
  - DNAC advisory detail API used to enrich profiles before GPT fallback
"""

from __future__ import annotations

import datetime
import json
import logging
import re
import threading
from typing import Optional

from psirt.applicability_engine import (
    ALWAYS_RUN,
    FEATURE_ALIASES,
    FEATURE_COMMANDS,
    analyse_applicability,
    check_compensating_controls,
    extract_advisory_profile,
    fetch_cisco_advisory_text,
    fetch_fixed_releases_openvuln,
    get_advisory_profile_from_cache,
    get_compensating_control_commands,
    resolve_feature_commands,
    save_advisory_profile_to_cache,
    version_only_verdict,
)
from psirt.db_queries import (
    build_remediation_tier1,
    clear_applicability_results,
    update_applicability_result,
    upsert_applicability_pending,
)

logger = logging.getLogger(__name__)

# DNAC Command Runner 400 messages that mean SSH won't help either.
# Errors that block the SSH fallback.
# "not in inventory" is intentionally removed: these devices exist in DNAC's
# device list and have management IPs, but are simply not registered with the
# Command Runner poller.  SSH can still reach them — let it try.
# Only "unreachable" (network-level failure) should block SSH.
_CR_SKIP_ERRORS = (
    "unreachable",
)

# ── Device type mapping (from app_psirtlm.py) ─────────────────────────────────
DNAC_DEVICE_TYPE_MAP = {
    "Cisco Catalyst 9300 Series Switches":                   "cisco_xe",
    "Cisco Catalyst 9200 Series Switches":                   "cisco_xe",
    "Cisco Catalyst 9400 Series Switches":                   "cisco_xe",
    "Cisco Catalyst 9500 Series Switches":                   "cisco_xe",
    "Cisco Catalyst 9600 Series Switches":                   "cisco_xe",
    "Cisco ASR 1000 Series Routers":                         "cisco_xe",
    "Cisco ISR 4000 Series":                                 "cisco_xe",
    "Cisco Nexus 9000 Series Switches":                      "cisco_nxos",
    "Cisco Nexus 7000 Series Switches":                      "cisco_nxos",
    "Cisco Nexus 5000 Series Switches":                      "cisco_nxos",
    "Cisco ASR 9000 Series Aggregation Services Routers":    "cisco_xr",
    "Cisco NCS 5500 Series":                                 "cisco_xr",
}


def _dnac_device_type(family: str, series: str) -> str:
    """
    Map DNAC family/series strings to correct Netmiko device_type.
    Fixes the 'Unsupported device_type cisco_ios_xe' error.
    """
    for key, dtype in DNAC_DEVICE_TYPE_MAP.items():
        if key.lower() in (series or "").lower() or key.lower() in (family or "").lower():
            return dtype
    combined = f"{family} {series}".lower()
    if "nxos" in combined or "nexus" in combined:
        return "cisco_nxos"
    if "xr" in combined or "asr 9" in combined or "ncs" in combined:
        return "cisco_xr"
    return "cisco_xe"   # safe default for modern IOS XE devices


# ── DNAC advisory detail fetch ────────────────────────────────────────────────

def _fetch_advisory_detail_from_dnac(
    dnac_host: str, token: str, advisory_id: str, verify_ssl: bool = False,
) -> dict:
    """
    Fetch advisory detail from DNAC's security-advisory API.

    Calls two endpoints and merges the results:
      1. /security-advisory/advisory/{id}        — advisory-level detail
      2. /security-advisory/advisory/{id}/device — per-device list; contains
         patchVersion / fixedVersions that DNAC shows in its UI (e.g. "15.2(7)E14")
         but that the advisory-level endpoint often omits.
    """
    import requests, urllib3
    urllib3.disable_warnings()
    headers = {"X-Auth-Token": token, "Content-Type": "application/json"}
    base = f"https://{dnac_host}/dna/intent/api/v1"
    detail: dict = {}

    # 1. Advisory-level detail
    try:
        resp = requests.get(
            f"{base}/security-advisory/advisory/{advisory_id}",
            headers=headers, verify=verify_ssl, timeout=20,
        )
        if resp.status_code == 200:
            detail = resp.json().get("response", {}) or {}
    except Exception as exc:
        logger.debug("[PSIRT] DNAC advisory detail failed %s: %s", advisory_id, exc)

    # NOTE: DNAC's /security-advisory/advisory/{id}/device endpoint spawns async
    # background tasks (returns a list of ~18 task IDs, one per device).
    # Tasks take >10s each and never populate useful progress fields in testing.
    # Polling them would add 500+ API calls per scan (18 tasks × 29 advisories).
    # Skipped: devices on placeholder train versions (e.g. 15.2) are correctly
    # flagged AFFECTED via the placeholder-detection path in version_only_verdict.

    return detail


def _infer_fixed_releases_from_affected_versions(affected_versions: list) -> dict:
    """
    Parse GPT-extracted affected_versions strings such as:
      '16.12.x before 16.12.10'  →  {'16.12': '16.12.10'}
      '17.9.x before 17.9.5a'    →  {'17.9': '17.9.5a'}
    Returns an empty dict if nothing could be parsed.
    """
    fixed: dict = {}
    pattern = re.compile(
        r"(\d+\.\d+)(?:\.\w+)?\s+before\s+([\d]+\.[\d]+\.[\d]+[a-zA-Z]?)",
        re.IGNORECASE,
    )
    for av in (affected_versions or []):
        m = pattern.search(str(av))
        if m:
            train = m.group(1)
            first_fixed = m.group(2)
            if train not in fixed:          # keep first match per train
                fixed[train] = first_fixed
    return fixed


def _ver_train_simple(v: str) -> str:
    parts = re.findall(r"\d+", v)
    return f"{parts[0]}.{parts[1]}" if len(parts) >= 2 else (parts[0] if parts else "")


def _build_profile_from_dnac_detail(
    advisory_id: str, dnac_detail: dict, dnac_advisory: dict,
) -> dict:
    """Build a structured profile from DNAC's advisory detail response."""
    merged = {**dnac_advisory, **dnac_detail}

    fixed_releases: dict = {}

    # fixedVersions: list of dicts [{"version": "15.2(7)E14"}, ...]
    for fv in merged.get("fixedVersions", []) or []:
        if isinstance(fv, dict):
            ver = fv.get("version") or fv.get("fixedVersion") or ""
        else:
            ver = str(fv)
        train = _ver_train_simple(ver)
        if train and ver:
            fixed_releases[train] = ver

    # patchVersion: single string "15.2(7)E14" from advisory/device endpoint
    pv = merged.get("patchVersion") or merged.get("suggestedVersion") or \
         merged.get("recommendedSoftwareVersion") or ""
    if isinstance(pv, str) and pv.strip():
        for v in re.split(r"[,;\s]+", pv.strip()):
            v = v.strip()
            if v:
                train = _ver_train_simple(v)
                if train and train not in fixed_releases:
                    fixed_releases[train] = v
                    logger.info(
                        "[PSIRT] DNAC patchVersion for %s: %s → train %s",
                        advisory_id, v, train,
                    )

    fr = merged.get("fixedReleases") or merged.get("fixedRelease") or ""
    if isinstance(fr, list):
        for v in fr:
            train = _ver_train_simple(str(v))
            if train:
                fixed_releases[train] = str(v)
    elif isinstance(fr, str) and fr.strip():
        for v in re.split(r"[,;\s]+", fr.strip()):
            v = v.strip()
            if v:
                train = _ver_train_simple(v)
                if train:
                    fixed_releases[train] = v

    affected_versions: list[str] = []
    for av in merged.get("affectedVersions", []) or []:
        lv = av.get("lastVersion") or av.get("version") or ""
        if lv:
            affected_versions.append(lv)

    platforms = merged.get("affectedPlatforms") or merged.get("platforms") or []
    if isinstance(platforms, str):
        platforms = [p.strip() for p in re.split(r"[,;]", platforms) if p.strip()]

    cmds = merged.get("verificationCommands") or merged.get("cliCommands") or []
    if isinstance(cmds, str):
        cmds = [c.strip() for c in cmds.split("\n") if c.strip()]

    return {
        "vulnerable_feature": merged.get("vulnerableFeature") or merged.get("technology") or "",
        "affected_platforms": platforms,
        "affected_versions":  affected_versions,
        "fixed_releases":     fixed_releases,
        "verification_commands": cmds,
        "detection_type": (merged.get("defaultDetectionType") or "version").lower(),
        "workaround": merged.get("workaround") or merged.get("workAround") or None,
        "_source": "dnac_detail",
    }


# ── DNAC Command Runner ───────────────────────────────────────────────────────

_DNAC_CMD_LIMIT = 5   # DNAC Command Runner hard limit: max commands per request


def _dnac_run_commands(
    host: str, token: str, device_uuid: str,
    commands: list[str], verify_ssl: bool = False,
) -> dict:
    """
    Submit commands via DNAC Command Runner and poll for results.
    Automatically batches into groups of ≤5 if needed (DNAC limit).
    Returns {"status":"ok","outputs":{cmd:text}}
         or {"status":"error","skip_ssh":bool,"error":str}
    """
    # ── Batch if over the DNAC limit ─────────────────────────────────────────
    if len(commands) > _DNAC_CMD_LIMIT:
        merged: dict[str, str] = {}
        for i in range(0, len(commands), _DNAC_CMD_LIMIT):
            batch_result = _dnac_run_commands(
                host, token, device_uuid,
                commands[i : i + _DNAC_CMD_LIMIT],
                verify_ssl,
            )
            if batch_result["status"] == "error":
                return batch_result          # fail fast — let SSH fallback handle it
            merged.update(batch_result.get("outputs", {}))
        return {"status": "ok", "outputs": merged, "skip_ssh": False}

    import json as _json, time, requests, urllib3
    urllib3.disable_warnings()

    headers = {"X-Auth-Token": token, "Content-Type": "application/json"}
    base    = f"https://{host}/dna/intent/api/v1"

    try:
        resp = requests.post(
            f"{base}/network-device-poller/cli/read-request",
            headers=headers,
            json={"commands": commands, "deviceUuids": [device_uuid]},
            verify=verify_ssl, timeout=30,
        )
        if resp.status_code == 400:
            err_text = resp.text.lower()
            skip = any(s in err_text for s in _CR_SKIP_ERRORS)
            logger.warning(
                "[PSIRT] DNAC CR HTTP 400 for device %s: %s (skip_ssh=%s)",
                device_uuid, resp.text[:300], skip,
            )
            return {"status": "error", "skip_ssh": skip,
                    "error": f"HTTP 400: {resp.text[:300]}"}
        resp.raise_for_status()
        task_id = resp.json()["response"]["taskId"]
    except Exception as exc:
        return {"status": "error", "skip_ssh": False, "error": str(exc)}

    for _ in range(20):
        time.sleep(3)
        try:
            t = requests.get(
                f"{base}/task/{task_id}", headers=headers,
                verify=verify_ssl, timeout=15,
            ).json()["response"]
            progress = t.get("progress", "")
            completed = bool(t.get("endTime"))
            if not completed:
                try:
                    if _json.loads(progress).get("fileId"):
                        completed = True
                except Exception:
                    pass
            if completed:
                try:
                    file_id = _json.loads(progress).get("fileId")
                except Exception:
                    file_id = progress.strip() or None
                break
            if t.get("isError"):
                return {"status": "error", "skip_ssh": False,
                        "error": t.get("failureReason", "Task failed")}
        except Exception as exc:
            return {"status": "error", "skip_ssh": False, "error": str(exc)}
    else:
        return {"status": "error", "skip_ssh": False, "error": "Task polling timed out"}

    try:
        file_resp = requests.get(
            f"{base}/file/{file_id}", headers=headers,
            verify=verify_ssl, timeout=30,
        )
        file_resp.raise_for_status()
        cmd_responses = file_resp.json()
    except Exception as exc:
        return {"status": "error", "skip_ssh": False,
                "error": f"File fetch failed: {exc}"}

    outputs: dict[str, str] = {}
    for entry in cmd_responses:
        for status_key in ("SUCCESS", "FAILURE", "success", "failure"):
            for cmd, out in entry.get("commandResponses", {}).get(status_key, {}).items():
                outputs[cmd] = out
    return {"status": "ok", "outputs": outputs, "skip_ssh": False}


def _ssh_collect(ssh_cfg: dict, commands: list[str]) -> dict:
    """Direct SSH via Netmiko — fallback when DNAC Command Runner unavailable."""
    try:
        from netmiko import (ConnectHandler, NetmikoAuthenticationException,
                             NetmikoTimeoutException)
    except ImportError:
        return {"status": "error", "error": "netmiko not installed"}
    try:
        conn = ConnectHandler(**ssh_cfg)
        outputs: dict[str, str] = {}
        for cmd in commands:
            try:
                outputs[cmd] = conn.send_command(cmd, read_timeout=30)
            except Exception as exc:
                outputs[cmd] = f"[ERROR running command: {exc}]"
        conn.disconnect()
        return {"status": "ok", "outputs": outputs}
    except NetmikoAuthenticationException:
        return {"status": "error",
                "error": "SSH authentication failed — check credentials"}
    except NetmikoTimeoutException:
        return {"status": "error",
                "error": "SSH timed out — check host/port/reachability"}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


def _collect_compensating_outputs(
    profile: dict, device: dict,
    existing_outputs: dict,
    dnac_host: str, token: str, device_uuid: str,
    verify_ssl: bool, ssh_username: str, ssh_password: str,
) -> dict:
    """
    Fetch any extra compensating-control commands not already in existing_outputs.
    Returns merged outputs dict (existing_outputs is not mutated).
    """
    feature_key = (profile.get("vulnerable_feature") or "").lower()
    cc_commands = get_compensating_control_commands(feature_key)
    new_cmds    = [c for c in cc_commands if c not in existing_outputs]
    merged      = dict(existing_outputs)
    if not new_cmds:
        return merged

    # Try DNAC Command Runner first
    if device_uuid:
        cc_result = _dnac_run_commands(dnac_host, token, device_uuid, new_cmds, verify_ssl)
        if cc_result["status"] == "ok":
            merged.update(cc_result["outputs"])
            return merged

    # SSH fallback
    dev_host = device.get("managementIpAddress") or device.get("host", "")
    dev_user = device.get("username") or ssh_username
    dev_pass = device.get("password") or ssh_password
    if dev_host and dev_user and dev_pass:
        ssh_cfg = {
            "host":        dev_host,
            "port":        int(device.get("port", 22)),
            "username":    dev_user,
            "password":    dev_pass,
            "device_type": _dnac_device_type(
                               device.get("family", ""), device.get("series", "")),
            "timeout":     30,
            "auth_timeout": 20,
        }
        cc_result = _ssh_collect(ssh_cfg, new_cmds)
        if cc_result["status"] == "ok":
            merged.update(cc_result["outputs"])

    return merged


# ── Per-pair scan ─────────────────────────────────────────────────────────────

def _run_scan_for_pair(
    advisory: dict,
    device: dict,
    dnac_host: str,
    token: str,
    dnac_id: Optional[str],
    verify_ssl: bool,
    scan_triggered_at: str,
    ssh_username: str = "",
    ssh_password: str = "",
) -> None:
    advisory_id = advisory.get("advisoryId", "")
    device_id   = device.get("instanceUuid") or device.get("id", "")
    hostname    = device.get("hostname") or device.get("managementIpAddress", "unknown")
    mgmt_ip     = device.get("managementIpAddress", "")
    platform      = device.get("platformId") or device.get("series", "Unknown")
    family        = device.get("family", "")
    software_type = device.get("softwareType", "")   # e.g. "IOS", "IOS-XE"
    sw_version    = device.get("softwareVersion", "")

    logger.info("[PSIRT] Processing %s × %s (%s)", advisory_id, hostname, device_id)

    # ── Mark PENDING ──────────────────────────────────────────────────────────
    upsert_applicability_pending(
        advisory_id=advisory_id, device_id=device_id, hostname=hostname,
        management_ip=mgmt_ip, platform=platform, software_version=sw_version,
        dnac_id=dnac_id, scan_triggered_at=scan_triggered_at,
    )

    # ── Build advisory profile ────────────────────────────────────────────────
    # Priority: ChromaDB → DNAC detail API → Cisco portal JSON → GPT extraction
    profile = get_advisory_profile_from_cache(advisory_id)
    if profile:
        logger.info("[PSIRT] %s: profile from ChromaDB cache.", advisory_id)
    else:
        # Try DNAC detail API first (has version data, no external dependency)
        dnac_detail = _fetch_advisory_detail_from_dnac(
            dnac_host, token, advisory_id, verify_ssl)
        profile = _build_profile_from_dnac_detail(advisory_id, dnac_detail, advisory)

        # If no fixed_releases from DNAC, try Cisco portal + GPT
        if not profile.get("fixed_releases"):
            logger.info("[PSIRT] %s: DNAC detail had no fixed_releases, trying Cisco portal + GPT", advisory_id)
            dnac_summary = (
                f"Advisory ID: {advisory_id}\n"
                f"CVE(s): {', '.join(advisory.get('cves', [])) or advisory.get('cveId', 'N/A')}\n"
                f"Security Impact Rating: {advisory.get('sir', 'N/A')}\n"
                f"CVSS Base Score: {advisory.get('cvssBaseScore', 'N/A')}\n"
                f"Publication URL: {advisory.get('publicationUrl', 'N/A')}\n"
                f"Detection Type: {advisory.get('defaultDetectionType', 'N/A')}\n"
            )
            cisco_full = fetch_cisco_advisory_text(advisory_id)
            if cisco_full:
                advisory_text = dnac_summary + "\n\n--- Full Cisco Advisory ---\n" + cisco_full
            else:
                advisory_text = dnac_summary
                if dnac_detail:
                    advisory_text += f"\nDNAC Detail: {json.dumps(dnac_detail, default=str)[:8000]}"

            gpt_profile = extract_advisory_profile(advisory_text, advisory_id=advisory_id)
            logger.info(
                "[PSIRT] %s: GPT extracted fixed_releases=%s affected_versions=%s",
                advisory_id,
                gpt_profile.get("fixed_releases"),
                gpt_profile.get("affected_versions"),
            )
            # Merge GPT results into DNAC-derived profile.
            # Only accept fixed_releases if the keys look like version trains
            # (e.g. "17.9", "16.12") — reject product-name keys like "IOS XE"
            # or "Meraki CS" that GPT occasionally hallucinates when the advisory
            # has no static Fixed Software table.
            _TRAIN_RE = re.compile(r'^\d+\.\d+')
            gpt_fr = gpt_profile.get("fixed_releases") or {}
            valid_gpt_fr = {k: v for k, v in gpt_fr.items() if _TRAIN_RE.match(str(k))}
            if len(valid_gpt_fr) < len(gpt_fr):
                logger.warning(
                    "[PSIRT] %s: GPT fixed_releases had %d invalid keys (non-train), kept %d: %s",
                    advisory_id, len(gpt_fr) - len(valid_gpt_fr), len(valid_gpt_fr), valid_gpt_fr,
                )
            if valid_gpt_fr:
                profile["fixed_releases"] = valid_gpt_fr
            if not profile.get("affected_versions"):
                profile["affected_versions"] = gpt_profile.get("affected_versions", [])
            if not profile.get("verification_commands"):
                profile["verification_commands"] = gpt_profile.get("verification_commands", [])
            if not profile.get("affected_platforms"):
                profile["affected_platforms"] = gpt_profile.get("affected_platforms", [])
            if not profile.get("vulnerable_feature"):
                profile["vulnerable_feature"] = gpt_profile.get("vulnerable_feature", "")
            if not profile.get("workaround"):
                profile["workaround"] = gpt_profile.get("workaround")

            # Last-resort: infer fixed_releases from affected_versions strings
            # e.g. "16.12.x before 16.12.10" → {"16.12": "16.12.10"}
            if not profile.get("fixed_releases") and profile.get("affected_versions"):
                inferred = _infer_fixed_releases_from_affected_versions(
                    profile["affected_versions"]
                )
                if inferred:
                    logger.info(
                        "[PSIRT] %s: inferred fixed_releases from affected_versions: %s",
                        advisory_id, inferred,
                    )
                    profile["fixed_releases"] = inferred

            # openVuln API fallback: HTML had no static table (Software Checker advisory)
            if not profile.get("fixed_releases"):
                logger.info("[PSIRT] %s: GPT+HTML yielded no version data — trying openVuln API", advisory_id)
                openvuln_fixed = fetch_fixed_releases_openvuln(advisory_id)
                if openvuln_fixed:
                    logger.info("[PSIRT] %s: openVuln API fixed_releases=%s", advisory_id, openvuln_fixed)
                    profile["fixed_releases"] = openvuln_fixed
                    save_advisory_profile_to_cache(advisory_id, profile)
                else:
                    logger.warning("[PSIRT] %s: openVuln API also returned no version data", advisory_id)

        # Only cache profiles that actually contain version data
        if profile and (profile.get("fixed_releases") or profile.get("affected_versions")):
            save_advisory_profile_to_cache(advisory_id, profile)
        elif profile:
            logger.warning(
                "[PSIRT] %s: skipping ChromaDB cache — profile has no version data "
                "(fixed_releases=%s, affected_versions=%s)",
                advisory_id,
                profile.get("fixed_releases"),
                profile.get("affected_versions"),
            )

    # ── Inference fallback (runs for both cached and fresh profiles) ──────────
    # A cached profile may have affected_versions but no fixed_releases if it
    # was stored before this fix. Try to infer fixed_releases from it now.
    if profile and not profile.get("fixed_releases") and profile.get("affected_versions"):
        inferred = _infer_fixed_releases_from_affected_versions(profile["affected_versions"])
        if inferred:
            logger.info(
                "[PSIRT] %s: inferred fixed_releases from cached affected_versions: %s",
                advisory_id, inferred,
            )
            profile["fixed_releases"] = inferred
            # Update the cache with the now-complete profile
            save_advisory_profile_to_cache(advisory_id, profile)

    if not profile:
        update_applicability_result(
            advisory_id, device_id, dnac_id,
            verdict="NEEDS_REVIEW",
            summary="Advisory profile could not be built from DNAC or GPT.",
            evidence="", collection_method="failed",
            needs_review_reason="collection_failed",
        )
        return

    # ── Guard: no fixed_releases → NEEDS_REVIEW ───────────────────────────────
    if not profile.get("fixed_releases"):
        logger.warning(
            "[PSIRT] %s: no fixed_releases after all extraction attempts "
            "(affected_versions=%s) — marking NEEDS_REVIEW",
            advisory_id, profile.get("affected_versions"),
        )
        update_applicability_result(
            advisory_id, device_id, dnac_id,
            verdict="NEEDS_REVIEW",
            summary=(
                f"No fixed release data available for this advisory. "
                f"Manual review required for {hostname} running {sw_version}."
            ),
            evidence=f"advisory_id={advisory_id}, device_version={sw_version}",
            layer1="UNKNOWN", layer2="UNKNOWN", layer3="UNKNOWN",
            collection_method="no_version_data",
            needs_review_reason="no_fixed_release",
            remediation=build_remediation_tier1(profile),
        )
        return

    # ── Determine commands ────────────────────────────────────────────────────
    advisory_cmds = profile.get("verification_commands") or []
    feature_key   = (profile.get("vulnerable_feature") or "").lower()
    if advisory_cmds:
        commands = list(dict.fromkeys(ALWAYS_RUN + advisory_cmds))
    else:
        commands = list(dict.fromkeys(ALWAYS_RUN + resolve_feature_commands(feature_key)))

    # ── DNAC Command Runner ───────────────────────────────────────────────────
    collection_method = "dnac_command_runner"
    skip_ssh          = False
    collect_result    = {"status": "error", "skip_ssh": True,
                         "error": "No device UUID"}

    if device_id:
        collect_result = _dnac_run_commands(
            dnac_host, token, device_id, commands, verify_ssl)
        skip_ssh = collect_result.get("skip_ssh", False)

    # ── SSH fallback ──────────────────────────────────────────────────────────
    if collect_result["status"] == "error" and not skip_ssh:
        dev_host = mgmt_ip or device.get("host", "")
        dev_user = device.get("username") or ssh_username
        dev_pass = device.get("password") or ssh_password
        dev_type = _dnac_device_type(family, platform)   # ← fixed device_type

        if dev_host and dev_user and dev_pass:
            logger.info("[PSIRT] DNAC CR failed (%s) — retrying SSH for %s",
                        collect_result.get("error", ""), hostname)
            collect_result = _ssh_collect({
                "host":         dev_host,
                "port":         int(device.get("port", 22)),
                "username":     dev_user,
                "password":     dev_pass,
                "device_type":  dev_type,
                "timeout":      30,
                "auth_timeout": 20,
            }, commands)
            collection_method = "ssh_fallback"
            if collect_result["status"] == "ok":
                logger.info("[PSIRT] SSH fallback succeeded for %s", hostname)
            else:
                logger.info("[PSIRT] SSH fallback also failed for %s: %s",
                            hostname, collect_result.get("error", ""))

    # ── Version-only fallback ─────────────────────────────────────────────────
    if collect_result["status"] == "error":
        logger.info(
            "[PSIRT] Version-only assessment for %s × %s: "
            "sw_version=%s  cr_error=%s  skip_ssh=%s",
            advisory_id, hostname, sw_version,
            collect_result.get("error", "")[:120], skip_ssh,
        )
        ver_verdict = version_only_verdict(profile, sw_version, platform, software_type)
        cr_err = collect_result.get("error", "")
        workaround = profile.get("workaround")
        layer4_result = (
            "NO_WORKAROUND" if not workaround
            else "UNKNOWN" if ver_verdict == "AFFECTED"
            else "UNKNOWN"
        )
        update_applicability_result(
            advisory_id, device_id, dnac_id,
            verdict=ver_verdict,
            summary=(
                f"Command collection failed ({cr_err[:120]}). "
                f"Version-only assessment: {sw_version} → {ver_verdict}."
            ),
            evidence=(
                f"fixed_releases={profile.get('fixed_releases')}, "
                f"device_version={sw_version}"
            ),
            layer1="UNKNOWN",
            layer2=("PASS" if ver_verdict == "AFFECTED"
                    else "FAIL" if ver_verdict == "NOT_AFFECTED"
                    else "UNKNOWN"),
            layer3="UNKNOWN",
            layer4=layer4_result,
            collection_method=("version_only" if ver_verdict != "NEEDS_REVIEW"
                               else "version_only_insufficient"),
            needs_review_reason=("insufficient_data" if ver_verdict == "NEEDS_REVIEW" else ""),
            remediation=build_remediation_tier1(profile),
        )
        return

    # ── Full 4-layer GPT analysis ─────────────────────────────────────────────
    logger.info("[PSIRT] Running 4-layer GPT analysis for %s × %s",
                advisory_id, hostname)
    analysis = analyse_applicability(
        advisory_profile=profile,
        device={"hostname": hostname, "platform": platform, "version": sw_version},
        command_outputs=collect_result.get("outputs", {}),
    )
    verdict = analysis.get("verdict", "NEEDS_REVIEW")
    summary = analysis.get("summary", "")

    # ── Compensating controls check (AFFECTED only) ──────────────────────────
    # The LLM's own "mitigated" judgment is authoritative: if it decides the
    # existing device configuration compensates for (blocks exploitation of)
    # this vulnerability, the verdict is reclassified from AFFECTED to
    # NOT_AFFECTED. No separate confidence gate is applied in code — that
    # decision is left entirely to the LLM call in check_compensating_controls().
    mitigation = None
    if verdict == "AFFECTED":
        logger.info("[PSIRT] Checking compensating controls for %s × %s",
                    advisory_id, hostname)
        try:
            merged_outputs = _collect_compensating_outputs(
                profile=profile,
                device=device,
                existing_outputs=collect_result.get("outputs", {}),
                dnac_host=dnac_host,
                token=token,
                device_uuid=device_id,
                verify_ssl=verify_ssl,
                ssh_username=ssh_username,
                ssh_password=ssh_password,
            )
            mitigation = check_compensating_controls(
                advisory_profile=profile,
                device={"hostname": hostname, "platform": platform, "version": sw_version},
                command_outputs=merged_outputs,
            )
            if mitigation.get("mitigated"):
                logger.info(
                    "[PSIRT] %s × %s → AFFECTED reclassified as NOT_AFFECTED "
                    "(compensating controls found, confidence: %s)",
                    advisory_id, hostname, mitigation.get("mitigation_confidence"),
                )
                verdict = "NOT_AFFECTED"
                summary = (
                    f"Reclassified NOT_AFFECTED — compensating controls mitigate "
                    f"exploitation ({mitigation.get('mitigation_confidence', 'UNKNOWN')} "
                    f"confidence). {mitigation.get('mitigation_summary', '')} "
                    f"[Original AFFECTED assessment: {summary}]"
                )
        except Exception as exc:
            logger.warning("[PSIRT] Compensating controls check failed: %s", exc)

    # Extract layer detail strings
    def _layer_result(key: str) -> str:
        l = analysis.get(key, {})
        if isinstance(l, dict):
            return l.get("result", "")
        return str(l)

    update_applicability_result(
        advisory_id, device_id, dnac_id,
        verdict=verdict,
        summary=summary,
        evidence=analysis.get("evidence", ""),
        action=analysis.get("action", ""),
        layer1=_layer_result("layer1"),
        layer2=_layer_result("layer2"),
        layer3=_layer_result("layer3"),
        layer4=_layer_result("layer4"),
        collection_method=collection_method,
        mitigation=mitigation,
        needs_review_reason=("insufficient_data" if verdict == "NEEDS_REVIEW" else ""),
        remediation=build_remediation_tier1(profile),
    )
    logger.info("[PSIRT] %s × %s → %s", advisory_id, hostname, verdict)


# ── Background worker ─────────────────────────────────────────────────────────

def _background_scan_worker(
    advisories: list[dict],
    devices_by_uuid: dict[str, dict],
    dnac_host: str,
    token: str,
    dnac_id: Optional[str],
    verify_ssl: bool,
    scan_triggered_at: str,
    ssh_username: str = "",
    ssh_password: str = "",
) -> None:
    logger.info("[PSIRT] Background scan started — %d advisories, dnac_id=%s",
                len(advisories), dnac_id)
    total, errors = 0, 0

    for advisory in advisories:
        advisory_id            = advisory.get("advisoryId", "")
        affected_device_uuids: list[str] = advisory.get("affected_devices", [])
        if not affected_device_uuids:
            continue

        for uuid in affected_device_uuids:
            device = devices_by_uuid.get(uuid) or {
                "instanceUuid": uuid, "id": uuid, "hostname": uuid,
                "managementIpAddress": "", "softwareVersion": "",
                "platformId": "", "family": "", "series": "",
            }
            # Inject job-level SSH creds without mutating shared dict
            if ssh_username and "username" not in device:
                device = dict(device)
                device["username"] = ssh_username
                device["password"] = ssh_password

            try:
                _run_scan_for_pair(
                    advisory=advisory, device=device,
                    dnac_host=dnac_host, token=token, dnac_id=dnac_id,
                    verify_ssl=verify_ssl, scan_triggered_at=scan_triggered_at,
                    ssh_username=ssh_username, ssh_password=ssh_password,
                )
                total += 1
            except Exception as exc:
                errors += 1
                logger.error("[PSIRT] Error processing %s × %s: %s",
                             advisory_id, uuid, exc, exc_info=True)

    logger.info("[PSIRT] Scan finished. Pairs: %d, errors: %d", total, errors)


# ── Public trigger API ────────────────────────────────────────────────────────

def trigger_applicability_scan(
    dnac,
    dnac_id: Optional[str] = None,
    verify_ssl: bool = False,
    ssh_username: str = "",
    ssh_password: str = "",
) -> str:
    scan_triggered_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

    try:
        from db.quries_postgresql import collect_impacted_advisories
        from db.database_postgresql import PostgreSQLConnector
    except Exception:
        try:
            from vulnerebility_management.db.quries_postgresql import collect_impacted_advisories
            from vulnerebility_management.db.database_postgresql import PostgreSQLConnector
        except Exception as exc:
            logger.error("[PSIRT] Could not load DB functions: %s", exc)
            return scan_triggered_at

    # NOTE: previously this sourced devices/advisories from the legacy,
    # unscoped 'devices'/'advisories' collections (all_devices()/all_advisories()),
    # which ignored dnac_id entirely and caused every DNAC instance's scan to
    # process the exact same static device snapshot. Fixed to source from the
    # dnac_id-scoped 'impactedadvisories'/'impacteddevices' tables instead, so
    # each DNAC's scan only ever touches its own inventory.
    try:
        advisories = collect_impacted_advisories(dnac_id=dnac_id)

        # Pull full raw device docs for THIS dnac_id only. A raw find (not
        # collect_impacted_devices()'s narrow projection) is used so
        # platformId/family/series/softwareType/instanceUuid — needed by the
        # device-type mapping and SSH fallback logic below — are preserved.
        _db = PostgreSQLConnector("AdvisoryDatabase")
        _device_collection = _db.collection("impacteddevices")
        raw_devices = _device_collection.find({"dnac_id": dnac_id} if dnac_id is not None else {})
        _db.close()

        devices_by_uuid = {
            (d.get("instanceUuid") or d.get("id", "")): d
            for d in raw_devices
        }
        known_uuids = set(devices_by_uuid.keys())

        # CORRECTION: impacteddevices documents do NOT actually carry a
        # populated advisoryIds field — that field is just whatever DNAC's
        # /network-device API returns, which has no per-device advisory
        # association at all. Inverting it (as a first attempt at this fix
        # did) silently produced empty affected_devices for every advisory
        # (observed as "Pairs: 0" in the scan log). DNAC only exposes the
        # advisory<->device relationship via a dedicated per-advisory API —
        # the same call the legacy store_advisory_data() used
        # (dnac.get_devices_per_advisory). Fetch it here instead, scoped to
        # devices that actually belong to this dnac_id.
        for advisory in advisories:
            advisory_id = advisory.get("advisoryId", "")
            try:
                resp = dnac.get_devices_per_advisory(advisory_id)
                device_uuids = resp.get("response", []) or []
            except Exception as fetch_exc:
                logger.warning(
                    "[PSIRT] Could not fetch affected devices for advisory %s: %s",
                    advisory_id, fetch_exc,
                )
                device_uuids = []
            advisory["affected_devices"] = [uuid for uuid in device_uuids if uuid in known_uuids]
            logger.info(
                "[PSIRT] %s: %d device(s) affected (dnac_id=%s)",
                advisory_id, len(advisory["affected_devices"]), dnac_id,
            )

    except Exception as exc:
        logger.error("[PSIRT] Could not load advisories/devices from DB: %s", exc)
        return scan_triggered_at

    if not advisories:
        logger.info("[PSIRT] No advisories in DB — scan skipped.")
        return scan_triggered_at

    # Resolve DNAC host
    try:
        from config import DNAC_INSTANCES
        cfg       = DNAC_INSTANCES.get(dnac_id or "", {})
        dnac_host = cfg.get("host") or getattr(dnac, "host", "")
    except Exception:
        dnac_host = getattr(dnac, "host", "")

    # Get token from DNAC client header
    try:
        token = dnac.header.get("x-auth-token", "")
        if not token:
            dnac.login()
            token = dnac.header.get("x-auth-token", "")
        if not token:
            logger.error("[PSIRT] Empty DNAC token — aborting scan.")
            return scan_triggered_at
    except Exception as exc:
        logger.error("[PSIRT] Token error: %s", exc)
        return scan_triggered_at

    # Wipe stale results for this DNAC before writing fresh ones
    clear_applicability_results(dnac_id)

    thread = threading.Thread(
        target=_background_scan_worker,
        args=(advisories, devices_by_uuid, dnac_host, token,
              dnac_id, verify_ssl, scan_triggered_at, ssh_username, ssh_password),
        daemon=True,
        name=f"psirt-scan-{dnac_id or 'default'}-{scan_triggered_at[:19]}",
    )
    thread.start()
    logger.info("[PSIRT] Scan thread started: %s", thread.name)
    return scan_triggered_at