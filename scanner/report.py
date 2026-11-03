from __future__ import annotations

import asyncio
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from scanner.agent import EXECUTING, investigate, should_investigate, tranco_checked_safe
from scanner.classify import classify, set_aside
from dataclasses import dataclass, field

from scanner.config import (
    EXPIRY_INVESTIGATE_DAYS,
    LLM_MAX_RETRIES,
    RANK_CONCURRENCY,
    RANK_MODEL,
    RANK_REASONING_EFFORT,
    SCAN_COST_CAP_USD,
)
from scanner.events import (
    OnEvent,
    classified_public,
    emit,
    finding_public,
    gather_public,
    public_target,
)
from scanner.compromised import (
    POLYFILL_FIX,
    SRI_FIX,
    compromised_status,
    is_polyfill_host,
)
from scanner.extract import (
    empty_coverage,
    extract_scan,
    github_login,
    is_bucket_ref,
    is_github_action_ref,
    is_github_owner_ref,
    is_website_source,
    website_coverage,
)
from scanner.tranco import tranco_rank
from scanner.website import extract_website
from scanner.llm import CallLog, ModelClient, call_json, is_model_transport_error
from scanner.lookups import LookupCache, consistent_evidence, merge_evidence
from scanner.models import (
    Classification,
    Finding,
    Investigation,
    RankModelOut,
    Reference,
    Severity,
)
from scanner.tools import ToolContext


@dataclass
class ScanOutcome:
    findings: list[Finding]
    investigations: list[Investigation] = field(default_factory=list)
    classify_cost_usd: float = 0.0
    agent_cost_usd: float = 0.0
    rank_cost_usd: float = 0.0
    budget_targets: list[str] = field(default_factory=list)
    coverage: dict[str, object] = field(default_factory=lambda: empty_coverage().as_dict())

    @property
    def cost_usd(self) -> float:
        return self.classify_cost_usd + self.agent_cost_usd + self.rank_cost_usd

CLAIMABLE_FIX = (
    "Remove or replace this reference. If this was yours, re-create it in your own "
    "account to reclaim the name."
)
ACTION_PIN_FIX = "Pin to a full commit SHA."
RANK_TIME_NOTE = "Not ranked by the model: the scan ran out of time on this host, so code rules set the severity."
ACTION_MISSING_FIX = (
    "Remove or replace this action. If this was yours, re-create it in your own "
    "account to reclaim the name. Pin to a full commit SHA."
)
ACTION_DISABLED_FIX = (
    "Replace this action: GitHub has disabled its repository, so CI cannot read "
    "what it runs. Pin the replacement to a full commit SHA."
)
NO_ACTION_FIX = "No action needed"
FIX_SENTENCES = {
    "remove dead reference": (
        "Remove this reference; it points to a host that no longer resolves."
    ),
    "self-host the asset": (
        "Self-host this asset so you are not depending on a third-party origin "
        "you do not control."
    ),
    "pin with subresource integrity": (
        "Add a subresource integrity hash, or self-host this script, so a "
        "taken-over host cannot change what browsers run."
    ),
    "re-register what you abandoned": (
        "Re-register this name in your own account, or remove the reference if "
        "you no longer need it."
    ),
    "replace with maintained source": (
        "Replace this with a source that is still maintained."
    ),
}
STATIC_TAGS = frozenset({"img", "source", "link"})
STATIC_SUFFIXES = (
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".otf",
)
DOWNLOAD_TYPES = frozenset({"script", "api"})
UNKNOWN_STATUSES = frozenset({"unavailable", "error", "timeout", "unknown"})
BANNED_FIELD_NAMES = ("rdap", "runs_in", "blast_radius", "status")
RUNS_IN_PHRASE = {
    "browser": "in the browser",
    "server": "on the server",
    "build": "at build time",
    "deploy": "in deploy",
    "ci": "in CI",
    "test": "in tests",
    "docs_only": "in docs",
}
SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}
# Fix today is critical or high, and only a code rule puts a target there.
FIX_TODAY = frozenset({"critical", "high"})
MODEL_CEILING: Severity = "medium"
DATE_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")
NUM_RE = re.compile(r"\b\d+\b")
REGION_RE = re.compile(r"\b[a-z]{2}-[a-z]+-\d+\b", re.IGNORECASE)
STATUS_PHRASES = (
    "does not exist",
    "doesn't exist",
    "do not exist",
    "nosuchbucket",
    "nxdomain",
    "unregistered",
    "registered",
    "exists",
    "accessdenied",
    "permanentredirect",
    "resolves",
    "forbidden",
)
# If evidence has any token in a row, every token in that row is the same fact.
STATUS_MEANING = (
    frozenset({"nosuchbucket", "404", "does not exist", "doesn't exist", "do not exist"}),
    frozenset({"nxdomain"}),
    frozenset({"unregistered"}),
    frozenset({"registered"}),
    frozenset({"exists", "403", "accessdenied", "forbidden"}),
    frozenset({"permanentredirect", "301"}),
    frozenset({"resolves"}),
)

GITHUB_OWNER_NOTE = (
    "GitHub may retire popular repository names after an owner is deleted or "
    "renamed, which can block this exact path."
)

RANK_SYSTEM_PROMPT = (
    "You rank takeover risk for one outside target (a bucket or a registrable domain). "
    "Use only the supplied classification and evidence. Do not invent dates, DNS results, "
    "HTTP statuses, or counts. "
    "risk is 1-2 plain-English sentences for a developer: what a stranger could do and "
    "where it lands in the repo. Do not use field names such as rdap, runs_in, "
    "blast_radius, or status. "
    "A lookup whose status is unavailable or error is unknown: never treat it as "
    "evidence for or against risk. "
    "A registered, resolving, actively used domain that renews soon is routine. "
    "tranco_rank is popularity context only: never lower severity below a code floor, "
    "and never treat popularity as a reason to ignore a compromised or claimable-now "
    "target. "
    "Expiry matters when combined with signs of abandonment (DNS does not resolve, "
    "or the owner has shut down). Do not raise severity for expiry alone. "
    "You may raise or lower blast_radius versus classify when evidence shows the "
    "reference matters more or less; if you change it, set blast_override_reason. "
    "fix must be one of the allowed values."
)

RANK_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "severity": {
            "type": "string",
            "enum": ["critical", "high", "medium", "low", "info"],
        },
        "risk": {"type": "string"},
        "fix": {
            "type": "string",
            "enum": [
                "remove dead reference",
                "self-host the asset",
                "pin with subresource integrity",
                "re-register what you abandoned",
                "replace with maintained source",
            ],
        },
        "uncertain_about": {"type": "string"},
        "blast_radius": {"type": "integer", "minimum": 0, "maximum": 3},
        "blast_override_reason": {"type": "string"},
    },
    "required": [
        "severity",
        "risk",
        "fix",
        "uncertain_about",
        "blast_radius",
        "blast_override_reason",
    ],
    "additionalProperties": False,
}


def target_key(ref: Reference, cl: Classification) -> tuple[str, str]:
    # One definition, shared with the events the page groups by.
    return public_target(ref, cl)


def group_by_target(
    rows: list[tuple[Reference, Classification, Investigation]],
) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for ref, cl, inv in rows:
        key, kind = target_key(ref, cl)
        if key not in groups:
            groups[key] = {
                "target": key,
                "kind": kind,
                "rows": [],
                "evidence": {},
            }
            order.append(key)
        groups[key]["rows"].append((ref, cl, inv))
        groups[key]["evidence"] = merge_evidence([groups[key]["evidence"], inv.evidence])
    return [groups[key] for key in order]


def finding_payload(group: dict[str, Any]) -> dict[str, Any]:
    rows: list[tuple[Reference, Classification, Investigation]] = group["rows"]
    raws = [ref.raw for ref, _, _ in rows]
    regions = sorted({match.group(0).lower() for raw in raws for match in REGION_RE.finditer(raw)})
    bucket = (group.get("evidence") or {}).get("bucket_probe") or {}
    provider = bucket.get("provider") or ""
    return {
        "target": group["target"],
        "kind": group["kind"],
        "reference_count": len(rows),
        "classified_blast_radius": max(cl.blast_radius for _, cl, _ in rows),
        "provider": provider,
        "regions": regions,
        "references": [
            {
                "file": ref.file,
                "line": ref.line,
                "file_line": f"{ref.file}:{ref.line}",
                "raw": ref.raw,
                "host_or_bucket": ref.host_or_bucket,
                "type": cl.type,
                "runs_in": cl.runs_in,
                "blast_radius": cl.blast_radius,
                "reason": cl.reason,
                "action_ref": ref.action_ref,
                "action_sha_pinned": ref.action_sha_pinned,
            }
            for ref, cl, _ in rows
        ],
        "evidence": usable_evidence(group["evidence"]),
    }


def usable_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    usable: dict[str, Any] = {}
    for name, value in evidence.items():
        if isinstance(value, dict):
            status = str(value.get("status", "")).lower()
            if status in UNKNOWN_STATUSES:
                continue
        usable[name] = value
    return usable


def claims_from_risk(risk: str) -> list[str]:
    claims = DATE_RE.findall(risk) + NUM_RE.findall(risk) + REGION_RE.findall(risk)
    folded = risk.casefold()
    for phrase in STATUS_PHRASES:
        if phrase in folded:
            claims.append(phrase)
    return claims


def _meaning_allowed(claim: str, blob: str) -> bool:
    token = claim.casefold()
    if token in blob:
        return True
    for group in STATUS_MEANING:
        if token not in group:
            continue
        if any(member in blob for member in group):
            return True
    return False


def missing_claims(risk: str, allowed: dict[str, Any] | None = None, evidence: dict[str, Any] | None = None) -> list[str]:
    payload = allowed if allowed is not None else {"evidence": usable_evidence(evidence or {})}
    blob = json.dumps(payload, default=str).casefold()
    missing = []
    for claim in claims_from_risk(risk):
        if not _meaning_allowed(claim, blob):
            missing.append(claim)
    return missing


def banned_fields(risk: str) -> list[str]:
    found = []
    for name in BANNED_FIELD_NAMES:
        if re.search(rf"\b{re.escape(name)}\b", risk, re.IGNORECASE):
            found.append(name)
    return found


def cited_unknown(risk: str, evidence: dict[str, Any]) -> list[str]:
    folded = risk.casefold()
    hits: list[str] = []
    for name, value in evidence.items():
        if not isinstance(value, dict):
            continue
        status = str(value.get("status", "")).lower()
        if status not in UNKNOWN_STATUSES:
            continue
        if name.casefold() in folded or status in folded:
            hits.append(name)
    return hits


def executing_runs_in(rows: list[tuple[Reference, Classification, Investigation]]) -> bool:
    return any(cl.runs_in in EXECUTING for _, cl, _ in rows)


def is_claimable(evidence: dict[str, Any]) -> bool:
    evidence = consistent_evidence(evidence)
    bucket = evidence.get("bucket_probe") or {}
    rdap = evidence.get("rdap") or {}
    owner = evidence.get("github_owner") or {}
    platform = evidence.get("platform_takeover") or {}
    if bucket.get("status") == "NoSuchBucket":
        return True
    if str(rdap.get("status", "")).lower() == "unregistered":
        return True
    if str(owner.get("status", "")).lower() == "missing":
        return True
    return (
        str(platform.get("status", "")).lower() == "unclaimed"
        and str(platform.get("takeover") or "") == "vulnerable"
    )


def has_risk_signal(evidence: dict[str, Any]) -> bool:
    usable = usable_evidence(evidence)
    if is_claimable(usable):
        return True
    dns = usable.get("dns") or {}
    rdap = usable.get("rdap") or {}
    platform = usable.get("platform_takeover") or {}
    if str(dns.get("status", "")).lower() == "nxdomain":
        return True
    if str(platform.get("status", "")).lower() == "unclaimed":
        return True
    repo = usable.get("github_repo") or {}
    if str(repo.get("status", "")).lower() in {"missing", "disabled"}:
        return True
    days = rdap.get("days_to_expiry")
    if isinstance(days, int) and days <= EXPIRY_INVESTIGATE_DAYS:
        return True
    live = usable.get("live_fetch") or {}
    return bool(live.get("parked") or live.get("for_sale"))


def _browser_script_rows(
    rows: list[tuple[Reference, Classification, Investigation]],
) -> list[tuple[Reference, Classification, Investigation]]:
    return [
        (ref, cl, inv)
        for ref, cl, inv in rows
        if cl.runs_in == "browser"
        and (ref.tag == "script" or cl.type == "script")
    ]


def _all_browser_scripts_sri(
    rows: list[tuple[Reference, Classification, Investigation]],
) -> bool:
    scripts = _browser_script_rows(rows)
    return bool(scripts) and all(ref.sri is True for ref, _cl, _inv in scripts)


def human_fix(fix: str) -> str:
    return FIX_SENTENCES.get(fix, fix)


def _is_static_asset(ref: Reference, cl: Classification) -> bool:
    if ref.tag == "iframe":
        return False
    blob = f"{ref.context} {ref.file} {ref.raw}".lower()
    if "product_image" in blob:
        return True
    if cl.type in DOWNLOAD_TYPES:
        return False
    if cl.type == "asset" or ref.tag in STATIC_TAGS:
        return True
    path = (ref.raw or "").split("?", 1)[0].lower()
    return path.endswith(STATIC_SUFFIXES)


def _has_download_ref(group: dict[str, Any]) -> bool:
    for ref, cl, _inv in group.get("rows") or []:
        if cl.runs_in not in EXECUTING:
            continue
        if _is_static_asset(ref, cl):
            continue
        return True
    return False


def _has_static_asset(group: dict[str, Any]) -> bool:
    return any(
        cl.runs_in in EXECUTING and _is_static_asset(ref, cl)
        for ref, cl, _inv in group.get("rows") or []
    )


def _claimable_now_floor(
    group: dict[str, Any], signal: str, where: str
) -> tuple[str | None, str]:
    if _has_download_ref(group):
        return _claimable_sri_floor(
            "critical",
            f"{signal} for a script/api/config download in executing position "
            f"({where}) is at least critical",
            group,
        )
    if _has_static_asset(group):
        return (
            "high",
            f"{signal} for a static asset in executing position ({where}) "
            "is at least high",
        )
    return _claimable_sri_floor(
        "critical",
        f"{signal} in executing position ({where}) is at least critical",
        group,
    )


def _group_compromised(
    group: dict[str, Any],
) -> str | None:
    names: list[str] = [group.get("target") or ""]
    for ref, _cl, _inv in group.get("rows") or []:
        names.append(ref.host_or_bucket)
        names.append(ref.domain)
    return compromised_status(*names)


def choose_fix(
    evidence: dict[str, Any],
    model_fix: str,
    final_severity: Severity,
    rows: list[tuple[Reference, Classification, Investigation]] | None = None,
) -> str:
    rows = rows or []
    names = [ref.host_or_bucket for ref, _cl, _inv in rows] + [
        ref.domain for ref, _cl, _inv in rows
    ]
    if is_polyfill_host(*names):
        return POLYFILL_FIX
    third_party_no_sri = False
    for ref, cl, _inv in _browser_script_rows(rows):
        if ref.sri is True:
            continue
        if ref.page_url and ref.host_or_bucket:
            page_host = (ref.page_url.split("://", 1)[-1].split("/", 1)[0].split(":")[0])
            if ref.host_or_bucket.lower() != page_host.lower():
                third_party_no_sri = True
    if third_party_no_sri:
        return SRI_FIX
    if any(is_github_action_ref(ref) for ref, _cl, _inv in rows):
        owner = evidence.get("github_owner") or {}
        repo = evidence.get("github_repo") or {}
        if (
            str(owner.get("status", "")).lower() == "missing"
            or str(repo.get("status", "")).lower() == "missing"
        ):
            return ACTION_MISSING_FIX
        if str(repo.get("status", "")).lower() == "disabled":
            return ACTION_DISABLED_FIX
        text = human_fix(model_fix) if has_risk_signal(evidence) else NO_ACTION_FIX
        if ACTION_PIN_FIX not in text:
            if text == NO_ACTION_FIX:
                return ACTION_PIN_FIX
            return f"{text.rstrip('.')} {ACTION_PIN_FIX}"
        return text
    if is_claimable(evidence):
        return CLAIMABLE_FIX
    if final_severity == "info" or not has_risk_signal(evidence):
        return NO_ACTION_FIX
    return human_fix(model_fix)


def evidence_line(group: dict[str, Any], *, include_runs_in: bool = True) -> str:
    evidence = consistent_evidence(group.get("evidence") or {})
    usable = usable_evidence(evidence)
    parts: list[str] = []
    dns = usable.get("dns") or {}
    dns_status = str(dns.get("status", "")).lower()
    raw_dns = str((evidence.get("dns") or {}).get("status", "")).lower()
    if raw_dns in {"timeout", "unknown"}:
        parts.append("DNS unknown (timeout)")
    elif dns_status == "nxdomain":
        parts.append("DNS does not resolve")
    elif dns_status == "resolves":
        parts.append("DNS resolves")
    rdap = usable.get("rdap") or {}
    rdap_status = str(rdap.get("status", "")).lower()
    if rdap_status == "unregistered":
        parts.append("domain not registered")
    elif rdap_status == "registered":
        parts.append("domain is registered")
        days = rdap.get("days_to_expiry")
        if isinstance(days, int) and days <= EXPIRY_INVESTIGATE_DAYS:
            parts.append(f"expires in {days} days")
    bucket = usable.get("bucket_probe") or {}
    bucket_status = str(bucket.get("status", ""))
    provider = str(bucket.get("provider") or "")
    if provider == "gcs":
        label = "GCS bucket"
    elif provider == "azure":
        label = "Azure blob"
    elif provider == "s3":
        label = "S3 bucket"
    else:
        label = "bucket"
    if bucket_status == "NoSuchBucket":
        parts.append(f"{label} does not exist")
    elif bucket_status.lower() == "exists":
        parts.append(f"{label} exists")
    owner = usable.get("github_owner") or {}
    if str(owner.get("status", "")).lower() == "missing":
        parts.append("GitHub owner does not exist")
    elif str(owner.get("status", "")).lower() == "exists":
        parts.append("GitHub owner exists")
    repo = usable.get("github_repo") or {}
    if str(repo.get("status", "")).lower() == "missing":
        parts.append("GitHub repo does not exist")
    elif str(repo.get("status", "")).lower() == "disabled":
        parts.append("GitHub repo disabled")
    elif str(repo.get("status", "")).lower() == "exists":
        parts.append("GitHub repo exists")
    platform = usable.get("platform_takeover") or {}
    if str(platform.get("status", "")).lower() == "unclaimed":
        plat_name = platform.get("platform") or "platform"
        takeover = platform.get("takeover") or "edge case"
        parts.append(f"{plat_name} unclaimed ({takeover})")
    status = _group_compromised(group)
    if status == "compromised":
        parts.append("compromised domain")
    elif status == "associated":
        parts.append("associated domain")
    sri_values = [ref.sri for ref, _cl, _inv in group.get("rows") or []]
    live = usable.get("live_fetch") or {}
    if live.get("for_sale"):
        parts.append("domain listed for sale")
    elif live.get("parked"):
        parts.append("domain is parked")
    rank = evidence.get("tranco_rank")
    if isinstance(rank, int):
        parts.append(f"Tranco rank {rank}")
    if False in sri_values:
        parts.append("SRI missing")
    elif True in sri_values:
        parts.append("SRI present")
    certs = usable.get("cert_history") or {}
    if str(certs.get("status", "")).lower() == "ok":
        issuers = certs.get("issuers") or []
        if issuers:
            parts.append("certificates found")
        else:
            parts.append("no certificates found")
    locs = [f"{ref.file}:{ref.line}" for ref, _cl, _inv in group.get("rows") or []]
    if not include_runs_in:
        if locs:
            parts.append("referenced at " + " and ".join(locs))
        return "Evidence: " + " · ".join(parts)
    by_run: dict[str, list[str]] = {}
    for ref, cl, _inv in group.get("rows") or []:
        by_run.setdefault(cl.runs_in, []).append(f"{ref.file}:{ref.line}")
    for runs_in, run_locs in by_run.items():
        place = RUNS_IN_PHRASE.get(runs_in, runs_in)
        joined = " and ".join(run_locs)
        if runs_in == "browser":
            parts.append(f"loaded by {joined} {place}")
        elif runs_in == "deploy":
            parts.append(f"named in {joined} {place}")
        else:
            parts.append(f"referenced at {joined} {place}")
    return "Evidence: " + " · ".join(parts)


def apply_website_roles(
    pairs: list[tuple[Reference, Classification]],
) -> list[tuple[Reference, Classification]]:
    updated: list[tuple[Reference, Classification]] = []
    for ref, cl in pairs:
        if ref.tag != "script":
            updated.append((ref, cl))
            continue
        changes: dict[str, Any] = {"runs_in": "browser"}
        if cl.type != "bucket" and not is_github_owner_ref(ref):
            changes["type"] = "script"
        updated.append((ref, cl.model_copy(update=changes)))
    return updated


def _reference_locations(group: dict[str, Any]) -> list[dict[str, Any]]:
    locations = []
    for ref, _cl, _inv in group.get("rows") or []:
        if not ref.page_url:
            continue
        locations.append(
            {
                "page_url": ref.page_url,
                "file": ref.file,
                "line": ref.line,
                "tag": ref.tag,
                "attribute": ref.attribute,
                "raw": ref.raw,
                "sri": ref.sri,
                "loaded_by": ref.loaded_by,
            }
        )
    return locations


def floor_severity(group: dict[str, Any]) -> str | None:
    level, _reason = floor_decision(group)
    return level


def _mention_floor(group: dict[str, Any]) -> tuple[str | None, str]:
    """A target only named in docs, tests or comments. Taking it over misleads a
    reader instead of running code, so it belongs in Review, never Fix today."""
    evidence = consistent_evidence(group["evidence"])
    dns = evidence.get("dns") or {}
    live = evidence.get("live_fetch") or {}
    if _group_compromised(group):
        signal = "Compromised domain"
    elif is_claimable(evidence):
        signal = "Claimable now"
    elif str(dns.get("status", "")).lower() == "nxdomain":
        signal = "DNS does not resolve"
    elif live.get("for_sale"):
        signal = "Domain listed for sale"
    elif live.get("parked"):
        signal = "Domain parked"
    else:
        return None, ""
    return "low", f"{signal}, but only named in docs, tests or comments, so it is low"


def floor_decision(group: dict[str, Any]) -> tuple[str | None, str]:
    if not executing_runs_in(group["rows"]):
        return _mention_floor(group)
    evidence = consistent_evidence(group["evidence"])
    runs = sorted(
        {cl.runs_in for _, cl, _ in group["rows"] if cl.runs_in in EXECUTING}
    )
    where = ", ".join(runs)
    sri_ok = _all_browser_scripts_sri(group["rows"])
    has_script = bool(_browser_script_rows(group["rows"]))
    status = _group_compromised(group)
    if status == "compromised" and has_script and not sri_ok:
        return (
            "critical",
            f"compromised domain in a browser script without SRI ({where}) "
            "is at least critical",
        )
    if status == "associated" and has_script:
        return (
            "high",
            f"associated domain in a browser script ({where}) is at least high",
        )
    bucket = evidence.get("bucket_probe") or {}
    rdap = evidence.get("rdap") or {}
    dns = evidence.get("dns") or {}
    if bucket.get("status") == "NoSuchBucket":
        return _claimable_now_floor(group, "NoSuchBucket", where)
    owner = evidence.get("github_owner") or {}
    if str(owner.get("status", "")).lower() == "missing":
        return _claimable_now_floor(group, "GitHub owner missing", where)
    repo = evidence.get("github_repo") or {}
    if str(repo.get("status", "")).lower() == "missing":
        return (
            "high",
            "GitHub repo missing in executing position "
            f"({where}) is at least high",
        )
    if str(repo.get("status", "")).lower() == "disabled":
        # the owner still holds the name, so nobody else can claim it, but
        # what CI runs is no longer there to read
        return (
            "medium",
            "GitHub repo disabled in executing position "
            f"({where}) is at least medium",
        )
    platform = evidence.get("platform_takeover") or {}
    if str(platform.get("status", "")).lower() == "unclaimed":
        plat_name = platform.get("platform") or "platform"
        takeover = str(platform.get("takeover") or "edge case")
        if takeover == "vulnerable":
            return _claimable_now_floor(
                group, f"{plat_name} unclaimed ({takeover})", where
            )
        return (
            "high",
            f"{plat_name} unclaimed ({takeover}) in executing position ({where}) "
            "is at least high",
        )
    if str(rdap.get("status", "")).lower() == "unregistered":
        return _claimable_now_floor(group, "RDAP unregistered", where)
    live = evidence.get("live_fetch") or {}
    for_sale = bool(live.get("for_sale"))
    parked = bool(live.get("parked"))
    if for_sale or parked:
        website = any(ref.page_url for ref, _cl, _inv in group["rows"])
        if (
            website
            and for_sale
            and has_script
            and not sri_ok
        ):
            return (
                "critical",
                "Domain is listed for sale → raised to critical.",
            )
        note = (
            "Domain is listed for sale → raised to high."
            if for_sale
            else "Domain is parked → raised to high."
        )
        return "high", note
    if str(dns.get("status", "")).lower() == "nxdomain":
        return (
            "high",
            f"NXDOMAIN in executing position ({where}) is at least high",
        )
    # On the compromised list but not as a browser script (server, build or CI
    # code calling it). SRI on every browser script is the only safe use.
    if status == "compromised" and not (has_script and sri_ok):
        return (
            "high",
            f"compromised domain in executing position ({where}) is at least high",
        )
    if status == "associated":
        return (
            "medium",
            f"associated domain in executing position ({where}) is at least medium",
        )
    return None, ""


def _claimable_sri_floor(
    level: str | None, reason: str, group: dict[str, Any]
) -> tuple[str | None, str]:
    if level != "critical":
        return level, reason
    rows = group["rows"]
    if _all_browser_scripts_sri(rows) and _browser_script_rows(rows):
        return (
            "medium",
            "claimable-now with SRI in executing position is at least medium",
        )
    return level, reason


def _github_owner_note(uncertain: str, evidence: dict[str, Any]) -> str:
    owner = evidence.get("github_owner") or {}
    if str(owner.get("status", "")).lower() != "missing":
        return uncertain
    if GITHUB_OWNER_NOTE in uncertain:
        return uncertain
    if uncertain.strip():
        return uncertain.rstrip() + " " + GITHUB_OWNER_NOTE
    return GITHUB_OWNER_NOTE


def apply_floor(severity: Severity, floor: str | None) -> tuple[Severity, str]:
    if floor is None:
        return severity, ""
    if SEVERITY_ORDER[severity] > SEVERITY_ORDER[floor]:
        return floor, floor  # type: ignore[return-value]
    return severity, ""


def settle_severity(model: Severity, floor: str | None) -> tuple[Severity, str, str]:
    """(final severity, floor that raised it, note when the model was overruled).

    Whether a target is in Fix today is decided by code: a rule at high or above
    puts it there (the model may still call it critical), and the model's call
    alone reaches Review at most. The same facts land in the same group on every
    run, whatever the model happens to say."""
    if floor in FIX_TODAY:
        final, raised = apply_floor(model, floor)
        return final, raised, ""
    note = ""
    if SEVERITY_ORDER[model] < SEVERITY_ORDER[MODEL_CEILING]:
        note = f"Muse Spark said {model}, but no code rule backs that, so it stays in Review."
        model = MODEL_CEILING
    final, raised = apply_floor(model, floor)
    return final, raised, note


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda item: (
            SEVERITY_ORDER[item.severity],
            -item.ranked_blast_radius,
            item.target,
        ),
    )


def rank(
    rows: list[tuple[Reference, Classification, Investigation]],
    *,
    client: ModelClient,
    cache: LookupCache | None = None,
    logs: list[CallLog] | None = None,
    on_event: OnEvent | None = None,
    deadline: float | None = None,
) -> list[Finding]:
    groups = group_by_target(rows)
    if not groups:
        return []
    results: list[Finding | None] = [None] * len(groups)
    # One list per group, merged in group order afterwards, so the cost log
    # does not depend on which worker finished first.
    group_logs: list[list[CallLog]] = [[] for _ in groups]

    def rank_one(index: int) -> None:
        finding = _rank_group(
            groups[index],
            client=client,
            cache=cache,
            logs=group_logs[index],
            deadline=deadline,
        )
        results[index] = finding
        # Tell the page as each target is ranked, not after all of them.
        emit(on_event, {"type": "ranked", **finding_public(finding)})

    if len(groups) == 1:
        rank_one(0)
    else:
        workers = min(RANK_CONCURRENCY, len(groups))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for future in [pool.submit(rank_one, i) for i in range(len(groups))]:
                future.result()
    if logs is not None:
        for bundle in group_logs:
            logs.extend(bundle)
    return sort_findings([item for item in results if item is not None])


def _rank_group(
    group: dict[str, Any],
    *,
    client: ModelClient,
    cache: LookupCache | None,
    logs: list[CallLog] | None,
    deadline: float | None = None,
) -> Finding:
    payload = finding_payload(group)
    floor, floor_why = floor_decision(group)
    ref0 = group["rows"][0][0]
    if tranco_checked_safe(ref0, group["evidence"]) and floor is None:
        rank = group["evidence"].get("tranco_rank")
        parsed = RankModelOut(
            severity="info",
            risk=f"Checked and safe. Tranco rank {rank}.",
            fix="remove dead reference",
            uncertain_about="",
            blast_radius=payload["classified_blast_radius"],
            blast_override_reason="",
        )
        return _finding_from_rank(
            group=group,
            payload=payload,
            parsed=parsed,
            floor=floor,
            floor_why=floor_why,
            cost_total=0.0,
        )
    body = json.dumps(payload, sort_keys=True, default=str)
    user = "Rank this target. Cite only facts from the provided evidence and finding.\n" + body
    cost_total = 0.0

    def check(parsed: RankModelOut) -> None:
        missing = missing_claims(parsed.risk, payload)
        banned = banned_fields(parsed.risk)
        unknown = cited_unknown(parsed.risk, group["evidence"])
        problems = []
        if missing:
            problems.append(f"claims not in evidence: {missing}")
        if banned:
            problems.append(f"banned field names: {banned}")
        if unknown:
            problems.append(f"unknown lookups cited: {unknown}")
        if problems:
            raise ValueError("; ".join(problems))

    for attempt in range(LLM_MAX_RETRIES + 1):
        if deadline is not None and time.monotonic() >= deadline:
            # A serverless host ends the request soon; keep the code severity.
            return _finding_from_rank(
                group=group,
                payload=payload,
                parsed=None,
                floor=floor,
                floor_why=floor_why,
                cost_total=cost_total,
                risk=RANK_TIME_NOTE,
            )
        try:
            parsed, log = call_json(
                RANK_MODEL,
                RANK_SYSTEM_PROMPT,
                user,
                RankModelOut,
                RANK_REASONING_EFFORT,
                client=client,
                json_schema=RANK_JSON_SCHEMA,
                schema_name="ranking",
                cache=cache,
                extra_check=check,
                retries=0,
            )
            if logs is not None:
                logs.append(log)
            cost_total += log.cost_usd
            return _finding_from_rank(
                group=group,
                payload=payload,
                parsed=parsed,
                floor=floor,
                floor_why=floor_why,
                cost_total=cost_total,
            )
        except ValueError as exc:
            rejected = str(exc)
            user = (
                "Rank this target. Cite only facts from the provided evidence and finding.\n"
                + body
                + "\nSelf-check rejected these tokens: "
                + rejected
                + ". only use facts from the provided evidence and finding."
            )
            continue

    return _finding_from_rank(
        group=group,
        payload=payload,
        parsed=None,
        floor=floor,
        floor_why=floor_why,
        cost_total=cost_total,
        needs_review=True,
    )


def _finding_from_rank(
    *,
    group: dict[str, Any],
    payload: dict[str, Any],
    parsed: RankModelOut | None,
    floor: str | None,
    floor_why: str,
    cost_total: float,
    needs_review: bool = False,
    risk: str = "",
) -> Finding:
    evidence = group["evidence"]
    refs = [item["file_line"] for item in payload["references"]]
    classified_blast = payload["classified_blast_radius"]
    if parsed is None:
        model_severity: Severity = "info"
        ranked_blast = classified_blast
        override = ""
        risk = risk or "needs review: ranking failed self-check"
        model_fix = "remove dead reference"
        uncertain = ""
    else:
        model_severity = parsed.severity
        ranked_blast = parsed.blast_radius
        if parsed.blast_radius != classified_blast:
            override = parsed.blast_override_reason or (
                "ranker changed blast_radius versus classify"
            )
        else:
            override = ""
        risk = parsed.risk
        model_fix = parsed.fix
        uncertain = parsed.uncertain_about
    uncertain = _github_owner_note(uncertain, evidence)
    final, raised, ceiling_note = settle_severity(model_severity, floor)
    # The rule that decided or bounded the severity, shown whether or not it
    # had to raise the model's call.
    floor_reason = floor_why if floor else ""
    action_ref = ""
    action_sha_pinned = None
    for ref, _cl, _inv in group["rows"]:
        if ref.action_ref:
            action_ref = ref.action_ref
            action_sha_pinned = ref.action_sha_pinned
            break
    return Finding(
        target=group["target"],
        kind=group["kind"],
        references=refs,
        severity=final,
        model_severity=model_severity,
        final_severity=final,
        classified_blast_radius=classified_blast,
        ranked_blast_radius=ranked_blast,
        blast_override_reason=override,
        risk=risk,
        fix=choose_fix(evidence, model_fix, final, group["rows"]),
        uncertain_about=uncertain,
        needs_review=needs_review,
        floor_applied=raised,
        floor_reason=floor_reason,
        ceiling_note=ceiling_note,
        evidence=evidence,
        evidence_line=evidence_line(group),
        cost_usd=cost_total,
        locations=_reference_locations(group),
        action_ref=action_ref,
        action_sha_pinned=action_sha_pinned,
    )


async def scan(
    source: str,
    *,
    client: ModelClient,
    cache: LookupCache,
    ctx: ToolContext | None = None,
    hydrate_only: bool = True,
    cost_cap: float = SCAN_COST_CAP_USD,
    on_event: OnEvent | None = None,
) -> list[Finding]:
    outcome = await run_scan(
        source,
        client=client,
        cache=cache,
        ctx=ctx,
        hydrate_only=hydrate_only,
        cost_cap=cost_cap,
        on_event=on_event,
    )
    return outcome.findings


async def run_scan(
    source: str,
    *,
    client: ModelClient,
    cache: LookupCache,
    ctx: ToolContext | None = None,
    hydrate_only: bool = True,
    allow_partial_cache: bool = False,
    cost_cap: float = SCAN_COST_CAP_USD,
    on_event: OnEvent | None = None,
    deadline: float | None = None,
    rank_deadline: float | None = None,
) -> ScanOutcome:
    if is_website_source(source):
        refs = await extract_website(source)
        coverage = website_coverage().as_dict()
    else:
        # Cloning and reading a repository blocks; keep it off the event loop so
        # the scan's own SSE stream keeps flowing while it runs.
        extracted = await asyncio.to_thread(extract_scan, source)
        refs = extracted.references
        coverage = extracted.coverage.as_dict()
    actionable = sum(1 for item in refs if item.filter_reason is None)
    emit(
        on_event,
        {
            "type": "extracted",
            "references": len(refs),
            "actionable": actionable,
            "filtered": len(refs) - actionable,
            "coverage": coverage,
            **gather_public(refs),
        },
    )
    class_logs: list[CallLog] = []
    # References code filters set aside never reach a later step, so the model
    # does not label them.
    labels = iter(
        await asyncio.to_thread(
            classify, refs, client=client, include_filtered=False, cache=cache, logs=class_logs
        )
    )
    classified = [
        next(labels) if ref.filter_reason is None else set_aside(ref) for ref in refs
    ]
    pairs = list(zip(refs, classified, strict=True))
    if is_website_source(source):
        pairs = apply_website_roles(pairs)
    emit(on_event, {"type": "classified", **classified_public(pairs)})
    ctx = ctx or ToolContext(cache=cache)
    investigations: list[Investigation] = []
    cached_rows = (
        rows_from_lookup_cache(pairs, cache, complete=not allow_partial_cache)
        if hydrate_only
        else None
    )
    if cached_rows is not None:
        rows = cached_rows
    else:
        investigations = await investigate(
            pairs,
            client=client,
            ctx=ctx,
            cost_cap=cost_cap,
            on_event=on_event,
            deadline=deadline,
        )
        inv_by_loc = {(item.file, item.line): item for item in investigations}
        rows = [
            (ref, cl, inv_by_loc[(ref.file, ref.line)])
            for ref, cl in pairs
            if (ref.file, ref.line) in inv_by_loc
        ]
    rank_logs: list[CallLog] = []
    findings = await asyncio.to_thread(
        rank,
        rows,
        client=client,
        cache=cache,
        logs=rank_logs,
        on_event=on_event,
        deadline=rank_deadline,
    )
    budget = sorted(
        {
            item.host_or_bucket
            for item in investigations
            if item.status == "budget"
        }
    )
    return ScanOutcome(
        findings=findings,
        investigations=investigations,
        classify_cost_usd=sum(log.cost_usd for log in class_logs),
        agent_cost_usd=sum(item.cost_usd for item in investigations),
        rank_cost_usd=sum(log.cost_usd for log in rank_logs),
        budget_targets=budget,
        coverage=coverage,
    )


def hydrate_evidence(
    ref: Reference, cl: Classification, cache: LookupCache
) -> dict[str, Any] | None:
    if cl.type == "bucket" or is_bucket_ref(ref):
        raw = ref.raw.lower()
        if "storage.googleapis.com" in raw:
            provider = "gcs"
        elif "blob.core.windows.net" in raw:
            provider = "azure"
        else:
            provider = "s3"
        hit = cache.get_json(f"bucket:{provider}:{ref.host_or_bucket}")
        if hit is None:
            return None
        evidence: dict[str, Any] = {
            "bucket_probe": hit,
            "tranco_rank": tranco_rank(ref.domain or ""),
        }
        urls = (
            [ref.raw]
            if ref.raw.startswith("http")
            else [f"https://{ref.host_or_bucket}.s3.amazonaws.com"]
        )
        for url in urls:
            wayback = cache.get_json(f"wayback:{url}")
            if wayback:
                evidence["wayback"] = wayback
                break
        return evidence
    if is_github_owner_ref(ref):
        login = github_login(ref)
        if not login:
            return None
        hit = cache.get_json(f"github_owner:{login.lower()}")
        if hit is None:
            return None
        return {
            "github_owner": hit,
            "tranco_rank": tranco_rank(ref.domain or ""),
        }
    if is_github_action_ref(ref):
        login = github_login(ref)
        if not login:
            return None
        owner = cache.get_json(f"github_owner:{login.lower()}")
        repo = cache.get_json(
            f"github_repo:{ref.action_owner.lower()}/{ref.action_repo.lower()}"
        )
        if owner is None or repo is None:
            return None
        return {
            "github_owner": owner,
            "github_repo": repo,
            "tranco_rank": tranco_rank(ref.domain or ""),
        }
    dns = cache.get_json(f"dns:{ref.host_or_bucket.lower()}")
    if dns is None:
        return None
    evidence = {"dns": dns, "tranco_rank": tranco_rank(ref.domain or "")}
    if ref.domain:
        rdap = cache.get_json(f"rdap:{ref.domain.lower()}")
        if rdap:
            evidence["rdap"] = rdap
        certs = cache.get_json(f"crtsh:{ref.domain.lower()}")
        if certs:
            evidence["cert_history"] = certs
    wayback = cache.get_json(f"wayback:{ref.raw}")
    if wayback:
        evidence["wayback"] = wayback
    platform = cache.get_json(f"platform:{ref.host_or_bucket.lower()}")
    if platform:
        evidence["platform_takeover"] = platform
    live = cache.get_json(f"live_fetch:https://{ref.host_or_bucket.lower()}/")
    if live:
        evidence["live_fetch"] = live
    login = github_login(ref)
    if login:
        owner = cache.get_json(f"github_owner:{login.lower()}")
        if owner:
            evidence["github_owner"] = owner
    return consistent_evidence(evidence)


def rows_from_lookup_cache(
    pairs: list[tuple[Reference, Classification]],
    cache: LookupCache,
    *,
    complete: bool = True,
) -> list[tuple[Reference, Classification, Investigation]] | None:
    rows: list[tuple[Reference, Classification, Investigation]] = []
    for ref, cl in pairs:
        if ref.filter_reason is not None:
            continue
        evidence = hydrate_evidence(ref, cl, cache)
        if evidence is None:
            if complete:
                return None
            continue
        evidence["tranco_rank"] = tranco_rank(ref.domain or "")
        if tranco_checked_safe(ref, evidence):
            rank = evidence["tranco_rank"]
            rows.append(
                (
                    ref,
                    cl,
                    Investigation(
                        file=ref.file,
                        line=ref.line,
                        host_or_bucket=ref.host_or_bucket,
                        status="done",
                        summary=f"Tranco rank {rank}",
                        evidence=evidence,
                    ),
                )
            )
            continue
        if not should_investigate(ref, cl, evidence):
            continue
        rows.append(
            (
                ref,
                cl,
                Investigation(
                    file=ref.file,
                    line=ref.line,
                    host_or_bucket=ref.host_or_bucket,
                    status="done",
                    evidence=evidence,
                ),
            )
        )
    return rows


def format_table(findings: list[Finding]) -> str:
    if not findings:
        return "(no findings)"
    lines = []
    for item in findings:
        refs = ", ".join(item.references)
        lines.append(
            f"{item.final_severity:8} {item.target} refs={refs} "
            f"blast={item.ranked_blast_radius}"
        )
        lines.append(f"         fix={item.fix}")
        if item.blast_override_reason:
            lines.append(f"         override: {item.blast_override_reason}")
        if item.floor_reason:
            lines.append(
                f"         floor: model={item.model_severity} "
                f"final={item.final_severity} reason={item.floor_reason}"
            )
        if item.needs_review:
            lines.append("         needs_review")
        lines.append(f"         {item.risk}")
        if item.evidence_line:
            lines.append(f"         {item.evidence_line}")
    return "\n".join(lines)
