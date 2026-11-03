from __future__ import annotations

import asyncio
import json
import time
from typing import Any

from scanner.config import (
    AGENT_MODEL,
    AGENT_REASONING_EFFORT,
    EXPIRY_INVESTIGATE_DAYS,
    MAX_AGENT_TOOL_CALLS,
    MAX_AGENT_TARGETS,
    MAX_INVESTIGATION_CONCURRENCY,
    PRECHECK_CONCURRENCY,
    SCAN_COST_CAP_USD,
)
from scanner.llm import CallLog, ModelClient, ToolTurn, cost_usd, is_model_transport_error
from scanner.llm import _tokens
from scanner.lookups import consistent_evidence, merge_evidence
from scanner.models import (
    Classification,
    Investigation,
    Reference,
    TraceEvent,
)
from scanner.events import OnEvent, emit, public_target, summarize
from scanner.compromised import compromised_status
from scanner.extract import (
    github_login,
    is_bucket_ref as _is_bucket_ref,
    is_github_action_ref,
    is_github_owner_ref,
)
from scanner.tools.platform_takeover import matching_platform
from scanner.tools import ToolContext, definitions, run as run_tool
from scanner.tranco import TOP_SAFE_RANK, tranco_rank

AGENT_SYSTEM_PROMPT = (
    "You investigate one outside reference for takeover risk. "
    "Code already ran dns and rdap for hosts, bucket_probe for buckets, "
    "github_owner for GitHub accounts, platform_takeover when a host or CNAME "
    "matches a listed platform, and live_fetch of the host's home page; those "
    "results are in the first message. Asking for one of them again returns the "
    "same answer, so spend turns on new facts: history (wayback, cert_history), or "
    "another host, domain or URL the facts point to. "
    "tranco_rank is popularity context only: never use it to lower a claimable-now "
    "or compromised finding. Each turn pick exactly one tool. You have at most "
    f"{MAX_AGENT_TOOL_CALLS} turns; call done(summary) when the facts are clear. "
    "Do not invent dates, DNS results, or HTTP statuses."
)

# The argument that names what a tool looks at, and the field its answer names it by.
_SUBJECT = {
    "dns": ("host", "host"),
    "rdap": ("domain", "domain"),
    "platform_takeover": ("host", "host"),
    "github_owner": ("owner", "owner"),
    "bucket_probe": ("name", "name"),
    "live_fetch": ("url", "url"),
    "cert_history": ("domain", "domain"),
    "wayback": ("url", "url"),
}

# Places where the referenced thing is loaded or run, not just mentioned.
EXECUTING = frozenset({"browser", "server", "build", "deploy", "ci"})

BUDGET_NOTE = "not investigated (budget)"
TIME_NOTE = "agent skipped (time budget)"
FACTS_NOTE = "code lookups only: no red flag for the agent"
AGENT_FINDINGS = "agent_findings"

# What a target's references add up to, strongest first. A target is ranked
# unless every reference is low exposure.
STEP_ORDER = ("agent", "facts", "popular", "low_exposure")


def _bucket_provider(raw: str) -> str:
    lowered = raw.lower()
    if "storage.googleapis.com" in lowered:
        return "gcs"
    if "blob.core.windows.net" in lowered:
        return "azure"
    return "s3"


def has_hard_signal(evidence: dict[str, Any]) -> bool:
    evidence = consistent_evidence(evidence)
    bucket = evidence.get("bucket_probe") or {}
    if bucket.get("status") == "NoSuchBucket":
        return True
    owner = evidence.get("github_owner") or {}
    if str(owner.get("status", "")).lower() == "missing":
        return True
    repo = evidence.get("github_repo") or {}
    if str(repo.get("status", "")).lower() == "missing":
        return True
    platform = evidence.get("platform_takeover") or {}
    if str(platform.get("status", "")).lower() == "unclaimed":
        return True
    dns = evidence.get("dns") or {}
    if str(dns.get("status", "")).lower() == "nxdomain":
        return True
    rdap = evidence.get("rdap") or {}
    if str(rdap.get("status", "")).lower() == "unregistered":
        return True
    days = rdap.get("days_to_expiry")
    if isinstance(days, int) and days <= EXPIRY_INVESTIGATE_DAYS:
        return True
    return False


def _attach_tranco(ref: Reference, evidence: dict[str, Any]) -> dict[str, Any]:
    evidence["tranco_rank"] = tranco_rank(ref.domain or "")
    return evidence


def tranco_checked_safe(ref: Reference, evidence: dict[str, Any]) -> bool:
    rank = evidence.get("tranco_rank")
    if not isinstance(rank, int) or rank > TOP_SAFE_RANK:
        return False
    dns = evidence.get("dns") or {}
    if str(dns.get("status", "")).lower() != "resolves":
        return False
    if has_hard_signal(evidence):
        return False
    if compromised_status(ref.host_or_bucket, ref.domain):
        return False
    return True


async def precheck(
    ref: Reference, cl: Classification, ctx: ToolContext
) -> dict[str, Any]:
    evidence: dict[str, Any] = {}
    if cl.type == "bucket" or _is_bucket_ref(ref):
        evidence["bucket_probe"] = await run_tool(
            "bucket_probe",
            {
                "name": ref.host_or_bucket,
                "provider": _bucket_provider(ref.raw),
            },
            ctx,
        )
        return _attach_tranco(ref, evidence)
    if is_github_action_ref(ref):
        login = github_login(ref)
        if login:
            evidence["github_owner"] = await run_tool(
                "github_owner", {"owner": login}, ctx
            )
        evidence["github_repo"] = (
            await ctx.github_repo(
                ref.action_owner, ref.action_repo, cache=ctx.cache
            )
        ).model_dump(mode="json")
        return _attach_tranco(ref, evidence)
    if is_github_owner_ref(ref):
        login = github_login(ref)
        if login:
            evidence["github_owner"] = await run_tool(
                "github_owner", {"owner": login}, ctx
            )
        return _attach_tranco(ref, evidence)
    domain = ref.domain or ""
    jobs = {"dns": run_tool("dns", {"host": ref.host_or_bucket}, ctx)}
    if domain:
        jobs["rdap"] = run_tool("rdap", {"domain": domain}, ctx)
    login = github_login(ref)
    if login:
        jobs["github_owner"] = run_tool("github_owner", {"owner": login}, ctx)
    evidence.update(zip(jobs, await asyncio.gather(*jobs.values())))
    dns = evidence.get("dns") or {}
    cnames = list(dns.get("cnames") or [])
    if matching_platform(ref.host_or_bucket, cnames):
        evidence["platform_takeover"] = await run_tool(
            "platform_takeover",
            {
                "host": ref.host_or_bucket,
                "cnames": cnames,
                "dns_status": dns.get("status"),
            },
            ctx,
        )
    return _attach_tranco(ref, consistent_evidence(evidence))


def should_investigate(ref: Reference, cl: Classification, evidence: dict[str, Any]) -> bool:
    """Worth ranking: a hard signal, or a reference that matters at all."""
    if ref.filter_reason is not None:
        return False
    return has_hard_signal(evidence) or cl.blast_radius >= 1


def red_flags(ref: Reference, evidence: dict[str, Any]) -> list[str]:
    """What the code lookups found that is worth an agent's turns, in plain words.

    A renewal date alone on a domain that still resolves is routine, so it is
    not a red flag; it only counts once DNS has stopped answering."""
    evidence = consistent_evidence(evidence)
    flags: list[str] = []
    status = compromised_status(ref.host_or_bucket, ref.domain)
    if status:
        flags.append(f"{status} domain")
    bucket = evidence.get("bucket_probe") or {}
    if bucket.get("status") == "NoSuchBucket":
        flags.append("bucket does not exist")
    owner = evidence.get("github_owner") or {}
    if str(owner.get("status", "")).lower() == "missing":
        flags.append("GitHub owner does not exist")
    repo = evidence.get("github_repo") or {}
    if str(repo.get("status", "")).lower() == "missing":
        flags.append("GitHub repo does not exist")
    elif str(repo.get("status", "")).lower() == "disabled":
        flags.append("GitHub repo disabled")
    platform = evidence.get("platform_takeover") or {}
    if str(platform.get("status", "")).lower() == "unclaimed":
        flags.append(f"{platform.get('platform') or 'platform'} unclaimed")
    dns = evidence.get("dns") or {}
    dns_status = str(dns.get("status", "")).lower()
    if dns_status == "nxdomain":
        flags.append("DNS does not resolve")
    rdap = evidence.get("rdap") or {}
    if str(rdap.get("status", "")).lower() == "unregistered":
        flags.append("domain not registered")
    days = rdap.get("days_to_expiry")
    if isinstance(days, int) and days <= EXPIRY_INVESTIGATE_DAYS and dns_status != "resolves":
        flags.append(f"domain expires in {days} days")
    live = evidence.get("live_fetch") or {}
    if live.get("for_sale"):
        flags.append("domain listed for sale")
    elif live.get("parked"):
        flags.append("domain parked")
    return flags


def needs_agent(ref: Reference, cl: Classification, evidence: dict[str, Any]) -> bool:
    """Only a red flag earns agent turns; clean lookups go straight to rank."""
    if not should_investigate(ref, cl, evidence):
        return False
    if tranco_checked_safe(ref, evidence):
        return False
    return bool(red_flags(ref, evidence))


def next_step(ref: Reference, cl: Classification, evidence: dict[str, Any]) -> str:
    """What investigate() does with this reference after the precheck, for the page."""
    if tranco_checked_safe(ref, evidence):
        return "popular"
    if needs_agent(ref, cl, evidence):
        return "agent"
    if should_investigate(ref, cl, evidence):
        return "facts"
    return "low_exposure"


def strongest_step(steps: list[str]) -> str:
    return min(steps, key=STEP_ORDER.index) if steps else "low_exposure"


def _precheck_key(ref: Reference, cl: Classification) -> tuple:
    """Everything precheck() reads. Two references sharing this get one lookup."""
    is_bucket = cl.type == "bucket" or _is_bucket_ref(ref)
    return (
        "bucket" if is_bucket else "other",
        ref.host_or_bucket.lower(),
        (ref.domain or "").lower(),
        (ref.action_owner or "").lower(),
        (ref.action_repo or "").lower(),
        _bucket_provider(ref.raw) if is_bucket else "",
        is_github_action_ref(ref),
        is_github_owner_ref(ref),
    )


async def _precheck_all(
    actionable: list[tuple[Reference, Classification]], ctx: ToolContext
) -> dict[tuple, dict[str, Any]]:
    leads: dict[tuple, tuple[Reference, Classification]] = {}
    for ref, cl in actionable:
        leads.setdefault(_precheck_key(ref, cl), (ref, cl))
    sem = asyncio.Semaphore(PRECHECK_CONCURRENCY)

    async def one(key: tuple) -> tuple[tuple, dict[str, Any]]:
        ref, cl = leads[key]
        async with sem:
            return key, await precheck(ref, cl, ctx)

    return dict(await asyncio.gather(*(one(key) for key in leads)))


async def investigate(
    pairs: list[tuple[Reference, Classification]],
    *,
    client: ModelClient,
    ctx: ToolContext,
    cost_cap: float = SCAN_COST_CAP_USD,
    max_concurrent: int = MAX_INVESTIGATION_CONCURRENCY,
    on_event: OnEvent | None = None,
    deadline: float | None = None,
) -> list[Investigation]:
    """deadline is a time.monotonic() value; after it no new agent run starts and
    running ones stop between turns. The precheck facts are kept either way.

    Decisions are made per target (the name the page shows): every reference
    to it gets the same next step, and a target gets at most one agent run.

    Code runs every check that can move a target into Fix today, on every
    target, every time: the lookups, then the live page of each host worth
    ranking. A target with a red flag gets the agent; a clean one gets its
    history (crt.sh, Wayback) from code, the checks an agent used to pick."""
    actionable = [(ref, cl) for ref, cl in pairs if ref.filter_reason is None]
    evidence_by_key = await _precheck_all(actionable, ctx)
    checked = [
        (ref, cl, dict(evidence_by_key[_precheck_key(ref, cl)]))
        for ref, cl in actionable
    ]
    await _live_pages(checked, ctx)
    steps = [next_step(ref, cl, evidence) for ref, cl, evidence in checked]
    by_target: dict[str, list[int]] = {}
    for index, (ref, cl, _evidence) in enumerate(checked):
        by_target.setdefault(_event_target(ref, cl), []).append(index)
    target_step = {
        target: strongest_step([steps[index] for index in members])
        for target, members in by_target.items()
    }

    target_facts = {
        target: merge_evidence([checked[index][2] for index in members])
        for target, members in by_target.items()
    }

    shown: set[str] = set()
    for ref, cl, _evidence in checked:
        target = _event_target(ref, cl)
        members = by_target[target]
        facts = target_facts[target]
        event = {
            "type": "precheck",
            "target": target,
            "kind": _event_kind(ref, cl),
            "hard_signal": has_hard_signal(facts),
            "next": target_step[target],
        }
        # The facts are about the target, so send them once, not once per line.
        if target not in shown:
            shown.add(target)
            event["evidence"] = facts
            event["flags"] = _target_flags(checked, members)
            if target_step[target] == "agent":
                event["max_turns"] = MAX_AGENT_TOOL_CALLS
        emit(on_event, event)

    results: list[Investigation | None] = [None] * len(checked)
    runs: list[tuple[int, list[int]]] = []
    clean: list[tuple[str, list[int]]] = []
    for target, members in by_target.items():
        ranked = [index for index in members if steps[index] in {"agent", "facts"}]
        if target_step[target] == "agent":
            runs.append((_lead(checked, steps, members), ranked))
        elif target_step[target] == "facts":
            clean.append((target, ranked))
    # Highest exposure first, so a spent budget skips the least important runs.
    runs.sort(key=lambda run: _priority(checked, run[0]))
    # Bound model-led exploration for very large repos. Every target still gets
    # code prechecks and is ranked from those facts; lower-priority targets just
    # do not start an agent conversation.
    deferred, runs = runs[MAX_AGENT_TARGETS:], runs[:MAX_AGENT_TARGETS]
    for _lead_index, members in deferred:
        for index in members:
            ref, _cl, evidence = checked[index]
            results[index] = _budget_skip(ref, evidence)

    spent = 0.0
    lock = asyncio.Lock()
    sem = asyncio.Semaphore(max_concurrent)

    def share(inv: Investigation, index: int, found: dict[str, Any]) -> Investigation:
        # Each reference keeps its own lookups; the agent's new facts are added.
        ref, _cl, evidence = checked[index]
        return inv.model_copy(
            update={
                "file": ref.file,
                "line": ref.line,
                "host_or_bucket": ref.host_or_bucket,
                "evidence": {**evidence, **found},
                "cost_usd": 0.0,
            }
        )

    async def worker(lead: int, members: list[int]) -> None:
        nonlocal spent
        ref, cl, evidence = checked[lead]
        async with sem:
            async with lock:
                over = spent >= cost_cap
            if over or _past(deadline):
                skip = _budget_skip if over else _time_skip
                for index in members:
                    other_ref, _other_cl, other_evidence = checked[index]
                    results[index] = skip(other_ref, other_evidence)
                return
            inv = await investigate_one(
                ref,
                cl,
                client=client,
                ctx=ctx,
                evidence=evidence,
                on_event=on_event,
                deadline=deadline,
            )
            async with lock:
                spent += inv.cost_usd
            found = {
                name: value
                for name, value in inv.evidence.items()
                if name not in evidence
            }
            for index in members:
                results[index] = inv if index == lead else share(inv, index, found)

    history_sem = asyncio.Semaphore(PRECHECK_CONCURRENCY)

    async def history(target: str, members: list[int]) -> None:
        async with history_sem:
            if _past(deadline):
                return
            lead = min(members, key=lambda index: _priority(checked, index))
            found = await _history(checked[lead][0], checked[lead][1], ctx)
        if not found:
            return
        for index in members:
            evidence = checked[index][2]
            for name, value in found.items():
                evidence.setdefault(name, value)
        emit(
            on_event,
            {
                "type": "checked",
                "target": target,
                "evidence": merge_evidence([checked[index][2] for index in by_target[target]]),
            },
        )

    await asyncio.gather(
        *(worker(lead, members) for lead, members in runs),
        *(history(target, members) for target, members in clean),
    )
    for target, members in by_target.items():
        for index in members:
            ref, _cl, evidence = checked[index]
            if steps[index] == "popular":
                results[index] = Investigation(
                    file=ref.file,
                    line=ref.line,
                    host_or_bucket=ref.host_or_bucket,
                    status="done",
                    summary=f"Tranco rank {evidence['tranco_rank']}",
                    evidence=evidence,
                )
            elif steps[index] == "facts" and target_step[target] != "agent":
                results[index] = Investigation(
                    file=ref.file,
                    line=ref.line,
                    host_or_bucket=ref.host_or_bucket,
                    status="done",
                    summary=FACTS_NOTE,
                    evidence=evidence,
                )
    return [item for item in results if item is not None]


def _is_domain_ref(ref: Reference, cl: Classification) -> bool:
    return not (
        cl.type == "bucket"
        or _is_bucket_ref(ref)
        or is_github_action_ref(ref)
        or is_github_owner_ref(ref)
    )


def _history_url(ref: Reference, cl: Classification) -> str:
    # the same URL hydrate_evidence() reads back from the cache
    if ref.raw.startswith("http"):
        return ref.raw
    if cl.type == "bucket" or _is_bucket_ref(ref):
        return f"https://{ref.host_or_bucket}.s3.amazonaws.com"
    return f"https://{ref.host_or_bucket}/"


async def _live_pages(
    checked: list[tuple[Reference, Classification, dict[str, Any]]], ctx: ToolContext
) -> None:
    """Fetch the home page of every host worth ranking that answers DNS, once per
    host, so a parked or for-sale domain is found every time, not when an agent
    happens to look."""
    hosts: dict[str, list[int]] = {}
    for index, (ref, cl, evidence) in enumerate(checked):
        dns = evidence.get("dns") or {}
        if (
            _is_domain_ref(ref, cl)
            and str(dns.get("status", "")).lower() == "resolves"
            and should_investigate(ref, cl, evidence)
            and not tranco_checked_safe(ref, evidence)
        ):
            hosts.setdefault(ref.host_or_bucket.lower(), []).append(index)
    sem = asyncio.Semaphore(PRECHECK_CONCURRENCY)

    async def one(host: str) -> tuple[str, dict[str, Any]]:
        async with sem:
            return host, await run_tool("live_fetch", {"url": f"https://{host}/"}, ctx)

    for host, page in await asyncio.gather(*(one(host) for host in hosts)):
        for index in hosts[host]:
            checked[index][2].setdefault("live_fetch", page)


async def _history(ref: Reference, cl: Classification, ctx: ToolContext) -> dict[str, Any]:
    """What a target looked like before: certificates for a domain, archived
    copies of the URL. Context for rank; no severity rule reads it."""
    found: dict[str, Any] = {}
    if is_github_action_ref(ref) or is_github_owner_ref(ref):
        return found  # whether the account and repo exist is the whole answer
    jobs = {"wayback": run_tool("wayback", {"url": _history_url(ref, cl)}, ctx)}
    if _is_domain_ref(ref, cl) and ref.domain:
        jobs["cert_history"] = run_tool("cert_history", {"domain": ref.domain}, ctx)
    for name, result in zip(jobs, await asyncio.gather(*jobs.values(), return_exceptions=True)):
        if not isinstance(result, BaseException):
            found[name] = result
    return found


def _target_flags(
    checked: list[tuple[Reference, Classification, dict[str, Any]]],
    members: list[int],
) -> list[str]:
    flags: list[str] = []
    for index in members:
        ref, _cl, evidence = checked[index]
        for flag in red_flags(ref, evidence):
            if flag not in flags:
                flags.append(flag)
    return flags


def _priority(
    checked: list[tuple[Reference, Classification, dict[str, Any]]], index: int
) -> tuple[int, int, int]:
    _ref, cl, _evidence = checked[index]
    return (-cl.blast_radius, 0 if cl.runs_in in EXECUTING else 1, index)


def _lead(
    checked: list[tuple[Reference, Classification, dict[str, Any]]],
    steps: list[str],
    members: list[int],
) -> int:
    """The reference the agent is asked about: a red-flagged one, the most exposed."""
    flagged = [index for index in members if steps[index] == "agent"]
    return min(flagged, key=lambda index: _priority(checked, index))


def _known(evidence: dict[str, Any], name: str, args: dict[str, Any]) -> dict[str, Any] | None:
    """The answer already in hand for exactly this lookup, if there is one."""
    subject = _SUBJECT.get(name)
    fact = evidence.get(name)
    if subject is None or not isinstance(fact, dict):
        return None
    arg, field = subject
    asked = str(args.get(arg) or "").strip().lower().rstrip("/.")
    held = str(fact.get(field) or "").strip().lower().rstrip("/.")
    return fact if asked and asked == held else None


async def investigate_one(
    ref: Reference,
    cl: Classification,
    *,
    client: ModelClient,
    ctx: ToolContext,
    evidence: dict[str, Any] | None = None,
    on_event: OnEvent | None = None,
    deadline: float | None = None,
) -> Investigation:
    if evidence is None:
        evidence = await precheck(ref, cl, ctx)
    else:
        evidence = dict(evidence)

    messages: list[dict[str, Any]] = [
        {
            "role": "user",
            "content": json.dumps(
                {
                    "reference": {
                        "file": ref.file,
                        "line": ref.line,
                        "raw": ref.raw,
                        "host_or_bucket": ref.host_or_bucket,
                        "domain": ref.domain,
                        "type": cl.type,
                        "runs_in": cl.runs_in,
                        "blast_radius": cl.blast_radius,
                    },
                    "precomputed": evidence,
                },
                sort_keys=True,
            ),
        }
    ]
    trace: list[TraceEvent] = []
    cost_total = 0.0
    summary = ""
    tools = definitions()

    for _ in range(MAX_AGENT_TOOL_CALLS):
        if trace and _past(deadline):
            summary = summary or TIME_NOTE
            break
        try:
            turn, log = await asyncio.to_thread(_model_turn, client, messages, tools)
        except Exception as exc:
            if not is_model_transport_error(exc):
                raise
            summary = "Model request timed out; continuing with code lookup evidence only."
            emit(
                on_event,
                {
                    "type": "notice",
                    "message": "The model timed out during investigation. Trustline kept its code lookup results and continued.",
                },
            )
            break
        cost_total += log.cost_usd
        trace.append(
            TraceEvent(
                kind="plan",
                tool=turn.name,
                arguments=turn.arguments,
                tokens=log.input_tokens + log.output_tokens,
                cost_usd=log.cost_usd,
                note=f"pick {turn.name}",
            )
        )
        emit(
            on_event,
            {
                "type": "plan",
                "target": _event_target(ref, cl),
                "tool": turn.name,
                "args": turn.arguments,
                "tokens": log.input_tokens + log.output_tokens,
                "cost_usd": log.cost_usd,
            },
        )
        trace.append(
            TraceEvent(
                kind="act",
                tool=turn.name,
                arguments=turn.arguments,
            )
        )
        emit(
            on_event,
            {
                "type": "act",
                "target": _event_target(ref, cl),
                "tool": turn.name,
                "args": turn.arguments,
            },
        )
        known = None if turn.name == "done" else _known(evidence, turn.name, turn.arguments)
        if known is not None:
            # already looked up by code: the same answer, without asking again
            result, refused = known, False
        else:
            try:
                result = await run_tool(turn.name, turn.arguments, ctx)
                refused = False
            except Exception as exc:
                result = {"error": str(exc)}
                refused = True
        # The agent adds facts; it never replaces one the code lookups found, so
        # the same target keeps the same facts however the agent spends its turns.
        if turn.name != "done" and not refused and known is None:
            if turn.name not in evidence:
                evidence[turn.name] = result
                evidence = consistent_evidence(evidence)
            else:
                # a second subject for a tool already used: another host, a CNAME
                # target, another URL. Kept beside the code's facts for rank to read.
                evidence[AGENT_FINDINGS] = [
                    *evidence.get(AGENT_FINDINGS, []),
                    {"tool": turn.name, "args": turn.arguments, "result": result},
                ]
        observe = "refused" if refused else "ok"
        trace.append(
            TraceEvent(
                kind="observe",
                tool=turn.name,
                arguments=turn.arguments,
                result=result,
                note=observe,
            )
        )
        emit(
            on_event,
            {
                "type": "observe",
                "target": _event_target(ref, cl),
                "tool": turn.name,
                "args": turn.arguments,
                "result_summary": summarize(result),
                "tokens": 0,
                "cost_usd": 0.0,
            },
        )
        messages.append(
            {
                "role": "assistant",
                "content": json.dumps(
                    {"tool": turn.name, "arguments": turn.arguments}
                ),
            }
        )
        messages.append(
            {"role": "user", "content": json.dumps({"observe": observe, "result": result})}
        )
        if turn.name == "done" and not refused:
            summary = str(result.get("summary") or "")
            break

    return Investigation(
        file=ref.file,
        line=ref.line,
        host_or_bucket=ref.host_or_bucket,
        status="done",
        summary=summary,
        evidence=evidence,
        trace=trace,
        cost_usd=cost_total,
    )


def _event_kind(ref: Reference, cl: Classification) -> str:
    if cl.type == "bucket" or _is_bucket_ref(ref):
        return "bucket"
    return "domain"


def _event_target(ref: Reference, cl: Classification) -> str:
    # The same name rank groups by, so a target's agent run, facts and finding line up.
    return public_target(ref, cl)[0]


def _past(deadline: float | None) -> bool:
    return deadline is not None and time.monotonic() >= deadline


def _time_skip(ref: Reference, evidence: dict[str, Any]) -> Investigation:
    # keep the precheck facts so rank and its floors still see them
    return Investigation(
        file=ref.file,
        line=ref.line,
        host_or_bucket=ref.host_or_bucket,
        status="done",
        summary=TIME_NOTE,
        evidence=evidence,
    )


def _budget_skip(ref: Reference, evidence: dict[str, Any]) -> Investigation:
    # The lookups are free and already done; dropping them hid real floors
    # whenever the model budget ran out first.
    return Investigation(
        file=ref.file,
        line=ref.line,
        host_or_bucket=ref.host_or_bucket,
        status="budget",
        summary=BUDGET_NOTE,
        evidence=evidence,
    )


def _model_turn(
    client: ModelClient,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
) -> tuple[ToolTurn, CallLog]:
    turn = client.complete_turn(
        model=AGENT_MODEL,
        system=AGENT_SYSTEM_PROMPT,
        messages=messages,
        tools=tools,
        reasoning_effort=AGENT_REASONING_EFFORT,
    )
    in_tok, out_tok, usage = _tokens(turn.usage)
    log = CallLog(
        model=AGENT_MODEL,
        input_tokens=in_tok,
        output_tokens=out_tok,
        cost_usd=cost_usd(AGENT_MODEL, in_tok, out_tok),
        api_usage=usage or None,
    )
    return turn, log
