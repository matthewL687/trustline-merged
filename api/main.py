from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import traceback
from pathlib import Path
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any, Literal

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from api.classify_target import TargetError, classify_target
from api.demo import demo_gap_ms, demo_report, load_demo
from api.jobs import Job, JobStore
from api.limits import LimitsStore, client_ip
from scanner.config import (
    DEFAULT_AGENT_DEADLINE_S,
    DEFAULT_RANK_DEADLINE_S,
    SERVERLESS_CLASSIFY_DEADLINE_S,
    SCAN_COST_CAP_USD,
    SERVERLESS_AGENT_DEADLINE_S,
    SERVERLESS_RANK_DEADLINE_S,
    on_serverless,
)
from scanner.llm import (
    DisabledModelClient,
    LiveModelClient,
    ModelClient,
    failure_message,
    redact_secrets,
)
from scanner.lookups import LookupCache, default_cache
from scanner.report import ScanOutcome, run_scan
from scanner.ssrf import allow_local_scan
from scanner.tools import ToolContext

ScanRunner = Callable[..., Awaitable[ScanOutcome]]
log = logging.getLogger("trustmap")
# The page lives in public/, which Vercel serves from its CDN; elsewhere this app serves it.
PUBLIC = Path(__file__).resolve().parents[1] / "public"
FIXTURES = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
MODEL_UNCONFIGURED = "Model scans need MODEL_API_KEY and TRUSTMAP_ENABLE_MODEL_SCANS=1"
PATH_REFUSED = "Paste a GitHub repository or website URL"
HEARTBEAT_S = 15.0
SSE_HEADERS = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}


class FreshStatic(StaticFiles):
    """Revalidate on every load, so a redeploy never pairs new HTML with an old script."""

    async def get_response(self, path, scope):
        response = await super().get_response(path, scope)
        response.headers["Cache-Control"] = "no-cache"
        return response


def path_scan_allowed(target: str) -> bool:
    """A public server must not read its own disk for strangers; fixtures are fine."""
    if allow_local_scan():
        return True
    return Path(target).resolve().is_relative_to(FIXTURES.resolve())


def _load_local_env() -> None:
    for candidate in (Path(".env"), Path(__file__).resolve().parents[1] / ".env"):
        if candidate.is_file():
            load_dotenv(candidate, override=False)
            return


class ScanIn(BaseModel):
    target: str
    kind: Literal["repo", "path", "website"] | None = None


def _cors_origins() -> list[str]:
    raw = os.environ.get("TRUSTMAP_CORS_ORIGINS", "*")
    if raw.strip() == "*":
        return ["*"]
    return [item.strip() for item in raw.split(",") if item.strip()]


def _sse(event: dict[str, Any]) -> str:
    return f"data: {json.dumps(event)}\n\n"


def _job_stream(job: Job) -> StreamingResponse:
    async def gen() -> AsyncIterator[str]:
        async for event in job.stream(heartbeat=HEARTBEAT_S):
            # an SSE comment keeps proxies from closing a quiet stream
            yield ": keep-alive\n\n" if event is None else _sse(event)

    return StreamingResponse(gen(), media_type="text/event-stream", headers=SSE_HEADERS)


def _deadline(env: str, serverless_default: float, start: float) -> float | None:
    raw = os.environ.get(env, "").strip()
    seconds = float(raw) if raw else (serverless_default if on_serverless() else 0.0)
    return start + seconds if seconds > 0 else None


def agent_deadline(start: float | None = None) -> float | None:
    """When the agent stage must stop starting new work, as a time.monotonic() value."""
    start = time.monotonic() if start is None else start
    default = SERVERLESS_AGENT_DEADLINE_S if on_serverless() else DEFAULT_AGENT_DEADLINE_S
    return _deadline("TRUSTMAP_AGENT_DEADLINE_S", default, start)


def rank_deadline(start: float | None = None) -> float | None:
    """When rank must stop starting model calls, so the scan ends before the host cuts it off."""
    start = time.monotonic() if start is None else start
    default = SERVERLESS_RANK_DEADLINE_S if on_serverless() else DEFAULT_RANK_DEADLINE_S
    return _deadline("TRUSTMAP_RANK_DEADLINE_S", default, start)


def classify_deadline(start: float | None = None) -> float | None:
    """Bound model classification on serverless hosts before falling back by file context."""
    start = time.monotonic() if start is None else start
    if not on_serverless():
        return None
    return _deadline(
        "TRUSTMAP_CLASSIFY_DEADLINE_S", SERVERLESS_CLASSIFY_DEADLINE_S, start
    )


def create_app(
    *,
    model_client: ModelClient | None = None,
    cache: LookupCache | None = None,
    ctx: ToolContext | None = None,
    cost_cap: float = SCAN_COST_CAP_USD,
    runner: ScanRunner | None = None,
    limits: LimitsStore | None = None,
) -> FastAPI:
    _load_local_env()
    app = FastAPI(
        title="Trustline",
        description="Find abandoned outside infrastructure a repository or website still trusts.",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins(),
        allow_methods=["*"],
        allow_headers=["*"],
    )
    store = JobStore()
    running: set[asyncio.Task] = set()
    app.state.store = store
    scan_runner = runner or run_scan
    client_holder: dict[str, ModelClient | None] = {"client": model_client}
    lookup_default = cache or default_cache()
    limit_store = limits or LimitsStore(lookup_default.path)

    def client() -> ModelClient:
        held = client_holder["client"]
        if held is None:
            held = LiveModelClient()
            client_holder["client"] = held
        return held

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(PUBLIC / "index.html", headers={"Cache-Control": "no-cache"})

    # On Vercel the CDN serves public/ and leaves it out of the function bundle, so the
    # folder must not be required at startup.
    app.mount("/static", FreshStatic(directory=PUBLIC / "static", check_dir=False), name="static")

    @app.get("/api/health")
    def health() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/api/scan/demo")
    def demo() -> dict[str, Any]:
        return demo_report()

    @app.get("/api/scan/demo/events")
    async def demo_events(
        speed: str | None = Query(default=None),
    ) -> StreamingResponse:
        try:
            gap_ms = demo_gap_ms(speed)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        payload = load_demo()
        events = list(payload["events"])

        async def gen() -> AsyncIterator[str]:
            for index, event in enumerate(events):
                if index and gap_ms:
                    await asyncio.sleep(gap_ms / 1000)
                yield _sse(event)

        return StreamingResponse(gen(), media_type="text/event-stream")

    def model_scans_enabled() -> bool:
        enabled = os.environ.get("TRUSTMAP_ENABLE_MODEL_SCANS", "").strip().lower()
        return model_client is not None or enabled in {"1", "true", "yes"}

    def live_ready() -> bool:
        return model_client is not None or not model_scans_enabled() or bool(
            os.environ.get("MODEL_API_KEY", "").strip()
        )

    def admit(body: ScanIn, request: Request) -> Job | JSONResponse:
        """Check the target and the limits, then start the scan as a background job."""
        try:
            kind, target = classify_target(body.target, body.kind)
        except TargetError as exc:
            return JSONResponse(status_code=exc.status_code, content=exc.body)
        if kind == "path" and not path_scan_allowed(target):
            return JSONResponse(status_code=400, content={"error": PATH_REFUSED, "kind": "path"})
        if not live_ready():
            return JSONResponse(status_code=503, content={"error": MODEL_UNCONFIGURED})
        use_model = model_scans_enabled()
        ip = client_ip(request, hops=limit_store.trusted_hops)
        job = Job(kind=kind, target=target)
        blocked = limit_store.admit(ip, job.scan_id, cost_cap if use_model else 0.0)
        if blocked:
            return JSONResponse(status_code=429, content={"error": blocked})
        store.add(job)
        job.emit(
            {
                "type": "started",
                "kind": kind,
                "target": target,
                "cost_cap_usd": cost_cap if use_model else 0.0,
                "model_calls_enabled": use_model,
                # on a serverless host the next request can land on another
                # instance, which has never heard of this job
                "shareable": not on_serverless(),
            }
        )
        task = asyncio.create_task(_run_job(job))
        running.add(task)
        task.add_done_callback(running.discard)
        return job

    @app.post("/api/scan", response_model=None)
    async def start_scan(body: ScanIn, request: Request):
        job = admit(body, request)
        if isinstance(job, JSONResponse):
            return job
        return {"scan_id": job.scan_id, "kind": job.kind, "target": job.target}

    @app.post("/api/scan/stream", response_model=None)
    async def stream_scan(body: ScanIn, request: Request):
        # Start and follow a scan in one request, which is all a serverless host
        # guarantees. The job is still stored, so share links work where the
        # process lives on.
        job = admit(body, request)
        if isinstance(job, JSONResponse):
            return job
        return _job_stream(job)

    async def _run_job(job: Job) -> None:
        def on_event(payload: dict[str, Any]) -> None:
            job.emit(payload)

        actual = 0.0
        start = time.monotonic()
        use_model = model_scans_enabled()
        deadlines = {
            name: value
            for name, value in (
                ("deadline", agent_deadline(start)),
                ("rank_deadline", rank_deadline(start)),
                ("classify_deadline", classify_deadline(start)),
            )
            if value is not None
        }
        try:
            lookup = cache or lookup_default
            outcome = await scan_runner(
                job.target,
                client=client() if use_model else DisabledModelClient(),
                cache=lookup,
                ctx=ctx or ToolContext(cache=lookup),
                hydrate_only=False,
                cost_cap=cost_cap if use_model else 0.0,
                model_enabled=use_model,
                on_event=on_event,
                **deadlines,
            )
            actual = outcome.cost_usd
            job.finish(outcome)
        except Exception as exc:
            # the page gets one line; the host's log gets the whole traceback
            trace = "".join(traceback.format_exception(exc))
            log.error("scan %s failed\n%s", job.scan_id, redact_secrets(trace))
            job.fail(failure_message(exc))
        finally:
            limit_store.reconcile(job.scan_id, actual)

    @app.get("/api/scan/{scan_id}/events")
    async def scan_events(scan_id: str) -> StreamingResponse:
        job = store.get(scan_id)
        if job is None:
            raise HTTPException(status_code=404, detail="unknown scan")
        return _job_stream(job)

    @app.get("/api/scan/{scan_id}", response_model=None)
    def scan_report(scan_id: str):
        job = store.get(scan_id)
        if job is None:
            raise HTTPException(status_code=404, detail="unknown scan")
        if job.status == "running":
            raise HTTPException(status_code=409, detail="scan still running")
        if job.status == "error":
            return JSONResponse(
                status_code=500,
                content={
                    "scan_id": job.scan_id,
                    "status": "error",
                    "error": job.error,
                },
            )
        assert job.report is not None
        return job.report

    return app


app = create_app
