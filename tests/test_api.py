import asyncio
import json
import re
import shutil
import ssl
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.classify_target import classify_target, infer_kind
from api.demo import demo_gap_ms, demo_report, load_demo
from api.jobs import Job
from scanner.extract import CloneError
from api.main import LIVE_UNCONFIGURED, create_app
from scanner.config import DEMO_EVENT_GAP_MS, SCAN_COST_CAP_USD
from scanner.llm import FakeModelClient
from scanner.lookups import LookupCache
from scanner.models import BucketProbeResult
from scanner.report import ScanOutcome
from tests.test_agent import _ctx, _scripted_client
from tests.test_report import _fixture_handler

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "demo_repo"


def _parse_sse(text: str) -> list[dict]:
    events = []
    for block in text.split("\n\n"):
        line = block.strip()
        if line.startswith("data: "):
            events.append(json.loads(line[6:]))
    return events


def _fixture_app(**kwargs):
    async def fake_bucket(name, provider, cache=None, **kw):
        missing = "acme-static-assets" not in name
        return BucketProbeResult(
            name=name,
            provider=provider,
            status="NoSuchBucket" if missing else "exists",
            http_status=404 if missing else 403,
        )

    tmp_path = kwargs.pop("tmp_path")
    client = FakeModelClient(
        handler=_fixture_handler(),
        tool_handler=_scripted_client().tool_handler,
    )
    cache = LookupCache(tmp_path / "api.db")
    return create_app(
        model_client=client,
        cache=cache,
        ctx=_ctx(tmp_path, bucket_probe=fake_bucket),
        **kwargs,
    )


def test_home_page_and_demo_replay():
    app = create_app(model_client=FakeModelClient(handler=lambda r: {}))
    with TestClient(app) as client:
        home = client.get("/")
        assert home.status_code == 200
        body = home.text
        assert "<title>Trustline</title>" in body
        assert 'id="target"' in body
        assert 'id="targets-tab"' in body
        css = client.get("/static/app.css")
        js = client.get("/static/app.js")
        assert css.status_code == 200
        assert js.status_code == 200
        assert "EventSource" in js.text
        demo = client.get("/api/scan/demo/events", params={"speed": "0"})
        assert demo.status_code == 200
        types = [item.get("type") for item in _parse_sse(demo.text)]
        assert "done" in types


def test_live_scan_without_key_returns_503(monkeypatch):
    monkeypatch.setattr("api.main._load_local_env", lambda: None)
    monkeypatch.delenv("MODEL_API_KEY", raising=False)
    monkeypatch.setenv("TRUSTMAP_ENABLE_MODEL_SCANS", "1")
    app = create_app()
    with TestClient(app) as client:
        response = client.post("/api/scan", json={"target": "https://example.com"})
        assert response.status_code == 503
        assert response.json() == {"error": LIVE_UNCONFIGURED}
        assert app.state.store._jobs == {}


def test_health_and_cors():
    app = create_app(model_client=FakeModelClient(handler=lambda r: {}))
    with TestClient(app) as client:
        response = client.get(
            "/api/health", headers={"Origin": "http://localhost:3000"}
        )
        assert response.status_code == 200
        assert response.json() == {"ok": True}
        assert response.headers.get("access-control-allow-origin") in {
            "*",
            "http://localhost:3000",
        }


def test_infer_kind_and_website_accepted():
    assert infer_kind("https://github.com/acme/widgets") == "repo"
    assert infer_kind(str(FIXTURE_ROOT)) == "path"
    assert infer_kind("https://example.com") == "website"
    assert classify_target("https://example.com") == ("website", "https://example.com")


def test_post_website_starts_job():
    async def runner(*args, **kwargs):
        return ScanOutcome(findings=[])

    app = create_app(
        model_client=FakeModelClient(handler=lambda r: {}),
        runner=runner,
    )
    with TestClient(app) as client:
        response = client.post("/api/scan", json={"target": "https://example.com"})
        assert response.status_code == 200
        body = response.json()
        assert body["kind"] == "website"
        assert body["target"] == "https://example.com"
        assert body["scan_id"]


def test_post_github_returns_kind_without_clone():
    async def runner(*args, **kwargs):
        return ScanOutcome(findings=[])

    app = create_app(
        model_client=FakeModelClient(handler=lambda r: {}),
        runner=runner,
    )
    with TestClient(app) as client:
        response = client.post(
            "/api/scan", json={"target": "https://github.com/acme/widgets"}
        )
        assert response.status_code == 200
        body = response.json()
        assert body["kind"] == "repo"
        assert body["target"] == "https://github.com/acme/widgets"
        assert body["scan_id"]


def test_report_409_while_running():
    app = create_app(model_client=FakeModelClient(handler=lambda r: {}))
    job = Job(kind="path", target=str(FIXTURE_ROOT))
    app.state.store.add(job)
    with TestClient(app) as client:
        assert client.get(f"/api/scan/{job.scan_id}").status_code == 409


def test_unknown_scan_404():
    app = create_app(model_client=FakeModelClient(handler=lambda r: {}))
    with TestClient(app) as client:
        assert client.get("/api/scan/missing").status_code == 404
        assert client.get("/api/scan/missing/events").status_code == 404


def test_fixture_path_scan_sse_and_report(tmp_path):
    app = _fixture_app(tmp_path=tmp_path)
    with TestClient(app) as client:
        posted = client.post("/api/scan", json={"target": str(FIXTURE_ROOT)})
        assert posted.status_code == 200
        assert posted.json()["kind"] == "path"
        scan_id = posted.json()["scan_id"]
        stream = client.get(f"/api/scan/{scan_id}/events")
        assert stream.status_code == 200
        events = _parse_sse(stream.text)
        types = [item["type"] for item in events]
        assert types[0] == "started"
        assert "extracted" in types
        extracted = next(item for item in events if item["type"] == "extracted")
        assert extracted["coverage"]["files_scanned"] >= 1
        assert extracted["coverage"]["files_total"] >= extracted["coverage"]["files_scanned"]
        assert "truncated" in extracted["coverage"]
        assert "precheck" in types
        assert "ranked" in types
        assert types[-1] == "done"
        assert all(item["scan_id"] == scan_id for item in events)
        report = client.get(f"/api/scan/{scan_id}")
        assert report.status_code == 200
        body = report.json()
        assert body["status"] == "done"
        assert body["findings"]
        critical = {
            item["target"]
            for item in body["findings"]
            if item["severity"] == "critical"
        }
        assert {
            "acme-legacy-uploads-a3f91c2e",
            "cdn-assets-trustmap-7f3k2.com",
            "trustmap-demo-assets",
            "github.com/trustmap-missing-owner-a3f91c2e",
            "trustmap-demo-pages.github.io",
            "trustmapdemoassets",
        } <= critical
        assert body["coverage"]["files_scanned"] == extracted["coverage"]["files_scanned"]
        assert "cost_usd" in body
        assert body["cost_usd"] == pytest.approx(
            body["classify_cost_usd"]
            + body["agent_cost_usd"]
            + body["rank_cost_usd"]
        )


def test_tiny_cost_cap_lists_budget_targets(tmp_path):
    app = _fixture_app(tmp_path=tmp_path, cost_cap=0.0)
    with TestClient(app) as client:
        scan_id = client.post(
            "/api/scan", json={"target": str(FIXTURE_ROOT)}
        ).json()["scan_id"]
        events = _parse_sse(client.get(f"/api/scan/{scan_id}/events").text)
        done = events[-1]
        assert done["type"] == "done"
        assert done["budget_targets"]
        report = client.get(f"/api/scan/{scan_id}").json()
        assert report["budget_targets"] == done["budget_targets"]


def test_demo_report_and_events_offline():
    assert DEMO_EVENT_GAP_MS == 150
    assert demo_gap_ms(None) == 150
    assert demo_gap_ms("0") == 0
    assert demo_gap_ms("40") == 40
    with pytest.raises(ValueError):
        demo_gap_ms("-1")
    payload = load_demo()
    app = create_app(model_client=FakeModelClient(handler=lambda r: {}))
    with TestClient(app) as client:
        report = client.get("/api/scan/demo")
        assert report.status_code == 200
        body = report.json()
        assert body == demo_report(payload)
        assert "events" not in body
        assert body["status"] == "done"
        assert body["findings"]
        stream = client.get("/api/scan/demo/events?speed=0")
        assert stream.status_code == 200
        events = _parse_sse(stream.text)
        assert events == payload["events"]
        assert events[0]["type"] == "started"
        assert events[-1]["type"] == "done"
        assert client.get("/api/scan/demo/events?speed=nope").status_code == 400


def test_demo_gap_default_matches_config():
    assert demo_gap_ms("") == DEMO_EVENT_GAP_MS
    assert SCAN_COST_CAP_USD == 1.00


PUBLIC = Path(__file__).resolve().parents[1] / "public"
STATIC = PUBLIC / "static"


def test_frontend_shows_the_five_layers_and_no_design_switcher():
    markup = (PUBLIC / "index.html").read_text()
    for number, name in enumerate(
        ("Gather", "Classify", "Investigate", "Reason", "Report"), start=1
    ):
        assert f'id="layer-{number}"' in markup
        assert f">{name}</h2>" in markup
    # a floating Home/Scanning/Results control is a design-tool affordance
    assert "showSwitcher" not in markup
    assert "Trustmap" not in markup
    assert markup.count("Trustline") > 1
    assert "Inter+Tight" in markup and "IBM+Plex+Mono" in markup


def test_layer_panels_ship_empty_so_only_api_data_renders():
    markup = (PUBLIC / "index.html").read_text()
    for panel in ("c1", "c2", "c3", "c4", "c5"):
        assert re.search(rf'id="{panel}"[^>]*>\s*</div>', markup), panel
    script = (STATIC / "app.js").read_text()
    for mock in ("paperplane", "trustline-demo-", "polyfill.io"):
        assert mock not in script, mock


def test_frontend_never_writes_report_text_as_html():
    script = (STATIC / "app.js").read_text()
    assert "innerHTML" not in script
    assert "outerHTML" not in script
    assert "insertAdjacentHTML" not in script
    assert "alert(" not in script
    # report targets must not become links
    assert 'createElement("a")' not in script


def test_frontend_keeps_only_the_scan_id_in_the_url():
    script = (STATIC / "app.js").read_text()
    assert '"?scan=" + encodeURIComponent(id)' in script
    assert '"?demo=1"' in script


def test_frontend_handles_every_documented_sse_event():
    script = (STATIC / "app.js").read_text()
    for event_type in ("started", "extracted", "classified", "precheck", "plan",
                       "act", "observe", "ranked", "done", "error"):
        assert f'"{event_type}"' in script, event_type


def test_static_assets_are_served_and_packaged():
    app = create_app(model_client=FakeModelClient(handler=lambda r: {}))
    with TestClient(app) as client:
        for path in ("/static/app.css", "/static/app.js", "/static/targets.json"):
            response = client.get(path)
            assert response.status_code == 200
            # a redeploy must never pair new HTML with a cached old script
            assert response.headers["cache-control"] == "no-cache"
    packaging = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text()
    for name in ("index.html", "static/app.css", "static/app.js", "static/targets.json"):
        assert f'"public/{name}"' in packaging


async def test_events_emitted_from_a_worker_thread_reach_the_stream():
    # the blocking scan stages run via asyncio.to_thread, so emit() must wake a
    # stream waiter while the event loop is parked with nothing else to do
    job = Job(kind="repo", target="https://github.com/acme/widgets")
    received: list[dict] = []

    async def drain() -> None:
        async for event in job.stream():
            received.append(event)

    task = asyncio.create_task(drain())
    await asyncio.sleep(0.05)

    def emit_from_thread() -> None:
        job.emit({"type": "precheck", "target": "acme.test"})
        job.emit({"type": "done", "finding_count": 0})

    threading.Thread(target=emit_from_thread).start()
    await asyncio.wait_for(task, timeout=5)
    assert [item["type"] for item in received] == ["precheck", "done"]


def test_pasted_github_url_scans_end_to_end(tmp_path, monkeypatch):
    # the whole repo path: GitHub URL -> shallow clone -> extract -> report,
    # with the clone stubbed to the checked-in fixture repo
    def fake_clone(url: str, dest_parent: Path) -> Path:
        dest = dest_parent / "widgets"
        shutil.copytree(FIXTURE_ROOT, dest)
        return dest

    monkeypatch.setattr("scanner.extract._clone_github", fake_clone)
    app = _fixture_app(tmp_path=tmp_path)
    with TestClient(app) as client:
        posted = client.post(
            "/api/scan", json={"target": "https://github.com/acme/widgets"}
        )
        assert posted.status_code == 200
        assert posted.json()["kind"] == "repo"
        scan_id = posted.json()["scan_id"]
        events = _parse_sse(client.get(f"/api/scan/{scan_id}/events").text)
        types = [item["type"] for item in events]
        assert types[0] == "started" and types[-1] == "done"
        assert "ranked" in types
        report = client.get(f"/api/scan/{scan_id}").json()
        assert report["kind"] == "repo"
        assert report["target"] == "https://github.com/acme/widgets"
        assert report["findings"]


def test_clone_failure_is_reported_as_a_scan_error(tmp_path, monkeypatch):
    def refuse(url: str, dest_parent: Path) -> Path:
        raise CloneError("acme/widgets could not be downloaded; it may be private or renamed")

    monkeypatch.setattr("scanner.extract._clone_github", refuse)
    app = _fixture_app(tmp_path=tmp_path)
    with TestClient(app) as client:
        scan_id = client.post(
            "/api/scan", json={"target": "https://github.com/acme/widgets"}
        ).json()["scan_id"]
        events = _parse_sse(client.get(f"/api/scan/{scan_id}/events").text)
        failure = events[-1]
        assert failure["type"] == "error"
        assert "private or renamed" in failure["message"]
        assert client.get(f"/api/scan/{scan_id}").status_code == 500


def test_model_connection_failure_names_its_cause(tmp_path, caplog):
    # The SDK says only "Connection error."; the page and the host log need the reason.
    import httpx
    import openai

    async def runner(*args, **kwargs):
        request = httpx.Request("POST", "https://api.meta.ai/v1/chat/completions")
        try:
            raise ssl.SSLCertVerificationError(1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed")
        except ssl.SSLError as cause:
            raise openai.APIConnectionError(request=request) from cause

    app = create_app(model_client=FakeModelClient(handler=lambda r: {}), runner=runner)
    with caplog.at_level("ERROR", logger="trustmap"), TestClient(app) as client:
        events = _parse_sse(
            client.post("/api/scan/stream", json={"target": str(FIXTURE_ROOT)}).text
        )
    failure = events[-1]
    assert failure["type"] == "error"
    assert failure["message"].startswith("Couldn't reach the Meta Model API")
    assert "CERTIFICATE_VERIFY_FAILED" in failure["message"]
    assert "Traceback" in caplog.text and "APIConnectionError" in caplog.text


def test_frontend_falls_back_when_the_event_stream_cannot_open():
    # a client without EventSource, or a proxy that buffers the stream, must
    # still end up with the report rather than a dropped scan
    script = (STATIC / "app.js").read_text()
    assert "waitWithoutStream" in script
    assert "new EventSource" in script
    assert "catch" in script.split("new EventSource")[1][:200]
    assert "Live updates aren't available" in script


def test_events_carry_what_each_layer_shows(tmp_path):
    app = _fixture_app(tmp_path=tmp_path)
    with TestClient(app) as client:
        scan_id = client.post("/api/scan", json={"target": str(FIXTURE_ROOT)}).json()["scan_id"]
        events = _parse_sse(client.get(f"/api/scan/{scan_id}/events").text)
    types = [item["type"] for item in events]
    assert types.index("extracted") < types.index("classified") < types.index("precheck")
    extracted = next(item for item in events if item["type"] == "extracted")
    gathered = {row["target"]: row for row in extracted["targets"]}
    assert extracted["targets_total"] == len(gathered)
    assert gathered["acme-legacy-uploads-a3f91c2e"]["kind"] == "bucket"
    assert gathered["acme-legacy-uploads-a3f91c2e"]["refs"] == 2
    assert gathered["trustmap-demo-pages.github.io"]["platform"] == "GitHub Pages"
    assert gathered["cdn-assets-trustmap-7f3k2.com"]["first"]["file"] == "index.html"
    assert extracted["set_aside"]["reserved_domain"]["count"] >= 1
    assert sum(item["count"] for item in extracted["set_aside"].values()) == extracted["filtered"]
    classified = next(item for item in events if item["type"] == "classified")
    assert classified["total"] == extracted["actionable"] == len(classified["items"])
    assert {"type", "runs_in", "blast_radius", "reason"} <= set(classified["items"][0])
    prechecks = [item for item in events if item["type"] == "precheck"]
    with_evidence = [item for item in prechecks if "evidence" in item]
    # facts are about a target, so they travel once per target
    assert len(with_evidence) == len({item["target"] for item in prechecks})
    assert all(item["next"] in {"agent", "facts", "popular", "low_exposure"} for item in prechecks)
    gone = next(item for item in with_evidence if item["target"] == "acme-legacy-uploads-a3f91c2e")
    assert gone["evidence"]["bucket_probe"]["status"] == "NoSuchBucket"
    # the ranked targets are the same names the earlier layers used
    ranked = {item["target"] for item in events if item["type"] == "ranked"}
    assert ranked <= set(gathered)


def test_server_paths_are_refused_unless_local_scans_are_on(tmp_path, monkeypatch):
    async def runner(*args, **kwargs):
        return ScanOutcome(findings=[])

    monkeypatch.delenv("TRUSTMAP_ALLOW_LOCAL_SCAN", raising=False)
    app = create_app(model_client=FakeModelClient(handler=lambda r: {}), runner=runner)
    with TestClient(app) as client:
        refused = client.post("/api/scan", json={"target": str(tmp_path)})
        assert refused.status_code == 400
        assert refused.json()["error"] == "Paste a GitHub repository or website URL"
        assert app.state.store._jobs == {}
        fixture = client.post("/api/scan", json={"target": str(FIXTURE_ROOT)})
        assert fixture.status_code == 200
        monkeypatch.setenv("TRUSTMAP_ALLOW_LOCAL_SCAN", "1")
        assert client.post("/api/scan", json={"target": str(tmp_path)}).status_code == 200


def test_stream_endpoint_runs_a_scan_in_one_response(tmp_path, monkeypatch):
    monkeypatch.delenv("VERCEL", raising=False)
    monkeypatch.delenv("TRUSTMAP_SERVERLESS", raising=False)
    app = _fixture_app(tmp_path=tmp_path)
    with TestClient(app) as client:
        response = client.post("/api/scan/stream", json={"target": str(FIXTURE_ROOT)})
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        events = _parse_sse(response.text)
        assert events[0]["type"] == "started" and events[-1]["type"] == "done"
        assert events[0]["shareable"] is True
        scan_id = events[0]["scan_id"]
        # the job is stored too, so a share link can replay it on this process
        assert client.get(f"/api/scan/{scan_id}").json()["findings"]
        assert _parse_sse(client.get(f"/api/scan/{scan_id}/events").text) == events


def test_stream_endpoint_refuses_with_json_like_post(tmp_path, monkeypatch):
    monkeypatch.setattr("api.main._load_local_env", lambda: None)
    monkeypatch.delenv("MODEL_API_KEY", raising=False)
    monkeypatch.delenv("TRUSTMAP_ALLOW_LOCAL_SCAN", raising=False)
    app = create_app()
    with TestClient(app) as client:
        assert client.post("/api/scan/stream", json={"target": str(tmp_path)}).status_code == 400
        no_key = client.post("/api/scan/stream", json={"target": "https://github.com/acme/widgets"})
        assert no_key.status_code == 503
        assert no_key.json() == {"error": LIVE_UNCONFIGURED}
        assert app.state.store._jobs == {}


def test_serverless_scans_are_not_shareable_and_get_an_agent_deadline(monkeypatch):
    seen: dict = {}

    async def runner(*args, **kwargs):
        seen.update(kwargs)
        return ScanOutcome(findings=[])

    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.delenv("TRUSTMAP_AGENT_DEADLINE_S", raising=False)
    monkeypatch.delenv("TRUSTMAP_RANK_DEADLINE_S", raising=False)
    app = create_app(model_client=FakeModelClient(handler=lambda r: {}), runner=runner)
    with TestClient(app) as client:
        events = _parse_sse(
            client.post("/api/scan/stream", json={"target": "https://github.com/acme/widgets"}).text
        )
    assert events[0]["shareable"] is False
    assert events[-1]["type"] == "done"
    assert seen["deadline"] > 0
    # rank gets the 80 s after the agent stops, so the scan ends before the 300 s cutoff
    assert seen["rank_deadline"] - seen["deadline"] == pytest.approx(80, abs=1)


def test_job_stream_heartbeat_marks_quiet_stretches():
    async def run() -> list:
        job = Job(kind="repo", target="https://github.com/acme/widgets")
        seen: list = []

        async def drain() -> None:
            async for event in job.stream(heartbeat=0.05):
                seen.append(event)

        task = asyncio.create_task(drain())
        await asyncio.sleep(0.18)
        job.emit({"type": "done", "finding_count": 0})
        await asyncio.wait_for(task, timeout=5)
        return seen

    seen = asyncio.run(run())
    assert seen[0] is None and seen[-1]["type"] == "done"


def test_vercel_entrypoint_is_a_ready_app(tmp_path, monkeypatch):
    import importlib
    import tomllib

    from fastapi import FastAPI

    project = tomllib.loads((Path(__file__).resolve().parents[1] / "pyproject.toml").read_text())
    assert project["tool"]["vercel"]["entrypoint"] == "index:app"
    monkeypatch.setenv("TRUSTMAP_CACHE_DB", str(tmp_path / "vercel.db"))
    module = importlib.import_module("index")
    assert isinstance(module.app, FastAPI)
    with TestClient(module.app) as client:
        assert client.get("/api/health").json() == {"ok": True}
        assert client.get("/").status_code == 200


def test_frontend_streams_live_scans_in_one_request():
    script = (STATIC / "app.js").read_text()
    assert '"/api/scan/stream"' in script
    assert "getReader" in script
    # a scan on a serverless host can't be replayed from another instance
    assert "shareable" in script


def test_repos_to_try_list_is_well_formed():
    data = json.loads((STATIC / "targets.json").read_text())
    repos = [item for group in data["groups"] for item in group["repos"]]
    assert data["checked"] and data["note"] and len(repos) >= 10
    assert len({item["repo"] for item in repos}) == len(repos)
    for item in repos:
        assert re.fullmatch(r"[A-Za-z0-9-]+/[\w.-]+", item["repo"]), item["repo"]
        assert item["expect"] in {"critical", "high", "flagged", "mostly safe", "big run"}
        assert isinstance(item["targets"], int) and item["finding"] and item["checked"]
    # the side panel builds from this file; the page itself ships no list
    markup = (PUBLIC / "index.html").read_text()
    assert 'id="targets-tab"' in markup and re.search(r'id="targets-list"[^>]*>\s*</div>', markup)


def test_app_starts_without_the_public_folder(monkeypatch):
    # Vercel's CDN serves public/ and leaves it out of the function bundle
    import api.main as main

    monkeypatch.setattr(main, "PUBLIC", Path("/nonexistent/public"))
    app = create_app(model_client=FakeModelClient(handler=lambda r: {}))
    with TestClient(app) as client:
        assert client.get("/api/health").json() == {"ok": True}
        assert client.get("/api/scan/demo").status_code == 200



def test_page_shows_results_not_product_copy():
    # the demo video explains the product; the page keeps to inputs and results
    markup = (PUBLIC / "index.html").read_text()
    for copy in ("A title check for everything", "AI model:", "Evidence:", "Brief", "No key needed for the demo",
                 "Facts:", "Judgment:", "Scope:", 'class="desc', ">Target<", "Layers:"):
        assert copy not in markup, copy
    # the input is a search bar: its label is for screen readers only
    assert '<label class="sr" for="target">' in markup
    # run details are a dropdown under the input
    assert '<details class="run" id="run" hidden><summary>Run details</summary><p id="run-text"></p></details>' in markup


def test_each_layer_collapses_to_its_result():
    markup = (PUBLIC / "index.html").read_text()
    for n in range(1, 6):
        assert f'id="layer-{n}" data-state="pending" data-open="false"' in markup
        assert re.search(rf'id="r{n}"[^>]*>\s*</div>', markup), n
        assert f'data-toggle="{n}" aria-expanded="false" aria-controls="c{n}" hidden' in markup
        assert re.search(rf'id="c{n}" hidden>', markup), n
    script = (STATIC / "app.js").read_text()
    assert "var OPEN = { 1: false, 2: false, 3: false, 4: false, 5: false };" in script
    for name in ("summaryGather", "summaryClassify", "summaryInvestigate", "summaryReason", "summaryReport"):
        assert f"function {name}()" in script
    assert "function showDetails(n)" in script
    assert '"Hide details" : "Show details"' in script
    # engine and status open with the details; the Report tally carries the verdict
    assert 'setAttribute("data-open", open ? "true" : "false")' in script
    assert 'h("p", { class: "verdict"' not in script


def test_file_tray_has_its_own_box_and_its_cards_go_somewhere():
    # Riffle from @lucasmarkes/hairline (MIT), rebuilt from design/tray.ts, vendored with its license
    markup = (PUBLIC / "index.html").read_text()
    assert '<div class="cell stack-cell span-3" data-scan="idle">' in markup
    assert '<div class="cell tray-cell span-2">' in markup
    assert '<div class="files" id="files"></div>' in markup
    assert '<script type="module" src="/static/figure.js"></script>' in markup
    # straight slabs, and leaders that stop short of the labels
    assert "rotate(" not in markup
    assert markup.count('x1="252"') == 5 and markup.count('x2="364"') == 5
    # the About card opens a dialog dressed like the error one
    assert 'class="win about" id="about" role="dialog"' in markup and "ABOUT TRUSTLINE" in markup
    vendor = STATIC / "vendor"
    bundle = (vendor / "trustline-tray.js").read_text()
    assert bundle.startswith("/*! Trustline file tray: the Riffle figure from @lucasmarkes/hairline 0.5.1 (MIT License")
    assert "export{" in bundle and "mountTray" in bundle
    assert "Copyright (c) 2026 Lucas Marques" in (vendor / "hairline-LICENSE.txt").read_text()
    figure = (STATIC / "figure.js").read_text()
    assert 'import { mountTray } from "./vendor/trustline-tray.js";' in figure
    assert '"Run details", "Repos to try", "About"' in figure
    assert 'new CustomEvent("trustline:card"' in figure
    script = (STATIC / "app.js").read_text()
    assert 'document.addEventListener("trustline:card"' in script
    for name in ("goToLayer", "goToRun", "openDrawer", "showAbout"):
        assert f"{name}(" in script
    assert 'art.setAttribute("data-scan"' in script
    app = create_app(model_client=FakeModelClient(handler=lambda r: {}))
    with TestClient(app) as client:
        for path in ("/static/figure.js", "/static/vendor/trustline-tray.js"):
            served = client.get(path)
            assert served.status_code == 200, path
            assert "javascript" in served.headers["content-type"], path


def test_page_carries_the_logo_and_icons():
    markup = (PUBLIC / "index.html").read_text()
    for href in ("/static/favicon.svg", "/static/favicon-32.png", "/static/apple-touch-icon.png", "/static/logo.svg"):
        assert href in markup, href
        assert (PUBLIC / href.removeprefix("/")).is_file(), href
    app = create_app(model_client=FakeModelClient(handler=lambda r: {}))
    with TestClient(app) as client:
        icon = client.get("/static/favicon.svg")
        assert icon.status_code == 200
        assert icon.headers["content-type"].startswith("image/svg+xml")
