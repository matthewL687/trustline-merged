# Trustline scan API

Base URL is the FastAPI app (`uvicorn api.main:app --factory`). All JSON events are
SSE frames `data: {json}\n\n`. Every event object has `type`, `scan_id`, and `ts`.

Jobs live in process memory. A restart forgets them.

## `POST /api/scan`

Start a scan. `kind` is inferred from `target` (`repo` = GitHub URL, `path` = existing
local path, `website` = other `http(s)` URL) and may be set explicitly.

`path` targets are refused with 400 `{"error": "Paste a GitHub repository or website URL"}`
unless `TRUSTMAP_ALLOW_LOCAL_SCAN=1` or the path is inside `tests/fixtures`, so a public
server never reads its own disk for a stranger.

Repository targets are shallow-cloned with `git`. Without a working `git` (for example
a Mac without developer tools) the scanner downloads GitHub's archive of the default
branch instead.

```json
{"target": "https://github.com/acme/widgets"}
```

```json
{"scan_id": "7c2e1a9b", "kind": "repo", "target": "https://github.com/acme/widgets"}
```

Website targets are fetched once (no JS execution). Private, loopback, link-local,
multicast, reserved, and unspecified addresses are refused with:

```json
{"type": "error", "message": "This address can't be scanned"}
```

```json
POST /api/scan
{"target": "https://example.com"}

{"scan_id": "7c2e1a9b", "kind": "website", "target": "https://example.com"}
```

Public-safety limits (demo routes are exempt):

- Daily model-spend cap (`TRUSTMAP_DAILY_CAP_USD`, default 10). Each accepted scan
  reserves the per-scan cap (`SCAN_COST_CAP_USD`, default 1) against the day, then
  reconciles to actual spend when the job ends. This ledger is reliable on a
  long-lived server with shared SQLite storage; on Vercel's ephemeral instances it is
  per instance, so it is not a global spending ceiling.
- Per-IP cap (`TRUSTMAP_IP_SCANS_PER_HOUR`, default 20). Client `X-Forwarded-For` is
  ignored unless `TRUSTMAP_TRUSTED_PROXY_HOPS` is set (0 locally, 1 on Render).
- Concurrent jobs (`TRUSTMAP_MAX_CONCURRENT_SCANS`, default 3) → 429
  `"Busy, try again in a minute"`.

When the daily cap is hit:

```json
429
{"error": "Daily limit reached, try the demo"}
```

Unknown `scan_id` on later GETs → 404.

On serverless hosts, live scans are disabled unless `TRUSTMAP_ENABLE_LIVE_SCANS=1` is set.
This fail-closed default keeps public traffic from spending the server's model budget.
The recorded demo remains available without a key. If live scans are enabled,
`MODEL_API_KEY` must also be set. Local development can continue to use a key without
the serverless opt-in.

If `MODEL_API_KEY` is not set (and no test client is injected, or live scans are paused):

```json
503
{"error": "Live scans are paused on this server; try the demo"}
```

No job is created. Demo routes do not need the key.

## `POST /api/scan/stream`

Same body, checks and JSON refusals (400, 429, 503) as `POST /api/scan`, but the response
is the scan's event stream itself (`text/event-stream`), from `started` to `done` or
`error`. The page uses this so a scan works on a serverless host, where a second request
may reach a different instance. The job is still stored, so `GET /api/scan/{id}` and the
events replay work on a long-lived server.

`started` carries `shareable`: `false` when `VERCEL` or `TRUSTMAP_SERVERLESS=1` is set,
because another instance cannot replay the job.

Every event stream sends an SSE comment (`: keep-alive`) after 15 quiet seconds.

`TRUSTMAP_AGENT_DEADLINE_S` sets how many seconds into a scan the agent stage stops
starting new work (default 170 on serverless hosts and 240 elsewhere). Targets it skips
keep their lookup evidence, so ranking and the severity floors still see it.
`TRUSTMAP_RANK_DEADLINE_S` does the same for ranking (default 250 on serverless hosts
and 480 elsewhere): targets not ranked by then keep the code severity, with the risk
text saying so. Set either to `0` to disable its deadline. Model API requests time out
after 30 seconds.

`TRUSTMAP_CLASSIFY_DEADLINE_S` bounds classification on serverless hosts (default 105).
It groups repeated references, submits up to eight batches concurrently, and labels
unfinished groups with low-confidence file-context fallbacks so later scan stages can
proceed. Clean targets that have no code flags skip model ranking.

## `GET /api/scan/{id}/events`

Replay buffered events, then live ones, then close on `done` or `error`.

| `type` | When | Payload |
|---|---|---|
| `started` | job accepted | `kind`, `target`, `cost_cap_usd` |
| `extracted` | after extract | `references`, `actionable`, `filtered`, `coverage` (`files_scanned`, `files_total`, `truncated`, `reason`), `targets` (first 300: `target`, `kind`, `platform`, `refs`, `files`, `first` {`file`, `line`, `raw`}), `targets_total`, `set_aside` ({reason: {`count`, `examples`}}) |
| `classified` | after classify | `items` (first 300 actionable references: `target`, `file`, `line`, `type`, `runs_in`, `blast_radius`, `confidence`, `reason`), `total` |
| `precheck` | after lookups for one reference | `target`, `kind` (bucket/domain), `hard_signal`, `next` for the whole target (`agent`: a red flag, one agent run; `facts`: clean lookups, ranked without the agent; `popular`; `low_exposure`: not ranked), and on the first event for each target only `evidence`, `flags` (the red flags in words) and `max_turns` (agent targets) |
| `checked` | history from code for a target with no red flag | `target`, `evidence` (the target's facts, now with `cert_history` and `wayback`) |
| `plan` / `act` / `observe` | each agent turn | `target`, `tool`, `args`, `result_summary`, `tokens`, `cost_usd` |
| `ranked` | each finding after rank | public finding fields (see report JSON) |
| `done` | finished | `finding_count`, `cost_usd`, `classify_cost_usd`, `agent_cost_usd`, `rank_cost_usd`, `budget_targets` |
| `error` | failure | `message` (no secrets) |

Live scans are not paced. Demo replay is (see below).

## `GET /api/scan/{id}`

Final report. **409** if still running, **404** if unknown, **500** if the job failed.

```json
{
  "scan_id": "7c2e1a9b",
  "kind": "repo",
  "target": "https://github.com/acme/widgets",
  "status": "done",
  "cost_usd": 0.12,
  "classify_cost_usd": 0.04,
  "agent_cost_usd": 0.06,
  "rank_cost_usd": 0.02,
  "budget_targets": [],
  "coverage": {
    "files_scanned": 12,
    "files_total": 12,
    "truncated": false,
    "reason": ""
  },
  "findings": [
    {
      "target": "cdn-assets-trustmap-7f3k2.com",
      "kind": "domain",
      "severity": "critical",
      "model_severity": "high",
      "floor_reason": "RDAP unregistered in executing position (browser) is at least critical",
      "floor_applied": "critical",
      "risk": "...",
      "fix": "Remove or replace this reference. If this was yours, re-create it in your own account to reclaim the name.",
      "evidence_line": "Evidence: DNS does not resolve · domain not registered",
      "evidence": {
        "dns": {"status": "nxdomain"},
        "rdap": {"status": "unregistered"},
        "tranco_rank": null,
        "live_fetch": {
          "parked": false,
          "for_sale": false,
          "signal": null,
          "final_url": "https://cdn-assets-trustmap-7f3k2.com/lib.js",
          "status": "ok"
        }
      },
      "tranco_rank": null,
      "parked": false,
      "for_sale": false,
      "live_signal": null,
      "action_ref": "",
      "action_sha_pinned": null,
      "references": ["index.html:7"],
      "cost_usd": 0.02
    }
  ]
}
```

Extra finding fields:

- `tranco_rank`: int or null (popularity; never lowers a code floor)
- `floor_reason`: the code rule behind the severity, set whenever a rule applies; `floor_applied` is the level when that rule raised the model's call
- `ceiling_note`: set when Muse Spark said high or critical with no code rule behind it, so the finding stays in Review
- `evidence.agent_findings`: lookups the agent ran on another subject than the code did (another host, a CNAME target, another URL): `tool`, `args`, `result`. They never replace the code's facts
- `evidence.live_fetch`: `final_url`, `http_status`, `redirect_chain`, `title`, `parked`, `for_sale`, `signal`
- `action_ref` / `action_sha_pinned`: GitHub Actions `uses:` pin (full 40-char SHA or not)
- `evidence.github_repo`: `exists` / `missing` / `disabled` for `owner/repo` actions (`disabled`: GitHub blocked the repo; the owner still holds the name, so it is Review, not Fix today)
- `uncertain_about`: what the ranker said it could not tell from the evidence
- `needs_review`: true when the ranker's sentence failed the evidence check and code set the severity
- `classified_blast_radius` / `blast_radius` / `blast_override_reason`: blast radius from
  classify, the ranker's value, and why the ranker changed it

Website findings put page locations in `references` (`page_url`, `tag`, `attribute`,
`line`, `sri`, `raw`) instead of `file:line`.

Jobs are in-process only: `GET /api/scan/{id}` works for a finished scan until the
process restarts. Shareable `?scan=<id>` is valid for that lifetime.

## `GET /api/health`

```json
{"ok": true}
```

## Demo (no models)

Saved fixture scan from `tests/fixtures/demo_repo` with `FakeModelClient`, checked in as
`api/demo_scan.json`.

- `GET /api/scan/demo` → finished report JSON (no model calls).
- `GET /api/scan/demo/events` → SSE replay of that file.

Replay pacing: **150 ms** between events by default (`DEMO_EVENT_GAP_MS`). Override with
`?speed=` as milliseconds (`?speed=0` for tests). The first event is sent immediately.

Register `/demo` before `/{id}`.
