# Trustline

Code name: trustmap.

Paste a GitHub repository or a website. Trustline finds every outside domain, script,
cloud bucket, GitHub account and Action that the code trusts, checks who owns each one
now, and ranks the ones a stranger could take over: expired domains, deleted buckets,
abandoned accounts, unclaimed hosting. Detection only: it never registers or claims
anything.

![Trustline after the demo scan](docs/screenshot.png)

The page shows the scan as five layers, each filled in live from the scan's event stream.
Each layer shows its result; **Show details** opens the tables, lookups and agent steps
behind it:

| Layer | Engine | Code |
|---|---|---|
| 01 Gather | code: file walk or page fetch, patterns, filters | `scanner/extract.py`, `scanner/website.py` |
| 02 Classify | Muse Spark: what each reference is, where it runs, blast radius 0–3 | `scanner/classify.py` |
| 03 Investigate | code lookups (DNS, RDAP, bucket probes, GitHub, platform fingerprints, Tranco) and the live home page of every host worth ranking; a target with a red flag can get one Muse Spark agent run (at most 3 turns), with a scan-wide limit of 12 agent targets; a clean target gets its history (crt.sh, Wayback) from code | `scanner/agent.py`, `scanner/tools/` |
| 04 Reason | Muse Spark writes the risk; code checks every claim against the evidence and applies severity floors. Only a code rule can put a target in Fix today | `scanner/report.py` |
| 05 Report | code: fix today, review, checked and safe | `public/static/app.js` |

Facts come from deterministic tools and are cached in SQLite. The model never looks
anything up and never does date math.

To bound slow model work, one scan starts at most 12 agent investigations, with at
most 3 turns each. On long-lived hosts, new agent work stops 4 minutes after scan
start and new ranking calls stop after 8 minutes; Vercel keeps its shorter 170/250
second limits. Model requests time out after 30 seconds. Code lookups keep running
for every selected target, and the report retains their evidence when a model step
is skipped. Large repositories are still subject to the file and byte coverage caps
reported by Layer 01, and external service delays mean no fixed runtime can be
guaranteed for every repository.

Scanning the same repo twice puts the same targets in Fix today. A target lands there
only when a code rule says so (a missing bucket or account, an unregistered or dead
domain, an unclaimed platform, a parked or for-sale domain, a compromised domain, in a
place where it runs), and each one shows that rule. Every check those rules read runs in
code on every target, so none depends on which tools the agent picked. Without a rule,
Muse Spark's call reaches Review at most (its high calls lead Review), and model calls
ask for temperature 0. `tests/test_repeatable.py` scans the fixture repo six times with
a model that changes its mind and checks Fix today never moves.

The file tray beside the layers is a set of shortcuts. Point at a layer and its card
stands up; while a scan runs, the card of the layer at work stands up. Click a card to
jump to layers 01–05, open Run details, open Repos to try, or read About.

**Repos to try** (the tab on the right edge of the page) lists real repos to scan:
popular projects nobody maintains anymore that have something to flag, polyfill.io
holdouts, quick runs and clean controls. It reads `public/static/targets.json`, so edit
that file to change the list.

This repo merges two team builds: the scanner engine from
[Git083104/trustline](https://github.com/Git083104/trustline) and the five-layer
interface from [jwang2007/trustline](https://github.com/jwang2007/trustline).

## Run locally

Python 3.11 or newer. With plain pip:

```bash
python3 -m pip install -r requirements.txt
python3 -m uvicorn api.main:app --factory --port 8000
```

Or with [uv](https://docs.astral.sh/uv/):

```bash
uv sync --group dev
uv run uvicorn api.main:app --factory --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000/. http://127.0.0.1:8000/?demo=1 replays a recorded scan and
needs no key. Live scans need `MODEL_API_KEY` in a `.env` file next to this README or in the
environment:

```
MODEL_API_KEY=your-meta-model-api-key
```

Optional: `GITHUB_TOKEN` raises GitHub's rate limit for account and repo checks. Keep
`TRUSTMAP_ALLOW_LOCAL_SCAN` unset or `0` on any public server.

Repositories are shallow-cloned with `git`. Without a working `git` (for example a Mac
without developer tools) the scanner downloads GitHub's archive of the default branch
instead.

## Tests

```bash
python3 -m pip install pytest pytest-asyncio
python3 -m pytest -q -m 'not slow'
```

The tests use a scripted model client and stubbed lookups, so they make no network or
model calls. `-m slow` runs the live-network lookup tests.

## The demo recording

`api/demo_scan.json` is a scan of `tests/fixtures/demo_repo`, recorded through the real
API with stubbed lookups and a scripted stand-in for Muse Spark; the page says so while
it plays. To re-record it:

```bash
python3 scripts/record_demo.py          # offline, free
python3 scripts/record_demo.py --live   # real lookups and Muse Spark; needs MODEL_API_KEY
```

A `--live` recording is labelled as a live scan on the page.

## Deploy

A scan runs as a background task in the process that accepted it, streams Server-Sent
Events while it works, and caches lookups in SQLite. It runs best on a host that keeps a
process alive (Render, Fly, Railway, a VM), and it also runs on Vercel with the
trade-offs below.

### Vercel

`vercel.json` pins the FastAPI preset and `pyproject.toml` points it at `index.py`
(`[tool.vercel] entrypoint = "index:app"`). The page itself lives in `public/`, which
Vercel serves from its CDN; a `.js` file under `api/` would be built as its own function
and break the deploy.

1. Push this repository to GitHub.
2. In Vercel: **Add New → Project**, import the repository, keep the detected settings.
3. Under **Environment Variables** add `MODEL_API_KEY` (and `GITHUB_TOKEN` if you have
   one), then **Deploy**. Live scans stay paused by default on Vercel; add
   `TRUSTMAP_ENABLE_LIVE_SCANS=1` only when you intend to let site visitors spend from
   that key.

What changes on Vercel, all handled in code when the `VERCEL` variable is present:

- The page starts and follows a scan in one request (`POST /api/scan/stream`), because
  the next request can reach a different instance. Share links are turned off there.
- A request may run for five minutes on the free plan. Classify groups repeated
  references, sends eight batches to Muse Spark at a time, and reports progress. It
  stops starting model work after 105 seconds by default; unfinished groups get
  explicit low-confidence fallback labels. Clean targets skip model ranking. The agent
  stage stops starting new work 170 seconds into a scan
  (`TRUSTMAP_AGENT_DEADLINE_S`) and ranking stops starting model calls at 250 seconds
  (`TRUSTMAP_RANK_DEADLINE_S`), so the scan ends before the cutoff; skipped targets keep
  their lookup facts and the code severity rules.
- Only `/tmp` is writable, so the cache lives in `/tmp/trustmap.db` and starts empty on
  each new instance. The daily spend cap and per-IP limit live there too, so they count
  per instance. Live scans are opt-in on Vercel because this is not a shared spending
  ledger.

### Render (the checked-in blueprint)

`render.yaml` describes the whole service: Docker runtime, free plan, and a health check
on `/api/health`.

1. Push this repository to GitHub.
2. In Render: **New → Blueprint**, pick the repository, apply `render.yaml`.
3. Set the two secrets it leaves blank: `MODEL_API_KEY` and `GITHUB_TOKEN`.

Everything else (the spend and rate caps, `TRUSTMAP_TRUSTED_PROXY_HOPS=1`, the cache
path) is already in the blueprint. Check the build locally first with:

```bash
docker build -t trustline . && docker run --rm -p 8000:8000 trustline
```

### What does not survive a restart

Jobs live in process memory. `GET /api/scan/{id}` and the `?scan=<id>` share link work
until the process restarts; after that the id is gone (404) and the scan has to be run
again. The demo is a checked-in recording and always works.

On the free plan there are two more consequences, because a free web service cannot
mount a disk and sleeps after 15 minutes without traffic:

- The SQLite cache at `TRUSTMAP_CACHE_DB` holds both network lookups and model
  responses, so losing it means a repeat scan of the same target pays full price
  again rather than being nearly free.
- A sleeping service takes about a minute to answer the first request. Open the site a
  minute before you demo it.

For a cache that survives, set `plan: starter` in `render.yaml` and add a disk back:

```yaml
    disk:
      name: trustline-data
      mountPath: /var/data
      sizeGB: 1
```

## API

See [docs/api.md](docs/api.md) for the scan API and every event the page listens to.
