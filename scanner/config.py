"""Scanner settings. Model keys are read in later phases; do not load .env here."""

import os

# Registrable domains we never flag. Bucket matches on Amazon/Google hosts are kept.
ALLOWLIST_DOMAINS: frozenset[str] = frozenset(
    {
        "github.com",
        "githubusercontent.com",
        "googleapis.com",
        "amazonaws.com",
        "npmjs.com",
        "pypi.org",
        "w3.org",
        "schema.org",
        "localhost",
        # License text, not runtime trust
        "opensource.org",
        "spdx.org",
        "apache.org",
        "gnu.org",
        "creativecommons.org",
        # XML / JSON schema namespaces
        "xmlsoap.org",
        "xml.org",
        "json-schema.org",
    }
)

SKIP_DIR_NAMES: frozenset[str] = frozenset(
    {".git", "node_modules", "vendor", "dist", "build"}
)
SKIP_FILE_NAMES: frozenset[str] = frozenset(
    {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "pnpm-lock.yml",
        "bun.lock",
        "bun.lockb",
        "poetry.lock",
        "pipfile.lock",
        "cargo.lock",
        "composer.lock",
        "gemfile.lock",
        "go.sum",
        "uv.lock",
    }
)
RESERVED_TLDS: frozenset[str] = frozenset(
    {"invalid", "test", "example", "localhost", "local"}
)
RFC2606_DOMAINS: frozenset[str] = frozenset(
    {"example.com", "example.net", "example.org"}
)

SKIP_NAME_SUFFIXES: tuple[str, ...] = (
    ".min.js",
    ".min.mjs",
    ".min.cjs",
    ".min.css",
    ".js.map",
    ".css.map",
    ".min.js.map",
    ".min.css.map",
    ".map",
)
MAX_FILE_BYTES = 1_000_000
MAX_SCAN_FILES = 5_000
MAX_SCAN_BYTES = 50 * 1024 * 1024
CONTEXT_LINES = 10
GITHUB_CLONE_TIMEOUT_S = 60
HTTP_TIMEOUT_S = 10.0
WEBSITE_PAGE_MAX_BYTES = 5 * 1024 * 1024
WEBSITE_JS_MAX_BYTES = 2 * 1024 * 1024
WEBSITE_MAX_JS_FILES = 10
CRTSH_TIMEOUT_S = 15.0
DNS_TIMEOUT_S = 5.0
CACHE_TTL_S = 24 * 60 * 60
RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
RDAP_FALLBACK_BASE = "https://rdap.org/"

META_BASE_URL = "https://api.meta.ai/v1"
CLASSIFY_MODEL = "muse-spark-1.3"
AGENT_MODEL = "muse-spark-1.3"
RANK_MODEL = "muse-spark-1.3"
CLASSIFY_REASONING_EFFORT = "low"
AGENT_REASONING_EFFORT = "low"
RANK_REASONING_EFFORT = "medium"
LLM_MAX_RETRIES = 2
CLASSIFY_BATCH_SIZE = 80
# batches in flight at once; rank already runs this many model calls in parallel
CLASSIFY_CONCURRENCY = 8
MAX_AGENT_TOOL_CALLS = 3
MAX_AGENT_TARGETS = 12
MAX_INVESTIGATION_CONCURRENCY = 4
PRECHECK_CONCURRENCY = 16
RANK_CONCURRENCY = 8
SCAN_COST_CAP_USD = 1.00
DAILY_CAP_USD = 10.0
IP_SCANS_PER_HOUR = 20
MAX_CONCURRENT_SCANS = 3
TRUSTED_PROXY_HOPS = 0
DEMO_EVENT_GAP_MS = 150
EVAL_SCAN_COST_CAP_USD = 3.00
EVAL_TARGET_CAP = 25
EVAL_SAMPLE_SEED = 42
EVAL_LOOKUP_CONCURRENCY = 10
EXPIRY_INVESTIGATE_DAYS = 90
# USD per million tokens
MODEL_PRICES: dict[str, dict[str, float]] = {
    "muse-spark-1.3": {"input": 1.25, "output": 4.25},
}


# Serverless hosts (Vercel) cut a request off after five minutes on the free plan,
# so the agent stage stops starting new work this long after a scan begins and
# rank still has time to finish.
SERVERLESS_AGENT_DEADLINE_S = 170.0
# ...and rank stops starting model calls here, so the last ones end before the cutoff.
SERVERLESS_RANK_DEADLINE_S = 250.0
# Keep scans on long-lived hosts bounded too. These deadlines are measured from
# scan start, leaving time for report finalization inside a 10-minute target.
DEFAULT_AGENT_DEADLINE_S = 240.0
DEFAULT_RANK_DEADLINE_S = 480.0
MODEL_REQUEST_TIMEOUT_S = 30.0
SERVERLESS_CLASSIFY_DEADLINE_S = 105.0


def on_serverless() -> bool:
    """Vercel and similar hosts: one request per scan, a time limit, only /tmp is writable."""
    if os.environ.get("VERCEL", "").strip():
        return True
    return os.environ.get("TRUSTMAP_SERVERLESS", "").strip().lower() in {"1", "true", "yes"}
