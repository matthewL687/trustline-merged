from __future__ import annotations

import os
import sqlite3
import time
from pathlib import Path

from scanner.config import (
    DAILY_CAP_USD,
    IP_SCANS_PER_HOUR,
    MAX_CONCURRENT_SCANS,
    SCAN_COST_CAP_USD,
    TRUSTED_PROXY_HOPS,
)

DAILY_LIMIT_MSG = "Daily limit reached, try the demo"
HOURLY_LIMIT_MSG = "Hourly limit reached, try the demo"
BUSY_MSG = "Busy, try again in a minute"
HOUR_S = 3600


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    return float(raw)


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    return int(raw)


def trusted_proxy_hops() -> int:
    raw = os.environ.get("TRUSTMAP_TRUSTED_PROXY_HOPS", "").strip()
    if raw:
        return max(0, int(raw))
    if os.environ.get("RENDER", "").strip() or os.environ.get("VERCEL", "").strip():
        return 1
    return TRUSTED_PROXY_HOPS


def client_ip(request, hops: int | None = None) -> str:
    peer = "unknown"
    if request.client is not None and request.client.host:
        peer = request.client.host
    hops = trusted_proxy_hops() if hops is None else hops
    if hops <= 0:
        return peer
    forwarded = request.headers.get("x-forwarded-for")
    if not forwarded:
        return peer
    parts = [part.strip() for part in forwarded.split(",") if part.strip()]
    if hops > len(parts):
        return peer
    return parts[-hops]


class LimitsStore:
    def __init__(
        self,
        path: str | Path,
        *,
        daily_cap: float | None = None,
        ip_per_hour: int | None = None,
        max_concurrent: int | None = None,
        scan_reserve: float | None = None,
        trusted_hops: int | None = None,
        now=None,
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.daily_cap = (
            daily_cap
            if daily_cap is not None
            else _env_float("TRUSTMAP_DAILY_CAP_USD", DAILY_CAP_USD)
        )
        self.ip_per_hour = (
            ip_per_hour
            if ip_per_hour is not None
            else _env_int("TRUSTMAP_IP_SCANS_PER_HOUR", IP_SCANS_PER_HOUR)
        )
        self.max_concurrent = (
            max_concurrent
            if max_concurrent is not None
            else _env_int("TRUSTMAP_MAX_CONCURRENT_SCANS", MAX_CONCURRENT_SCANS)
        )
        self.scan_reserve = (
            scan_reserve
            if scan_reserve is not None
            else _env_float("SCAN_COST_CAP_USD", SCAN_COST_CAP_USD)
        )
        self.trusted_hops = (
            trusted_hops if trusted_hops is not None else trusted_proxy_hops()
        )
        self._now = now or time.time
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS spend_ledger (
                    day TEXT PRIMARY KEY,
                    usd REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS spend_reserve (
                    scan_id TEXT PRIMARY KEY,
                    day TEXT NOT NULL,
                    usd REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS scan_starts (
                    ip TEXT NOT NULL,
                    ts REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS scan_starts_ip_ts ON scan_starts (ip, ts);
                CREATE TABLE IF NOT EXISTS inflight (
                    scan_id TEXT PRIMARY KEY
                );
                """
            )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.isolation_level = None
        return conn

    def day_key(self) -> str:
        return time.strftime("%Y-%m-%d", time.gmtime(self._now()))

    def spent_today(self) -> float:
        day = self.day_key()
        with self._connect() as conn:
            committed = conn.execute(
                "SELECT usd FROM spend_ledger WHERE day = ?",
                (day,),
            ).fetchone()
            reserved = conn.execute(
                "SELECT COALESCE(SUM(usd), 0) FROM spend_reserve WHERE day = ?",
                (day,),
            ).fetchone()
        return float(committed[0] if committed else 0) + float(reserved[0])

    def starts_last_hour(self, ip: str) -> int:
        cutoff = self._now() - HOUR_S
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM scan_starts WHERE ip = ? AND ts >= ?",
                (ip, cutoff),
            ).fetchone()
        return int(row[0]) if row else 0

    def inflight_count(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) FROM inflight").fetchone()
        return int(row[0]) if row else 0

    def check(self, ip: str, reserve_usd: float | None = None) -> str | None:
        reserve_usd = self.scan_reserve if reserve_usd is None else reserve_usd
        if self.inflight_count() >= self.max_concurrent:
            return BUSY_MSG
        if reserve_usd > 0 and self.spent_today() + reserve_usd > self.daily_cap:
            return DAILY_LIMIT_MSG
        if self.starts_last_hour(ip) >= self.ip_per_hour:
            return HOURLY_LIMIT_MSG
        return None

    def admit(self, ip: str, scan_id: str, reserve_usd: float | None = None) -> str | None:
        reserve_usd = self.scan_reserve if reserve_usd is None else reserve_usd
        day = self.day_key()
        cutoff = self._now() - HOUR_S
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            inflight = conn.execute("SELECT COUNT(*) FROM inflight").fetchone()[0]
            if inflight >= self.max_concurrent:
                conn.execute("ROLLBACK")
                return BUSY_MSG
            committed = conn.execute(
                "SELECT usd FROM spend_ledger WHERE day = ?",
                (day,),
            ).fetchone()
            reserved = conn.execute(
                "SELECT COALESCE(SUM(usd), 0) FROM spend_reserve WHERE day = ?",
                (day,),
            ).fetchone()
            spent = float(committed[0] if committed else 0) + float(reserved[0])
            if reserve_usd > 0 and spent + reserve_usd > self.daily_cap:
                conn.execute("ROLLBACK")
                return DAILY_LIMIT_MSG
            starts = conn.execute(
                "SELECT COUNT(*) FROM scan_starts WHERE ip = ? AND ts >= ?",
                (ip, cutoff),
            ).fetchone()[0]
            if starts >= self.ip_per_hour:
                conn.execute("ROLLBACK")
                return HOURLY_LIMIT_MSG
            conn.execute("INSERT INTO inflight (scan_id) VALUES (?)", (scan_id,))
            conn.execute(
                "INSERT INTO spend_reserve (scan_id, day, usd) VALUES (?, ?, ?)",
                (scan_id, day, reserve_usd),
            )
            conn.execute(
                "INSERT INTO scan_starts (ip, ts) VALUES (?, ?)",
                (ip, self._now()),
            )
            conn.execute("COMMIT")
        return None

    def record_start(self, ip: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO scan_starts (ip, ts) VALUES (?, ?)",
                (ip, self._now()),
            )

    def add_spend(self, usd: float) -> None:
        if usd == 0:
            return
        day = self.day_key()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO spend_ledger (day, usd) VALUES (?, ?)
                ON CONFLICT(day) DO UPDATE SET usd = usd + excluded.usd
                """,
                (day, usd),
            )

    def reconcile(self, scan_id: str, actual_usd: float) -> None:
        day = self.day_key()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM spend_reserve WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM inflight WHERE scan_id = ?", (scan_id,))
            if actual_usd > 0:
                conn.execute(
                    """
                    INSERT INTO spend_ledger (day, usd) VALUES (?, ?)
                    ON CONFLICT(day) DO UPDATE SET usd = usd + excluded.usd
                    """,
                    (day, actual_usd),
                )
            conn.execute("COMMIT")
