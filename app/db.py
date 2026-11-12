"""SQLite-backed shared state for the login service.

Concurrency model
-----------------
Two (or more) uvicorn worker processes share one SQLite database file.

* The database runs in WAL mode, so a reader never blocks a writer and two
  readers never block each other; writers still serialize through the single
  WAL writer, which is exactly the serialization point we need for the
  per-account slot accounting.
* Every state-changing operation opens a *short* ``BEGIN IMMEDIATE``
  transaction. The argon2 hash itself is computed by the caller **outside**
  any transaction (see :mod:`app.security`), so CPU-bound password hashing
  never holds the SQLite write lock.
* There is deliberately no in-process global lock around verification:
  cross-process coordination happens entirely inside SQLite transactions.
* Each request uses its own connection; no connection is ever shared across
  threads.

Time base
---------
All error-window and in-flight timestamps use the **host monotonic clock**
(``time.monotonic()``), not the wall clock:

* The 60-second error window measures *actually elapsed* time. NTP/manual
  wall-clock calibration — forward or backward jumps — cannot lift a
  just-triggered limit early or extend it into an extra hour of lockout.
* ``CLOCK_MONOTONIC`` is identical in every process and container on the
  same host, so both web processes share one time base, and a process or
  container restart within the same host boot keeps existing error windows
  elapsing — they are neither cleared nor refilled.
* Admission and error settlement take their timestamp **after** the SQLite
  write lock has been acquired, so a request that waited on the lock never
  judges an already-expired window as still active, and a just-settled
  error always gets its full window starting at the real settlement
  instant.

Wall-clock time is still used where wall time is the natural semantic —
session expiry and display — via :func:`wall_now`, which applies the demo
clock-calibration offset stored in the shared ``meta`` table.
"""
from __future__ import annotations

import os
import sqlite3
import time
import uuid
from contextlib import contextmanager
from typing import Iterator, Optional

from .config import settings
from .security import hash_password

# Demo accounts. Only the argon2 hashes are ever persisted; the plaintext
# passwords live here solely so the one-time seed can be generated and are
# shown on the demo page for convenience.
SEED_ACCOUNTS = (
    ("alice", "alice-pass-2026"),
    ("bob", "bob-pass-2026"),
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    id            INTEGER PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    REAL NOT NULL
);

-- created_at is a *monotonic* timestamp (seconds on the host monotonic
-- clock), comparable across processes and restarts within one host boot.
CREATE TABLE IF NOT EXISTS login_errors (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL REFERENCES accounts(id),
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_errors_account_time
    ON login_errors(account_id, created_at);

-- acquired_at is a monotonic timestamp as well.
CREATE TABLE IF NOT EXISTS login_inflight (
    slot_id    TEXT PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id),
    acquired_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_inflight_account
    ON login_inflight(account_id);

-- Sessions use wall-clock time (service wall clock incl. the demo offset).
CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id),
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

# Generation marker for the timestamp semantics stored in login_errors /
# login_inflight. Rows written by older builds (wall-clock epochs) are not
# comparable to monotonic readings and are discarded at startup.
TIME_BASE = "monotonic-v1"


def connect() -> sqlite3.Connection:
    """Open a brand-new connection with concurrency-friendly settings."""
    os.makedirs(os.path.dirname(settings.db_path), exist_ok=True)
    conn = sqlite3.connect(
        settings.db_path,
        timeout=30.0,            # wait on the write lock instead of erroring
        isolation_level=None,    # explicit BEGIN/COMMIT, no implicit txns
        check_same_thread=False,  # connections are per-call, never shared
    )
    conn.row_factory = sqlite3.Row
    # Persistent WAL/journal settings are stored in the DB file itself;
    # re-issuing them on every connection is cheap and makes a fresh file
    # self-initializing even before init_db() runs.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def immediate_tx(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Acquire the WAL write lock up-front and commit/roll back as a unit.

    ``conn.execute("BEGIN IMMEDIATE")`` returns only after the write lock is
    held. Callers that need the decision timestamp (admission, settlement)
    must read ``time.monotonic()`` as the *first* statement inside the
    ``with`` block, so the value reflects the post-lock instant rather than
    the moment the request started waiting for the lock.
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
        # An inner block may have rolled back explicitly to bail out cleanly.
        if conn.in_transaction:
            conn.execute("COMMIT")
    except Exception:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise


def mono_now() -> float:
    """Host monotonic clock: the single time base for the error window."""
    return time.monotonic()


# --- Service wall clock (demo clock-calibration offset) --------------------
#
# The offset simulates an operator calibrating the server clock (NTP step,
# manual date change) without touching the host time. It is stored in the
# shared database so both web processes observe the same calibrated wall
# clock. A short in-process cache avoids a database round-trip per call;
# after a change the other process picks it up within the TTL.

_OFFSET_CACHE_TTL_SECONDS = 0.5
_offset_cache = {"value": 0.0, "expires_mono": -1.0}


def get_clock_offset() -> float:
    """Current demo wall-clock offset in seconds (shared across processes)."""
    now = time.monotonic()
    if now < _offset_cache["expires_mono"]:
        return _offset_cache["value"]
    conn = connect()
    try:
        try:
            row = conn.execute(
                "SELECT value FROM meta WHERE key = 'clock_offset'"
            ).fetchone()
        except sqlite3.OperationalError:
            row = None  # meta table not created yet (very early startup)
    finally:
        conn.close()
    value = float(row["value"]) if row is not None else 0.0
    _offset_cache["value"] = value
    _offset_cache["expires_mono"] = now + _OFFSET_CACHE_TTL_SECONDS
    return value


def set_clock_offset(offset_seconds: float) -> None:
    """Persist a new demo wall-clock offset (visible to both processes)."""
    value = float(offset_seconds)
    conn = connect()
    try:
        with immediate_tx(conn):
            conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES ('clock_offset', ?)",
                (repr(value),),
            )
    finally:
        conn.close()
    _offset_cache["value"] = value
    _offset_cache["expires_mono"] = time.monotonic() + _OFFSET_CACHE_TTL_SECONDS


def wall_now() -> float:
    """Service wall clock: host wall time plus the demo calibration offset."""
    return time.time() + get_clock_offset()


def _read_boot_id() -> Optional[str]:
    """Kernel boot id, or None on platforms without /proc."""
    try:
        with open("/proc/sys/kernel/random/boot_id", "r", encoding="ascii") as fh:
            return fh.read().strip() or None
    except OSError:
        return None


def _startup_cleanup_locked(conn: sqlite3.Connection) -> None:
    """Reconcile persisted state for a (re)started process. Lock must be held.

    * In-flight slots belong to verifiers that died with the old process:
      reclaim them all.
    * Completed errors are kept: their windows run on the host monotonic
      clock and keep elapsing across process/container restarts within the
      same host boot — never cleared, never refilled.
    * Rows are dropped only when their timestamps are no longer comparable:
      a different timestamp generation (legacy wall-clock rows) or a
      different host boot (monotonic readings are per-boot).
    """
    row = conn.execute(
        "SELECT value FROM meta WHERE key = 'time_base'"
    ).fetchone()
    if row is None or row["value"] != TIME_BASE:
        conn.execute("DELETE FROM login_errors")
        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('time_base', ?)",
            (TIME_BASE,),
        )
    boot_id = _read_boot_id()
    if boot_id is not None:
        row = conn.execute(
            "SELECT value FROM meta WHERE key = 'boot_id'"
        ).fetchone()
        if row is not None and row["value"] != boot_id:
            # The host rebooted: monotonic timestamps from the previous boot
            # belong to a different clock epoch and must not be compared
            # with readings taken now.
            conn.execute("DELETE FROM login_errors")
        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('boot_id', ?)",
            (boot_id,),
        )
    conn.execute("DELETE FROM login_inflight")


def init_db() -> None:
    """Create the schema, seed demo accounts and run startup reconciliation.

    Safe to run concurrently from several processes: DDL uses
    ``IF NOT EXISTS`` and account seeding uses ``INSERT OR IGNORE``.
    """
    conn = connect()
    try:
        conn.executescript(SCHEMA)
        with immediate_tx(conn):
            now_wall = wall_now()
            for username, password in SEED_ACCOUNTS:
                row = conn.execute(
                    "SELECT id FROM accounts WHERE username = ?", (username,)
                ).fetchone()
                if row is None:
                    # Hashing happens before the write; it is not performed
                    # while holding any lock beyond this short seed txn.
                    conn.execute(
                        "INSERT OR IGNORE INTO accounts"
                        " (username, password_hash, created_at)"
                        " VALUES (?, ?, ?)",
                        (username, hash_password(password), now_wall),
                    )
            _startup_cleanup_locked(conn)
    finally:
        conn.close()


def startup_cleanup() -> None:
    """Re-run the startup reconciliation (process/container restart semantics).

    Used by the restart demo endpoint; identical to what ``init_db`` does
    with existing state on a real restart: in-flight slots are reclaimed,
    completed error windows keep elapsing on the monotonic clock.
    """
    conn = connect()
    try:
        with immediate_tx(conn):
            _startup_cleanup_locked(conn)
    finally:
        conn.close()


def hold_write_lock(seconds: float) -> float:
    """Demo helper: hold the SQLite write lock for ``seconds``, then release.

    Readers (stats) are unaffected in WAL mode; writers (admission,
    settlement) wait and then act on a *post-lock* timestamp. Returns the
    actually held duration.
    """
    seconds = max(0.0, min(float(seconds), 20.0))
    conn = connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        started = time.monotonic()
        try:
            time.sleep(seconds)
            conn.execute("COMMIT")
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        return time.monotonic() - started
    finally:
        conn.close()


def get_account(conn: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT id, username, password_hash FROM accounts WHERE username = ?",
        (username,),
    ).fetchone()


def acquire_slot(account_id: int) -> Optional[str]:
    """Atomically take one verification slot for an account.

    Counts *completed* errors inside the rolling window plus *in-flight*
    verifications. When the account is at capacity the function returns
    ``None`` without inserting anything (caller returns HTTP 429 and must
    not hash the password).

    The admission timestamp is taken immediately after the write lock is
    acquired, so a request that waited on the lock judges the window as of
    the decision instant — errors that expired during the wait are already
    gone, never "expired but still rejected".
    """
    slot_id = uuid.uuid4().hex
    conn = connect()
    try:
        with immediate_tx(conn):
            # First statement inside the lock: the admission instant.
            now = mono_now()
            cutoff = now - settings.error_window_seconds
            # An error occupies its slot for exactly one full window:
            # at elapsed >= window it is expired (strict inequality).
            conn.execute(
                "DELETE FROM login_errors WHERE created_at <= ?", (cutoff,)
            )
            errors = conn.execute(
                "SELECT COUNT(*) AS c FROM login_errors WHERE account_id = ?",
                (account_id,),
            ).fetchone()["c"]
            inflight = conn.execute(
                "SELECT COUNT(*) AS c FROM login_inflight WHERE account_id = ?",
                (account_id,),
            ).fetchone()["c"]
            if errors + inflight >= settings.max_slots:
                return None
            conn.execute(
                "INSERT INTO login_inflight (slot_id, account_id, acquired_at)"
                " VALUES (?, ?, ?)",
                (slot_id, account_id, now),
            )
            return slot_id
    finally:
        conn.close()


def settle(
    slot_id: str,
    account_id: int,
    success: bool,
    session_token: Optional[str] = None,
    session_expires_at: Optional[float] = None,
) -> bool:
    """Book a finished verification and, on success, issue the session.

    The slot release, the error record (or error-window reset) and the
    session row are written in one transaction, so settlement and session
    issuance commit together or not at all.

    The settlement timestamp is taken after the write lock is acquired, so
    a recorded error always gets its full window measured from the real
    settlement instant — lock waiting can never make a just-settled error
    already (partially) expired.

    On success the currently completed errors of the account are cleared.
    Other in-flight attempts are untouched: if they fail when they finish,
    their failures are still recorded and start a fresh window.

    Returns ``True`` when the slot was settled normally, ``False`` when the
    slot no longer existed (e.g. a startup cleanup after a crash reclaimed
    it while the verifier was still finishing). A missing slot means the
    accounting was already reconciled, so the caller must not treat this as
    a hard failure.
    """
    conn = connect()
    try:
        with immediate_tx(conn):
            # First statement inside the lock: the settlement instant.
            now = mono_now()
            cur = conn.execute(
                "DELETE FROM login_inflight WHERE slot_id = ?", (slot_id,)
            )
            if cur.rowcount == 0:
                # Slot was reclaimed out from under us (crash/startup
                # cleanup). Roll back the no-op delete and let the caller
                # decide; no error/session rows are written for a slot we no
                # longer own.
                conn.execute("ROLLBACK")
                return False
            if success:
                conn.execute(
                    "DELETE FROM login_errors WHERE account_id = ?", (account_id,)
                )
                if session_token is None or session_expires_at is None:
                    raise RuntimeError("successful settlement requires a session")
                conn.execute(
                    "INSERT INTO sessions"
                    " (token, account_id, created_at, expires_at)"
                    " VALUES (?, ?, ?, ?)",
                    (session_token, account_id, wall_now(), session_expires_at),
                )
            else:
                # Error is counted at *completion* (settlement) time, not
                # acquisition time.
                conn.execute(
                    "INSERT INTO login_errors (account_id, created_at)"
                    " VALUES (?, ?)",
                    (account_id, now),
                )
        return True
    finally:
        conn.close()


def get_session(token: str) -> Optional[sqlite3.Row]:
    now = wall_now()
    conn = connect()
    try:
        return conn.execute(
            "SELECT s.token, s.expires_at, a.id AS account_id, a.username"
            " FROM sessions s JOIN accounts a ON a.id = s.account_id"
            " WHERE s.token = ? AND s.expires_at > ?",
            (token, now),
        ).fetchone()
    finally:
        conn.close()


def delete_session(token: str) -> None:
    conn = connect()
    try:
        with immediate_tx(conn):
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
    finally:
        conn.close()


def account_stats() -> list[dict]:
    """Snapshot of every account: windowed errors, in-flight, slots left.

    Uses the same monotonic clock and the same window predicate as
    admission, so the numbers shown here agree with what ``acquire_slot``
    would decide right now, and an error disappears exactly when its full
    window has elapsed.
    """
    now = mono_now()
    cutoff = now - settings.error_window_seconds
    conn = connect()
    try:
        rows = conn.execute(
            """
            SELECT a.id, a.username,
                   (SELECT COUNT(*) FROM login_errors e
                     WHERE e.account_id = a.id AND e.created_at > ?) AS errors,
                   (SELECT MIN(e2.created_at) FROM login_errors e2
                     WHERE e2.account_id = a.id AND e2.created_at > ?)
                       AS oldest_error,
                   (SELECT COUNT(*) FROM login_inflight f
                     WHERE f.account_id = a.id) AS inflight
              FROM accounts a
             ORDER BY a.username
            """,
            (cutoff, cutoff),
        ).fetchall()
    finally:
        conn.close()
    out = []
    for row in rows:
        used = row["errors"] + row["inflight"]
        oldest = row["oldest_error"]
        expires_in = None
        if oldest is not None:
            expires_in = max(0.0, oldest + settings.error_window_seconds - now)
        out.append(
            {
                "account_id": row["id"],
                "username": row["username"],
                "window_errors": row["errors"],
                "inflight": row["inflight"],
                "used_slots": used,
                "remaining_slots": max(0, settings.max_slots - used),
                "max_slots": settings.max_slots,
                "window_seconds": settings.error_window_seconds,
                # Seconds until the oldest active error ages out; None when
                # no completed error occupies the window.
                "window_expires_in": (
                    round(expires_in, 1) if expires_in is not None else None
                ),
            }
        )
    return out


def next_retry_after(account_id: int) -> float:
    """Seconds until at least one occupied slot frees up (for Retry-After)."""
    now = mono_now()
    cutoff = now - settings.error_window_seconds
    conn = connect()
    try:
        oldest_error = conn.execute(
            "SELECT MIN(created_at) AS t FROM login_errors"
            " WHERE account_id = ? AND created_at > ?",
            (account_id, cutoff),
        ).fetchone()["t"]
        oldest_inflight = conn.execute(
            "SELECT MIN(acquired_at) AS t FROM login_inflight WHERE account_id = ?",
            (account_id,),
        ).fetchone()["t"]
    finally:
        conn.close()
    candidates = []
    if oldest_error is not None:
        candidates.append(oldest_error + settings.error_window_seconds - now)
    if oldest_inflight is not None:
        # In-flight work has no known deadline from SQL's perspective; the
        # caller's requested delay bounds it, but a safe answer is to wait
        # for the oldest error to age out. Fall back to one window if the
        # account is saturated purely by in-flight attempts.
        candidates.append(settings.error_window_seconds)
    return max(1.0, min(candidates) if candidates else 1.0)
