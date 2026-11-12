"""FastAPI login service.

Threading / disconnect guarantees
---------------------------------
The login endpoint is a *synchronous* ``def``. Starlette runs sync endpoints
in a worker thread with no ``await`` point between slot acquisition and
settlement, so an HTTP client disconnecting mid-request cannot cancel the
handler: the argon2 verification always runs and the slot is always settled
(released, error counted or session issued) before anything is sent back.

No global lock serializes verifications; worker threads run argon2 fully in
parallel and coordinate only through short SQLite write transactions.

Time base
---------
The 60-second error window runs on the host monotonic clock (see
``app/db.py``): wall-clock calibration (NTP steps, manual date changes)
cannot lift a limit early or extend it, both web processes share the same
time base, and windows keep elapsing across process/container restarts
within one host boot. Admission and settlement are timestamped *after* the
SQLite write lock is acquired, never while the request is still waiting for
the lock. Wall-clock time (with the demo calibration offset applied) is
used only for session expiry and display.
"""
from __future__ import annotations

import logging
import math
import time
from pathlib import Path
from typing import Any

import anyio
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from . import db
from .config import settings
from .security import (
    compare_tokens,
    hash_password,
    new_session_token,
    verify_password,
)

COOKIE_NAME = "session"

logger = logging.getLogger("login_guard")

# A throwaway hash used to give unknown-username requests comparable timing
# to real ones (user-enumeration hardening). Generated once at import time.
_DUMMY_HASH = hash_password("not-a-real-password")


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    delay: float = Field(default=0.0, ge=0.0, le=60.0)


class ClockBody(BaseModel):
    # Simulated wall-clock calibration offset, ±7 days.
    offset_seconds: float = Field(ge=-7 * 24 * 3600, le=7 * 24 * 3600)


class HoldLockBody(BaseModel):
    # Keep well under the 30s SQLite busy_timeout so waiting writers block
    # instead of erroring.
    seconds: float = Field(ge=0.1, le=20.0)


app = FastAPI(title="Guessing-budget login demo", version="1.0.0")


@app.on_event("startup")
def _startup() -> None:
    # Allow enough worker threads for overlapping delayed verifications.
    anyio.to_thread.current_default_thread_limiter().total_tokens = 64
    db.init_db()


@app.middleware("http")
async def _add_process_header(request: Request, call_next):
    # Monotonic clock for durations: wall-clock calibration demos must not
    # produce negative or absurd process times.
    started = time.monotonic()
    try:
        response = await call_next(request)
    except Exception:
        raise
    response.headers["X-Served-By"] = settings.process_name
    response.headers["X-Process-Time-ms"] = (
        f"{(time.monotonic() - started) * 1000:.1f}"
    )
    return response


def _stats_payload() -> dict[str, Any]:
    return {
        # Service wall clock (demo offset applied) and the monotonic time
        # base used for the error window, exposed so the page can show that
        # calibration moves only the former.
        "wall_now": db.wall_now(),
        "mono_now": db.mono_now(),
        "clock_offset_seconds": db.get_clock_offset(),
        "window_seconds": settings.error_window_seconds,
        "max_slots": settings.max_slots,
        "accounts": db.account_stats(),
    }


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=settings.session_ttl_seconds,
        httponly=True,
        samesite="lax",
        secure=False,  # plain HTTP on localhost; enable behind TLS
        path="/",
    )


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    html_path = Path(__file__).with_name("static").joinpath("index.html")
    return HTMLResponse(html_path.read_text(encoding="utf-8"))


@app.get("/api/stats")
def stats() -> JSONResponse:
    return JSONResponse(_stats_payload())


@app.get("/api/me")
def me(request: Request) -> JSONResponse:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="not authenticated")
    row = db.get_session(token)
    if row is None or not compare_tokens(row["token"], token):
        raise HTTPException(status_code=401, detail="session invalid or expired")
    return JSONResponse(
        {
            "authenticated": True,
            "username": row["username"],
            "account_id": row["account_id"],
            "expires_at": row["expires_at"],
            "served_by": settings.process_name,
        }
    )


@app.post("/api/logout")
def logout(request: Request) -> Response:
    token = request.cookies.get(COOKIE_NAME)
    if token:
        db.delete_session(token)
    response = Response(status_code=204)
    response.delete_cookie(COOKIE_NAME, path="/")
    return response


@app.post("/api/login")
def login(body: LoginBody) -> JSONResponse:
    delay = min(max(body.delay, 0.0), float(settings.max_delay_seconds))

    conn = db.connect()
    try:
        account = db.get_account(conn, body.username.strip())
    finally:
        conn.close()

    if account is None:
        # Spend an argon2 verification anyway so timing does not reveal
        # whether the username exists. No slot exists for unknown users.
        verify_password(_DUMMY_HASH, body.password)
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_credentials", "message": "用户名或密码错误"},
        )

    account_id = account["id"]

    # --- Atomic reservation: windowed errors + in-flight vs. the limit ---
    # The admission timestamp is taken inside, after the SQLite write lock
    # is acquired — never here, before the (possibly long) lock wait.
    slot_id = db.acquire_slot(account_id)
    if slot_id is None:
        # Full: reject immediately and do NOT hash the password.
        retry_after = math.ceil(db.next_retry_after(account_id))
        raise HTTPException(
            status_code=429,
            headers={"Retry-After": str(retry_after)},
            detail={
                "error": "rate_limited",
                "message": "该账号错误次数/在途核验已达上限，请稍后再试",
                "retry_after": retry_after,
                "account": next(
                    (a for a in db.account_stats() if a["account_id"] == account_id),
                    None,
                ),
            },
        )

    # --- Verification runs with NO database write lock held and NO global ---
    # --- lock; other requests/processes verify in parallel.              ---
    ok = False
    try:
        if delay:
            time.sleep(delay)  # demo knob: interleave completion ordering
        ok = verify_password(account["password_hash"], body.password)
    except Exception:
        ok = False

    # --- Settlement always happens, even if the client has disconnected ---
    if ok:
        token = new_session_token()
        expires_at = db.wall_now() + settings.session_ttl_seconds
        # Session insert + slot release + error reset commit together.
        settled = db.settle(
            slot_id,
            account_id,
            success=True,
            session_token=token,
            session_expires_at=expires_at,
        )
        if not settled:
            # The slot was reclaimed by a startup cleanup while we were
            # verifying; no session can be issued for a slot we no longer own.
            logger.warning("slot %s reclaimed before successful settlement", slot_id)
            return JSONResponse(
                status_code=503,
                content={
                    "ok": False,
                    "error": "slot_reclaimed",
                    "message": "服务刚完成重启，请重试登录",
                    "served_by": settings.process_name,
                    "stats": _stats_payload(),
                },
            )
        response = JSONResponse(
            {
                "ok": True,
                "username": account["username"],
                "message": "登录成功",
                "served_by": settings.process_name,
                "stats": _stats_payload(),
            }
        )
        _set_session_cookie(response, token)
        return response

    settled = db.settle(slot_id, account_id, success=False)
    if not settled:
        # Slot was already reclaimed (crash recovery); the verification
        # still ran to completion, but its error must not be double-counted.
        logger.warning("slot %s reclaimed before failure settlement", slot_id)
    return JSONResponse(
        status_code=401,
        content={
            "ok": False,
            "error": "invalid_credentials",
            "message": "用户名或密码错误",
            "served_by": settings.process_name,
            "stats": _stats_payload(),
        },
    )


# --- Fault-injection demos ---------------------------------------------------
# These endpoints let the web page demonstrate clock calibration (without
# touching the host clock), SQLite lock waiting and restart semantics. They
# change no security invariant: the error window always runs on the host
# monotonic clock with post-lock timestamps.


def _require_demo_api() -> None:
    if not settings.demo_api_enabled:
        raise HTTPException(status_code=404, detail="demo API disabled")


@app.post("/api/demo/clock")
def demo_clock(body: ClockBody) -> JSONResponse:
    """Simulate an operator calibrating the server wall clock.

    The offset is stored in the shared database, so both web processes see
    the same calibrated wall clock. The error window is unaffected: it runs
    on the monotonic clock.
    """
    _require_demo_api()
    db.set_clock_offset(body.offset_seconds)
    return JSONResponse(
        {
            "ok": True,
            "clock_offset_seconds": db.get_clock_offset(),
            "wall_now": db.wall_now(),
            "mono_now": db.mono_now(),
            "served_by": settings.process_name,
        }
    )


@app.post("/api/demo/hold-lock")
def demo_hold_lock(body: HoldLockBody) -> JSONResponse:
    """Hold the SQLite write lock for a while (readers keep working)."""
    _require_demo_api()
    held = db.hold_write_lock(body.seconds)
    return JSONResponse(
        {
            "ok": True,
            "held_seconds": round(held, 3),
            "served_by": settings.process_name,
        }
    )


@app.post("/api/demo/restart")
def demo_restart() -> JSONResponse:
    """Simulate a process/container restart within the same host boot.

    Runs exactly the startup reconciliation: stale in-flight slots are
    reclaimed, completed error windows are kept and keep elapsing on the
    monotonic clock — not cleared, not refilled.
    """
    _require_demo_api()
    db.startup_cleanup()
    return JSONResponse(
        {
            "ok": True,
            "message": "已执行启动清理：在途占位清空，窗口内错误保留并继续流逝",
            "served_by": settings.process_name,
            "stats": _stats_payload(),
        }
    )
