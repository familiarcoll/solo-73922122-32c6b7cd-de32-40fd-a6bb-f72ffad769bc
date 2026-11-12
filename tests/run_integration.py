"""End-to-end integration test for the login service.

Spins up TWO uvicorn processes sharing one SQLite file (same topology as the
docker-compose deployment) and verifies:

  1. basic login / session cookie / identity / logout
  2. per-account slot accounting across both processes
  3. atomic reservation: a 6th concurrent attempt gets an immediate 429
     (fast => no argon2 hashing, Retry-After header present)
  4. errors counted at completion time; correct password blocked at capacity
  5. rolling window expiry restores slots
  6. client disconnect does NOT release slots: verification still settles
  7. success clears completed errors; later in-flight failures still count
  8. restart keeps windowed errors and reclaims stale in-flight slots
  9. only password hashes are stored (no plaintext in the database)
 10. wall-clock calibration (±1h jumps) never lifts or extends the window
 11. admission is judged at the post-lock instant: errors that expire while
     a request waits on the SQLite write lock are correctly admitted
 12. settlement is booked at the post-lock instant: an error settled after
     a lock wait gets its full window from the real settlement time
 13. restart within one host boot keeps the window elapsing (no reset, no
     refill) and expires errors at the original deadline
 14. demo endpoints: hold-lock, simulated restart, clock offset
 15. server logs contain no unhandled exceptions
"""
from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
# Unique per invocation: restricted sandboxes may forbid killing orphaned
# servers from an earlier crashed run, so never reuse ports/db paths.
_RUN_ID = os.environ.get("IT_RUN_ID", str(int(time.time() * 1000)))
DB_DIR = Path(f"/tmp/login-guard-it-{_RUN_ID}")
DB_PATH = DB_DIR / "login.db"
PORTS = {"web1": 8201 + (int(_RUN_ID) % 100),
         "web2": 8301 + (int(_RUN_ID) % 100)}
WINDOW = 5
MAX_SLOTS = 5
BASE = {name: f"http://127.0.0.1:{port}" for name, port in PORTS.items()}

failures: list[str] = []


def check(cond: bool, label: str) -> None:
    mark = "PASS" if cond else "FAIL"
    print(f"  [{mark}] {label}")
    if not cond:
        failures.append(label)


def reset_db() -> None:
    conn = sqlite3.connect(DB_PATH, timeout=30)
    try:
        conn.execute("DELETE FROM login_inflight")
        conn.execute("DELETE FROM login_errors")
        conn.execute("DELETE FROM sessions")
        conn.commit()
    finally:
        conn.close()


def stats(base: str) -> dict:
    r = httpx.get(f"{base}/api/stats", timeout=10)
    r.raise_for_status()
    return r.json()


def account_stat(base: str, username: str) -> dict:
    return next(a for a in stats(base)["accounts"] if a["username"] == username)


def wait_ready(base: str, timeout: float = 25.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if httpx.get(f"{base}/api/stats", timeout=2).status_code == 200:
                return
        except httpx.TransportError:
            pass
        time.sleep(0.2)
    raise RuntimeError(f"service at {base} never became ready")


def start_process(name: str) -> subprocess.Popen:
    env = os.environ.copy()
    env.update(
        {
            "LOGIN_DB_PATH": str(DB_PATH),
            "PROCESS_NAME": name,
            "ERROR_WINDOW_SECONDS": str(WINDOW),
            "MAX_SLOTS": str(MAX_SLOTS),
            "MAX_DELAY_SECONDS": "10",
            "PYTHONPATH": str(ROOT),
        }
    )
    log = open(DB_DIR / f"{name}.log", "w")
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app",
         "--host", "127.0.0.1", "--port", str(PORTS[name]), "--no-access-log"],
        cwd=str(ROOT), env=env, stdout=log, stderr=subprocess.STDOUT,
    )
    wait_ready(BASE[name])
    return proc


def login(base: str, username: str, password: str, delay: float = 0.0,
          timeout: float = 30.0):
    return httpx.post(
        f"{base}/api/login",
        json={"username": username, "password": password, "delay": delay},
        timeout=timeout,
    )


def set_clock_offset(base: str, offset_seconds: float):
    return httpx.post(
        f"{base}/api/demo/clock",
        json={"offset_seconds": offset_seconds},
        timeout=10,
    )


def hold_lock(base: str, seconds: float):
    return httpx.post(
        f"{base}/api/demo/hold-lock", json={"seconds": seconds}, timeout=30
    )


def stop_process(proc: subprocess.Popen) -> bool:
    """Best-effort SIGTERM. Returns False when the sandbox forbids signals."""
    if proc.poll() is not None:
        return True
    try:
        proc.terminate()  # SIGTERM on POSIX
        proc.wait(timeout=15)
        return True
    except (PermissionError, ProcessLookupError):
        return False
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
            proc.wait(timeout=5)
            return True
        except PermissionError:
            return False


def run_startup_cleanup() -> None:
    """Execute exactly the startup hook (db.init_db) in a fresh process.

    On a real Docker restart the new container process runs this same code
    against the same volume; all slot state lives in SQLite, so a separate
    short-lived process is a faithful equivalent when the sandbox forbids
    killing the long-running servers.
    """
    env = os.environ.copy()
    env.update(
        {
            "LOGIN_DB_PATH": str(DB_PATH),
            "ERROR_WINDOW_SECONDS": str(WINDOW),
            "MAX_SLOTS": str(MAX_SLOTS),
            "PYTHONPATH": str(ROOT),
        }
    )
    subprocess.run(
        [sys.executable, "-c", "from app.db import init_db; init_db()"],
        cwd=str(ROOT), env=env, check=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def main() -> int:
    DB_DIR.mkdir(parents=True, exist_ok=True)
    for p in DB_DIR.glob("login.db*"):
        p.unlink()

    procs = {name: start_process(name) for name in PORTS}
    try:
        # ---- 1. basics ----------------------------------------------------
        print("1. 基本登录 / 会话 / 身份 / 退出")
        r = login(BASE["web1"], "alice", "wrong")
        check(r.status_code == 401, "错误密码返回 401")
        r = login(BASE["web2"], "alice", "alice-pass-2026")
        check(r.status_code == 200, "正确密码返回 200")
        cookie = r.headers.get("set-cookie", "")
        check("httponly" in cookie.lower(), "会话 Cookie 带 HttpOnly")
        check(r.json()["served_by"] == "web2", "响应由 web2 进程处理")
        client = httpx.Client(base_url=BASE["web1"], cookies=r.cookies)
        me = client.get("/api/me")
        check(me.status_code == 200 and me.json()["username"] == "alice",
              "跨进程携带 HttpOnly 会话可查看当前身份")
        check(client.post("/api/logout").status_code == 204, "退出登录 204")
        check(client.get("/api/me").status_code == 401, "退出后身份查询 401")

        # ---- 2. cross-process shared view --------------------------------
        print("2. 两进程共享同一名额视图")
        reset_db()
        s1 = account_stat(BASE["web1"], "bob")
        s2 = account_stat(BASE["web2"], "bob")
        check(s1 == s2 and s1["remaining_slots"] == MAX_SLOTS,
              "两进程看到一致的初始名额")
        r = login(BASE["web1"], "bob", "nope")
        check(r.status_code == 401 and r.headers["X-Served-By"] == "web1",
              "web1 记录一次错误")
        check(account_stat(BASE["web2"], "bob")["window_errors"] == 1,
              "web2 立刻看到 web1 写入的错误")

        # ---- 3. atomic reservation + immediate 429, no hashing -----------
        print("3. 原子占位：满额立即 429 且不做哈希")
        reset_db()
        barrier = threading.Barrier(6)

        def attempt(i):
            barrier.wait()
            return login(BASE["web1" if i % 2 else "web2"],
                         "alice", "wrong", delay=2.0, timeout=30)

        with ThreadPoolExecutor(max_workers=6) as pool:
            futs = [pool.submit(attempt, i) for i in range(6)]
            results = [f.result() for f in futs]
        statuses = sorted(r.status_code for r in results)
        check(statuses == [401, 401, 401, 401, 401, 429],
              f"5 个进入核验、第 6 个 429（实际状态码 {statuses}）")
        limited = next(r for r in results if r.status_code == 429)
        check("retry-after" in {k.lower() for k in limited.headers.keys()},
              "429 带 Retry-After 头")
        check(limited.elapsed.total_seconds() < 1.5,
              f"429 立即返回（{limited.elapsed.total_seconds():.2f}s < 1.5s，未做 argon2/未睡延迟）")
        st = account_stat(BASE["web1"], "alice")
        check(st["window_errors"] == 5 and st["inflight"] == 0
              and st["remaining_slots"] == 0,
              "结算后错误=5、在途=0、剩余=0")

        # ---- 4. capacity blocks even the correct password ---------------
        print("4. 满额时正确密码同样立即 429")
        t0 = time.time()
        r = login(BASE["web2"], "alice", "alice-pass-2026")
        check(r.status_code == 429 and time.time() - t0 < 1.0,
              "满额后正确密码也被快速 429")

        # ---- 5. window expiry --------------------------------------------
        print(f"5. 滑动窗口（{WINDOW}s）过期后名额恢复")
        deadline = time.time() + WINDOW + 8
        while time.time() < deadline:
            if account_stat(BASE["web1"], "alice")["remaining_slots"] == MAX_SLOTS:
                break
            time.sleep(0.3)
        check(account_stat(BASE["web1"], "alice")["remaining_slots"] == MAX_SLOTS,
              "窗口滑过后名额恢复为 5")
        r = login(BASE["web1"], "alice", "alice-pass-2026")
        check(r.status_code == 200, "恢复后正确密码可登录")

        # ---- 6. disconnect does not release the slot ---------------------
        print("6. 客户端断连后核验仍完成并结算（不提前归还名额）")
        reset_db()
        def disconnecting_attempt(i):
            try:
                login(BASE["web1"], "bob", "wrong", delay=2.0, timeout=0.5)
            except httpx.TimeoutException:
                return "aborted"
            return "unexpected"

        with ThreadPoolExecutor(max_workers=3) as pool:
            futs = [pool.submit(disconnecting_attempt, i) for i in range(3)]
            time.sleep(0.9)  # requests already in-flight server-side
            mid = account_stat(BASE["web2"], "bob")
            check(mid["inflight"] == 3 and mid["window_errors"] == 0,
                  "客户端已超时断开，服务端在途仍为 3")
            outcomes = [f.result() for f in futs]
            check(outcomes == ["aborted"] * 3, "三个客户端均已断开")
        deadline = time.time() + 6
        while time.time() < deadline:
            st = account_stat(BASE["web1"], "bob")
            if st["inflight"] == 0:
                break
            time.sleep(0.2)
        st = account_stat(BASE["web1"], "bob")
        check(st["inflight"] == 0 and st["window_errors"] == 3,
              "断连的请求在服务端完成核验并计入 3 个错误")

        # ---- 7. success clears completed errors, late failures still count
        print("7. 成功清除已完成错误；其他在途请求随后出错仍计数")
        reset_db()
        for _ in range(2):
            check(login(BASE["web1"], "alice", "wrong").status_code == 401,
                  "预置 2 个已完成错误")
        check(account_stat(BASE["web1"], "alice")["window_errors"] == 2,
              "当前错误=2")

        start_event = threading.Event()

        def slow_wrong():
            start_event.wait()
            return login(BASE["web2"], "alice", "wrong", delay=2.5, timeout=30)

        with ThreadPoolExecutor(max_workers=2) as pool:
            f1 = pool.submit(slow_wrong)
            f2 = pool.submit(slow_wrong)
            start_event.set()  # both requests start together
            time.sleep(0.8)  # ensure both slots are acquired before continuing
            ok = login(BASE["web1"], "alice", "alice-pass-2026")
            check(ok.status_code == 200, "在途期间正确密码登录成功")
            st = account_stat(BASE["web1"], "alice")
            check(st["window_errors"] == 0 and st["inflight"] == 2,
                  "成功清除当时已完成错误，2 个在途不受影响")
            rs = [f1.result().status_code, f2.result().status_code]
            check(sorted(rs) == [401, 401], "两个慢请求随后失败")
        st = account_stat(BASE["web2"], "alice")
        check(st["window_errors"] == 2 and st["inflight"] == 0,
              "后完成的在途错误仍然计数（错误=2）")

        # ---- 8. restart persistence --------------------------------------
        print("8. 重启保留窗口内错误、清理未完成占位")
        reset_db()
        check(login(BASE["web1"], "bob", "wrong").status_code == 401,
              "制造 1 个已完成错误")
        pool = ThreadPoolExecutor(max_workers=2)
        futs = [
            pool.submit(lambda: login(BASE["web1"], "bob", "wrong",
                                      delay=4.0, timeout=30)),
            pool.submit(lambda: login(BASE["web2"], "bob", "wrong",
                                      delay=4.0, timeout=30)),
        ]
        time.sleep(1.0)
        check(account_stat(BASE["web1"], "bob")["inflight"] == 2,
              "重启前存在 2 个在途占位")

        stopped = all(stop_process(p) for p in procs.values())
        if stopped:
            # Real restart path: servers died with requests in flight.
            check(not any(f.done() for f in futs),
                  "客户端请求随进程关闭而未完成")
            procs = {name: start_process(name) for name in PORTS}
        else:
            # Sandbox blocks signals: simulate the restart by running the
            # exact startup hook in a fresh process against the same DB.
            run_startup_cleanup()
        st = account_stat(BASE["web1"], "bob")
        check(st["inflight"] == 0, "重启后未完成占位已清空")
        check(st["window_errors"] == 1, "窗口内错误在重启后保留")
        late_codes = []
        for f in futs:
            try:
                late_codes.append(f.result(timeout=10).status_code)
            except Exception:
                late_codes.append("transport")
        pool.shutdown(wait=True)
        if not stopped:
            # The verifiers finished after their slots were reclaimed: they
            # must settle gracefully (401, not a 500) and must not resurrect
            # slots or double-count errors.
            check(all(c in (401, "transport") for c in late_codes),
                  f"占位被回收后的延迟核验不产生 500（实际 {late_codes}）")
        st = account_stat(BASE["web2"], "bob")
        check(st["inflight"] == 0 and st["window_errors"] == 1,
              "延迟核验结束后无残留占位、错误不重复计数")
        reset_db()  # keep state clean for subsequent assertions

        # ---- 9. no plaintext passwords at rest ---------------------------
        print("9. 数据库仅存哈希")
        conn = sqlite3.connect(DB_PATH)
        try:
            rows = conn.execute(
                "SELECT username, password_hash FROM accounts ORDER BY username"
            ).fetchall()
            check([u for u, _ in rows] == ["alice", "bob"], "预置两个账号")
            all_argon = all(h.startswith("$argon2id$") for _, h in rows)
            check(all_argon, "密码字段均为 argon2id 哈希")
            dumped = "\n".join(
                str(r) for r in conn.execute(
                    "SELECT name, sql FROM sqlite_master").fetchall())
            for plain in ("alice-pass-2026", "bob-pass-2026"):
                check(plain not in dumped, f"库结构中无明文 {plain}")
        finally:
            conn.close()

        # ---- 10. wall-clock jumps do not move the error window ----------
        print("10. 校时（墙钟前跳/后跳）不解除也不延长错误窗口")
        reset_db()
        # Five concurrent wrong passwords settle within ~1s of each other.
        with ThreadPoolExecutor(max_workers=MAX_SLOTS) as pool:
            futs = [pool.submit(login, BASE["web1"], "alice", "wrong")
                    for _ in range(MAX_SLOTS)]
            for f in futs:
                f.result()
        st = account_stat(BASE["web1"], "alice")
        check(st["window_errors"] == MAX_SLOTS and st["remaining_slots"] == 0,
              "预置 5 个错误后名额为 0")
        check(login(BASE["web2"], "alice", "wrong").status_code == 429,
              "满额时第 6 次尝试 429")
        t_errors = time.monotonic()  # errors were settled just before this

        r = set_clock_offset(BASE["web1"], 3600)
        check(r.status_code == 200 and r.json()["clock_offset_seconds"] == 3600,
              "模拟校时：墙钟前跳 1 小时")
        # web1 的偏移缓存同步生效，可立即检查；跨进程可见性单独验证一次。
        st = account_stat(BASE["web1"], "alice")
        check(st["window_errors"] == MAX_SLOTS and st["remaining_slots"] == 0,
              "墙钟前跳后窗口错误仍为 5（限制未被解除）")
        check(login(BASE["web1"], "alice", "wrong").status_code == 429,
              "墙钟前跳后第 6 次尝试仍 429")
        time.sleep(0.8)  # let the other process's offset cache expire
        s2 = stats(BASE["web2"])
        check(abs(s2["wall_now"] - (time.time() + 3600)) < 10,
              "另一进程同样看到 +1h 墙钟（偏移经共享库生效）")

        check(set_clock_offset(BASE["web1"], -3600).status_code == 200,
              "模拟校时：墙钟后跳 1 小时")
        st = account_stat(BASE["web1"], "alice")
        check(st["window_errors"] == MAX_SLOTS and st["remaining_slots"] == 0,
              "墙钟后跳后窗口错误仍为 5（限制未被延长）")
        check(login(BASE["web1"], "alice", "wrong").status_code == 429,
              "墙钟后跳后第 6 次尝试仍 429")
        # Even with the wall clock shifted backwards, the window expires on
        # real elapsed time (monotonic), not one hour late.
        deadline = t_errors + WINDOW + 6
        recovered = False
        while time.monotonic() < deadline:
            if account_stat(BASE["web1"], "alice")["remaining_slots"] == MAX_SLOTS:
                recovered = True
                break
            time.sleep(0.3)
        check(recovered, "墙钟后跳状态下窗口仍按实际经过时间满期恢复")
        set_clock_offset(BASE["web1"], 0)
        time.sleep(0.8)
        check(stats(BASE["web2"])["clock_offset_seconds"] == 0,
              "恢复真实时间（偏移归零）")

        # ---- 11. admission uses the post-lock instant --------------------
        print("11. 准入以取得写锁后的时刻判定（锁等待期间过期的错误被放行）")
        reset_db()
        with ThreadPoolExecutor(max_workers=MAX_SLOTS) as pool:
            futs = [pool.submit(login, BASE["web1"], "alice", "wrong")
                    for _ in range(MAX_SLOTS)]
            for f in futs:
                f.result()
        check(account_stat(BASE["web1"], "alice")["remaining_slots"] == 0,
              "预置 5 个错误后满额")
        # Hold the write lock until well past the window expiry.
        holder = threading.Thread(target=hold_lock, args=(BASE["web2"], 7))
        holder.start()
        time.sleep(1.0)  # lock is held now; all errors expire during the hold
        t0 = time.monotonic()
        r = login(BASE["web1"], "alice", "wrong", timeout=30)
        waited = time.monotonic() - t0
        holder.join()
        check(r.status_code == 401,
              f"锁释放时错误已过期，请求被放行进入核验"
              f"（401 而非 429，实际 {r.status_code}）")
        check(waited > 4, f"请求确实排队等待了写锁（等待 {waited:.1f}s）")

        # ---- 12. settlement is booked at the post-lock instant -----------
        print("12. 结算以取得写锁后的时刻记录（窗口从实际结算时刻起算）")
        reset_db()
        holder = threading.Thread(target=hold_lock, args=(BASE["web2"], 4))
        holder.start()
        time.sleep(0.8)  # lock held; verification completes during the hold
        r = login(BASE["web1"], "alice", "wrong", timeout=30)
        holder.join()
        t_released = time.monotonic()
        check(r.status_code == 401, "错误密码返回 401")
        check(account_stat(BASE["web1"], "alice")["window_errors"] == 1,
              "错误已在锁释放后结算")
        # With a pre-lock timestamp this error would expire one window after
        # the *verification* finished (during the hold); it must instead
        # expire one full window after the real settlement instant.
        time.sleep(WINDOW - 1.5)
        check(account_stat(BASE["web1"], "alice")["window_errors"] == 1,
              "锁释放后近一个窗口时错误仍在（未按锁前时刻提前过期）")
        deadline = t_released + WINDOW + 4
        while time.monotonic() < deadline:
            if account_stat(BASE["web1"], "alice")["window_errors"] == 0:
                break
            time.sleep(0.2)
        check(account_stat(BASE["web1"], "alice")["window_errors"] == 0,
              "自满期时刻起错误正常过期")

        # ---- 13. restart keeps the window elapsing ------------------------
        print("13. 重启后窗口继续流逝（不清零、不重新计满）")
        reset_db()
        check(login(BASE["web1"], "bob", "wrong").status_code == 401,
              "制造 1 个已完成错误")
        t_err = time.monotonic()
        time.sleep(2.0)
        run_startup_cleanup()  # simulated restart: same code as init_db
        st = account_stat(BASE["web1"], "bob")
        check(st["window_errors"] == 1, "重启后窗口内错误保留")
        expires_in = st["window_expires_in"]
        check(expires_in is not None and 0.5 <= expires_in <= WINDOW - 1.5,
              f"恢复倒计时接着流逝而非重新计满（剩余 {expires_in}s）")
        deadline = t_err + WINDOW + 4
        while time.monotonic() < deadline:
            if account_stat(BASE["web1"], "bob")["window_errors"] == 0:
                break
            time.sleep(0.2)
        check(account_stat(BASE["web1"], "bob")["window_errors"] == 0,
              "错误仍在原定的满窗口时刻过期")

        # ---- 14. demo endpoints -------------------------------------------
        print("14. 演示端点：持锁 / 模拟重启 / 校时")
        reset_db()
        r = hold_lock(BASE["web1"], 0.5)
        check(r.status_code == 200 and r.json()["held_seconds"] >= 0.4,
              "持锁端点返回实际持锁时长")
        check(login(BASE["web1"], "bob", "wrong").status_code == 401,
              "制造 1 个已完成错误")
        pool = ThreadPoolExecutor(max_workers=1)
        slow = pool.submit(lambda: login(BASE["web2"], "bob", "wrong",
                                         delay=3.0, timeout=30))
        time.sleep(0.8)
        check(account_stat(BASE["web1"], "bob")["inflight"] == 1,
              "模拟重启前存在 1 个在途占位")
        r = httpx.post(f"{BASE['web1']}/api/demo/restart", timeout=10)
        check(r.status_code == 200, "模拟重启端点 200")
        st = account_stat(BASE["web1"], "bob")
        check(st["inflight"] == 0 and st["window_errors"] == 1,
              "模拟重启后在途清空、窗口错误保留")
        code = slow.result().status_code
        check(code == 401, f"被回收占位的慢请求优雅结算（{code}，非 500）")
        pool.shutdown(wait=True)
        st = account_stat(BASE["web1"], "bob")
        check(st["inflight"] == 0 and st["window_errors"] == 1,
              "慢请求结束后无残留占位、错误不重复计数")
        reset_db()  # keep state clean for the log check

        # ---- 15. server logs contain no unhandled exceptions -------------
        print("15. 服务端日志无未处理异常")
        for name in PORTS:
            log_text = (DB_DIR / f"{name}.log").read_text(errors="replace")
            check("Traceback" not in log_text and "RuntimeError" not in log_text,
                  f"{name} 日志无 Traceback/RuntimeError")

    finally:
        for proc in procs.values():
            stop_process(proc)

    print()
    if failures:
        print(f"{len(failures)} 项失败：")
        for f in failures:
            print(" -", f)
        return 1
    print("全部检查通过 ✅")
    return 0


if __name__ == "__main__":
    sys.exit(main())
