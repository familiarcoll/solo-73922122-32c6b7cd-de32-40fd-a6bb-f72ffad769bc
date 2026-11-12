# 并发密码猜测限制登录服务

FastAPI + SQLite(WAL) + argon2-cffi 实现的登录演示：两个独立 Web 进程共享同一
SQLite 数据库，对同一员工账号的并发密码猜测做严格名额控制，**客户端断连不能绕过限制**。
错误窗口以**宿主单调时钟**计时：维护人员校准服务器墙钟（NTP 跳变/手动改时）不会
提前解除也不会延长限制。

## 时间基准设计（窗口正确性）

| 问题 | 设计 |
| --- | --- |
| 校准服务器时间后，刚触发的限制立即解除或额外封锁一小时 | 错误窗口只使用 `time.monotonic()`（宿主单调时钟）：墙钟前跳/后跳均不改变已记录的截止期限，60 秒按实际经过时间计满即过期 |
| 锁等待导致"过期仍拒绝" | 准入判定在 `BEGIN IMMEDIATE` 取得写锁**之后**才读取单调时钟（`app/db.py:acquire_slot`），排队期间过期的错误在判定时已被清除 |
| 锁等待导致"刚结算的错误已过期" | 错误结算同样在取得写锁后取时刻（`app/db.py:settle`），窗口从实际结算瞬间起算满 60 秒 |
| 两个 Web 进程时间基准不一致 | `CLOCK_MONOTONIC` 在同一宿主的所有进程/容器间完全一致，两进程天然共用同一基准 |
| 重启进程/容器后窗口清零或重新计满 | 单调时钟在同一宿主启动周期内连续：重启后已记录的窗口继续流逝。仅当宿主真正重启（`boot_id` 变化）或时间基准代际不同时，启动清理才丢弃不可比的旧错误行 |
| 统计/剩余名额/Retry-After 与准入不一致 | 三者使用同一单调时钟与同一窗口谓词（`created_at > now - window`，满 60 秒即过期）；`/api/stats` 另给出每账号 `window_expires_in` 恢复倒计时 |
| 会话过期 | 会话使用墙钟（含演示校时偏移），与错误窗口的单调时钟互不影响——校时演示可直观看到这一对比 |

## 快速启动（Docker Compose）

```bash
docker compose up --build
```

启动后浏览器打开：

| 入口 | 地址 | 说明 |
| --- | --- | --- |
| 主入口（Nginx 轮询两个进程） | http://localhost:8080 | 推荐，请求在 web1/web2 间轮询 |
| 直连进程 1 | http://localhost:8001 | 响应头 `X-Served-By: web1` |
| 直连进程 2 | http://localhost:8002 | 响应头 `X-Served-By: web2` |

预置账号（数据库中**只存 argon2id 哈希**，页面上展示明文仅为演示方便）：

- `alice` / `alice-pass-2026`
- `bob` / `bob-pass-2026`

停止与清理：

```bash
docker compose down          # 停止；命名卷 login-db 保留，窗口错误持久存在
docker compose down -v       # 连数据库卷一起删除，下次启动重新预置
```

## 规则与实现映射

| 需求 | 实现 |
| --- | --- |
| 每账号 60 秒窗口错误数 + 在途核验数合计 ≤ 5 | `app/db.py:acquire_slot`，`BEGIN IMMEDIATE` 短事务内同时计数 `login_errors`（窗口内）与 `login_inflight`，超限直接拒绝 |
| 窗口 60 秒按实际经过时间计算，校时不解除/不延长 | 错误与在途时间戳一律使用宿主单调时钟 `time.monotonic()`，墙钟（NTP/手动校准）跳变不影响期限 |
| 准入及错误结算以取得写锁后的时刻判定 | `acquire_slot` / `settle` 在 `BEGIN IMMEDIATE` 返回后的第一条语句取 `time.monotonic()`，锁等待不会用过期视图拒绝、也不会让刚结算的错误提前过期 |
| 两进程一致时间基准、重启后窗口继续流逝 | 单调时钟同宿主全进程/容器一致且重启不归零；`meta` 表记录 `boot_id` 与 `time_base`，仅宿主重启或代际变更时才清理不可比的旧错误 |
| 核验前原子占位 | 计数与插入占位在同一个 SQLite 写事务中完成；WAL + `busy_timeout=30s` 保证两进程竞争时串行裁决、不报错 |
| 满额立即 429 且不算哈希 | 占位失败直接抛 `HTTPException(429)`，带 `Retry-After`；argon2 调用在其后，根本不会执行（测试实测 429 响应约 0.02s 返回） |
| 完成后释放占位；错误按完成时刻计数 | `app/db.py:settle` 在核验结束后统一结算，错误记录写的是结算时刻的单调时钟，不是占位时刻 |
| 成功清除**当时已完成**错误，其他在途之后出错仍计数 | 成功事务只 `DELETE login_errors`，不碰 `login_inflight`；慢请求结束后照常插入自己的错误（集成测试第 7 组覆盖） |
| 结算与会话签发一起提交 | 释放占位 / 清错误或插错误 / 插入 session 行在同一事务，同生共死 |
| 两个 Web 进程共用状态 | 两容器挂载同一命名卷的同一个 `login.db`，WAL 模式允许读写并发、写事务互斥裁决 |
| 哈希计算不持数据库写锁 | `verify_password` 在 `app/main.py` 登录处理中、任何写事务之外执行；DB 连接在核验前就已关闭 |
| 不用全局锁串行核验 | 无任何进程内锁；同步端点跑在 Starlette 线程池（上限调到 64），argon2 完全并行，协调只靠 SQLite 短事务 |
| 断连仍完成核验并结算，不提前归还名额 | 登录端点是同步 `def`，占位到结算之间无 `await` 点，客户端断开无法取消线程；核验和结算必然先完成（集成测试第 6 组覆盖） |
| 重启保留窗口内错误、清理未完成占位 | 错误是已提交的普通行；启动钩子 `init_db` 无条件 `DELETE FROM login_inflight`（旧核验者已随进程死亡），窗口错误保留且倒计时继续 |
| 随机 HttpOnly 会话 | `secrets.token_urlsafe(32)` 生成 256-bit 令牌，Cookie 带 `HttpOnly; SameSite=Lax`，仅令牌哈希引用以行存于 `sessions` 表 |

## 数据库结构（SQLite，WAL）

```text
accounts        id, username UNIQUE, password_hash(argon2id), created_at
login_errors    account_id, created_at          -- 单调时钟，按完成时刻记录，窗口外惰性清理
login_inflight  slot_id PK, account_id, acquired_at  -- 单调时钟，原子占位，重启清空
sessions        token PK, account_id, created_at, expires_at  -- 墙钟（含演示校时偏移）
meta            key PK, value                   -- time_base / boot_id / clock_offset
```

## HTTP 接口

- `GET /` — 演示网页（并发发起、AbortController 中途断开、1 秒刷新各账号剩余名额与恢复倒计时、可调核验延迟、校时/锁等待/重启演示）
- `POST /api/login` — body `{username, password, delay}`，成功 200 并下发会话 Cookie；失败 401；满额 429（`Retry-After`）
- `GET /api/me` — 查看当前登录身份
- `POST /api/logout` — 销毁当前会话
- `GET /api/stats` — 每个账号的窗口错误数、在途数、剩余名额、恢复倒计时，以及服务器墙钟/单调时钟/当前校时偏移
- `POST /api/demo/clock` — body `{offset_seconds}`，模拟校准服务器墙钟（偏移写入共享库，两进程同时生效；错误窗口不受影响）
- `POST /api/demo/hold-lock` — body `{seconds}`（≤20），持有 SQLite 写锁，演示锁等待期间的准入/结算判定
- `POST /api/demo/restart` — 执行与真实重启相同的启动清理（在途清空、窗口错误保留并继续流逝）

所有响应带 `X-Served-By`（web1/web2）与 `X-Process-Time-ms`，便于观察轮询与耗时。

## 网页演示建议

1. 对 `alice` 并发发起 6 个错误密码、延迟 4s：前 5 个进入在途，第 6 个立即 429。
2. 在途期间点「全部断开」：浏览器侧已取消，名额表仍显示 5 在途；约 4s 后服务端自行结算，在途归零、错误变 5。
3. 5 个错误结算后任何请求（哪怕密码正确）都立即 429；等待窗口按实际经过时间滑过自动恢复。
4. 用正确密码发一个长延迟请求，同时并发错误请求，观察「成功只清已完成错误、后到的在途错误仍计数」。
5. **校时**：触发限制后点「墙钟前跳 1 小时」——限制不解除；点「墙钟后跳 1 小时」——限制不延长；倒计时只随真实时间流逝（对比：现有会话按墙钟计算，前跳 1 小时会立即失效）。
6. **锁等待**：制造 5 个错误，等恢复倒计时接近 0 时点「持有写锁」8 秒，期间发起登录会排队，锁释放后错误已过期、请求被放行（401 而非 429）。
7. **重启**：制造错误后点「模拟进程重启」或 `docker compose restart web1`：在途占位清空，窗口错误保留且倒计时接着流逝，不清零也不重新计满。

## 本地无 Docker 时运行（开发/测试）

```bash
pip install -r requirements.txt
export LOGIN_DB_PATH=/tmp/login.db
uvicorn app.main:app --port 8001   # 终端 A
PROCESS_NAME=web2 uvicorn app.main:app --port 8002   # 终端 B，同一 DB 文件
```

## 集成测试

`tests/run_integration.py` 会在本机拉起两个共享同一 SQLite 文件的 uvicorn 进程，
覆盖 15 组断言（原子占位/429 不哈希、滑窗、断连结算、交错完成、重启语义、
墙钟前后跳不影响窗口、锁等待后的准入与结算时刻、重启后窗口继续流逝、
演示端点、无明文存储、服务日志无异常等）：

```bash
python tests/run_integration.py
```

测试通过环境变量 `ERROR_WINDOW_SECONDS` / `MAX_SLOTS` 把窗口缩短为 5 秒以便验证，
生产默认值为 60 秒 / 5。

## 可调环境变量

| 变量 | 默认 | 含义 |
| --- | --- | --- |
| `LOGIN_DB_PATH` | `/data/login.db` | SQLite 文件路径（两进程必须指向同一文件） |
| `ERROR_WINDOW_SECONDS` | `60` | 错误计数滑动窗口（单调时钟计时） |
| `MAX_SLOTS` | `5` | 每账号窗口错误 + 在途的合计上限 |
| `MAX_DELAY_SECONDS` | `10` | 演示用核验延迟上限 |
| `SESSION_TTL_SECONDS` | `3600` | 会话有效期（墙钟） |
| `PROCESS_NAME` | `login` | 标识进程，体现在 `X-Served-By` |
| `ENABLE_DEMO_API` | `1` | 是否开放 `/api/demo/*` 演示端点（校时/持锁/模拟重启） |
