# Loom — 自托管 Git 代码托管（Steadholme 编织机）

Loom 是 Steadholme 主权基础设施中的 **自托管 Git 代码托管服务（git forge）**，落子域
`git.w33d.xyz`，内网监听 `9030`。它在同一个子域上提供两个面，并在 Sluice 网关按路径切分认证：

- **Web 控制台（`/`，`auth=sso`）**：仓库列表 / 新建、仓库浏览（默认分支文件树 + 提交历史 +
  分支）、Issues（列表 / 新建 / 开关）、个人访问令牌（PAT）管理。网关完成 OIDC 浏览器登录后注入
  `X-Auth-Subject` / `X-Auth-Email`，Loom 仅内网可达，因此**信任**这两个头，自身不做登录。
- **Git 智能 HTTP 协议（`/git/`，`auth=public`）**：`git clone` / `pull` / `push`。因为 `git`
  CLI **不会**走浏览器 OIDC/cookie SSO，网关在此放行为 `public`，由 **Loom 自己**做 HTTP Basic
  认证 —— 凭据是**个人访问令牌（PAT）**（用户名任意，密码=PAT）。

> 设计要点：Web UI 走网关 SSO；协议子路径走网关 public + 服务自认证。这是本浪次（git/docker CLI 无法
> 说浏览器 SSO）所有服务共用的“按路径切分”模式（参见姊妹服务 Cellar 镜像仓库的 `/v2/`）。

## 架构

```
浏览器 ──TLS──> Sluice 网关 ──(auth=sso, 注入 X-Auth-*)──> Loom Web 控制台 (/)
git  CLI ──TLS──> Sluice 网关 ──(auth=public)───────────> Loom 智能 HTTP (/git/) ──> git http-backend (CGI)
                                                                    │
                                                                    └─ PAT Basic 认证（Loom 自做）
```

- **仓库字节**：裸仓库（bare repo）存放在挂载卷 `LOOM_DATA/repos/{owner}/{name}.git`。通过
  shell 调用系统 `git` 管理（`git init --bare`；浏览用 `git` plumbing：`ls-tree` / `cat-file` /
  `log` / `for-each-ref`）。**不引入** C 链接的 `libgit2`/`git2`，与全 estate 的 rustls/无 OpenSSL
  立场一致。
- **clone/pull/push**：调用 `git http-backend` 作为 CGI（设置 `GIT_PROJECT_ROOT` /
  `PATH_INFO` / `GIT_HTTP_EXPORT_ALL` / `REQUEST_METHOD` / `QUERY_STRING` / `CONTENT_TYPE` /
  `GIT_PROTOCOL` 等），请求体与 stdout 并发读写，避免大 push 时管道死锁，得到正确的
  `info/refs?service=git-upload-pack|git-receive-pack` 广告与收发 pack 处理。
- **元数据**：仓库 / Issue / PAT 元数据落自有 Postgres 数据库 `loom`。`Store` 是 **async trait**
  （处理器直接 `.await`，`PgStore` 原生驱动 sqlx —— 无 `block_in_place`、无 sync-over-async 桥接）。
  运行期查询（无编译期宏）+ 可移植标准 SQL，将来可整体切到 FusionDB（pgwire）。

## 认证模型

| 操作 | 路由 | 认证 |
|------|------|------|
| Web 控制台（浏览 / 新建 / Issues / PAT） | `git.w33d.xyz/` | 网关 SSO（注入 `X-Auth-*`） |
| 公开仓库 `clone`/`pull`（`git-upload-pack`） | `git.w33d.xyz/git/...` | 匿名放行 |
| 私有仓库 `clone`/`pull` | `git.w33d.xyz/git/...` | **必须** PAT（且属于仓库 owner） |
| `push`（`git-receive-pack`） | `git.w33d.xyz/git/...` | **始终必须** PAT（且属于仓库 owner） |

- PAT 仅存 **SHA-256 哈希**（`pats.token_hash`），明文只在生成时**一次性**展示。
- 缺失/无效凭据 → `401 WWW-Authenticate: Basic`；令牌有效但不属于该仓库 owner → `403`。
- 私有仓库对非 owner 在 Web 上返回 404（不泄露存在性）。
- Web 写操作（新建仓库 / Issue / PAT / 撤销）走 **double-submit CSRF**（`__Host-csrf` cookie）。
- 所有生产者文本（仓库名/描述/文件内容/提交标题/Issue 正文）渲染时 **HTML 转义**；文件内容只在转义
  的 `<pre>` 中展示，绝不作为可执行 HTML。

## 数据模型（db `loom`）

```sql
repos(id TEXT PK, owner_sub TEXT, name TEXT, description TEXT,
      is_private BOOLEAN DEFAULT FALSE, default_branch TEXT DEFAULT 'main',
      created_at BIGINT, UNIQUE(owner_sub, name))

issues(id TEXT PK, repo_id TEXT, number BIGINT, title TEXT, body TEXT,
       author_sub TEXT, state TEXT DEFAULT 'open', created_at BIGINT)
-- 附加唯一索引 (repo_id, number) 支撑“每仓库自增编号”的并发安全 ON CONFLICT 重试

pats(id TEXT PK, owner_sub TEXT, name TEXT, token_hash TEXT, created_at BIGINT)
```

## 配置（环境变量）

| 变量 | 默认 | 说明 |
|------|------|------|
| `BIND_ADDR` | `0.0.0.0:9030` | 监听地址 |
| `LOOM_STORE` | `memory` | `memory`（无库，开发/测试）/ `postgres` |
| `DATABASE_URL` | — | `LOOM_STORE=postgres` 时必填（`postgres:5432/loom`） |
| `LOOM_DATA` | `/data` | 裸仓库根（`<LOOM_DATA>/repos/{owner}/{name}.git`） |
| `PUBLIC_BASE_URL` | `https://git.w33d.xyz` | 渲染 `git clone` URL 用 |
| `GIT_HTTP_BACKEND` | `/usr/lib/git-core/git-http-backend` | `git http-backend` CGI 路径 |
| `GIT_BIN` | `git` | `git` 可执行 |

## 运行

```bash
# 开发：内存存储，仓库落系统临时目录，无需数据库
cargo run

# 生产：Postgres + 持久卷
LOOM_STORE=postgres DATABASE_URL=postgres://steadholme:***@postgres:5432/loom \
LOOM_DATA=/data PUBLIC_BASE_URL=https://git.w33d.xyz cargo run --release

# 容器健康探针（镜像 HEALTHCHECK 复用此子命令，无需 curl）
loom healthcheck   # GET 127.0.0.1:$PORT/healthz，200 退出 0
```

## 使用 git（PAT 认证）

```bash
# 1) 在 Web 控制台 https://git.w33d.xyz/pats 生成 PAT（仅展示一次）
# 2) 新建仓库 https://git.w33d.xyz/ （或浏览已有仓库的 clone 地址）

# 公开仓库匿名克隆
git clone https://git.w33d.xyz/git/<owner>/<repo>.git

# 推送（用户名任意，密码=PAT；私有仓库克隆同理）
git clone https://<user>:<PAT>@git.w33d.xyz/git/<owner>/<repo>.git
cd <repo>
git add . && git commit -m "first commit"
git push origin main
```

## HTTP 路由

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/healthz` | 存活探针（public） |
| GET | `/` | 仓库列表 + 新建表单 |
| POST | `/new` | 新建仓库（CSRF）→ 302 仓库页 |
| GET | `/r/{owner}/{name}` | 代码页（根树 + 提交 + 分支 + clone 地址） |
| GET | `/r/{owner}/{name}/tree/{*path}` | 浏览子目录 |
| GET | `/r/{owner}/{name}/blob/{*path}` | 查看文件（转义） |
| GET/POST | `/r/{owner}/{name}/issues` | Issue 列表 / 新建（CSRF） |
| POST | `/r/{owner}/{name}/issues/{n}/toggle` | 开/关 Issue（CSRF） |
| GET/POST | `/pats` | 令牌列表 / 生成（一次性展示） |
| POST | `/pats/{id}/revoke` | 撤销令牌（CSRF） |
| GET/POST | `/git/{*path}` | Git 智能 HTTP（PAT Basic 自认证） |

## 测试

```bash
# 默认套件：单元 + 内存端到端流程（含真实 git http-backend CGI 与 PAT 认证策略）。
# 因 Loom 本质是 git forge，测试需要宿主机 git + git-http-backend 在 PATH。
cargo test

# Postgres 集成测试（仅在设置 TEST_DATABASE_URL 时运行）
docker run --rm -d --name loom-testpg -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=loom \
  -p 127.0.0.1:55470:5432 postgres:18-alpine
TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55470/loom \
  cargo test --test pg_store -- --nocapture
docker rm -f loom-testpg

# Lint
cargo clippy --all-targets -- -D warnings
```

## 构建镜像

```bash
docker build -t steadholme/loom:dev .
```

多阶段、非 root（uid 10001）；运行镜像安装 `git`（提供 `git-http-backend`）与 `ca-certificates`；
无 OpenSSL（sqlx 用 rustls、PAT 哈希用 RustCrypto `sha2`）。`/data` 为裸仓库卷（新建命名卷继承
uid 10001 可写属主）。

## 已延后（DEFER）

- Pull Request / 代码评审 / Web 端合并
- Webhooks
- SSH 传输（当前仅智能 HTTP）
- 大 push 的请求体直通流式转发（当前先在内存缓冲再交给 CGI，上限 1 GiB）
- 仓库删除 / 协作者模型（当前单 owner）
