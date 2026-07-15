# Cellar — 主权 OCI 容器镜像仓库

Cellar 是 Steadholme 主权基础设施中的**容器镜像仓库**（OCI / Docker Registry HTTP API V2），
落子域 `registry.w33d.xyz`，内网端口 `9040`。它把整套架构的核心挑战做成范式：
**Web 控制台走浏览器 SSO，CLI 协议走仓库自有的 HTTP Basic 认证**——因为 `docker` 客户端
不会做浏览器的 OIDC/Cookie 单点登录。

## 两个面，一个子域（网关按路径切分）

| 路由 | 网关认证 | 说明 |
|------|----------|------|
| `registry.w33d.xyz/`（Web 控制台） | `auth=sso` | 网关跑 OIDC 登录，注入受信的 `X-Auth-Subject`/`X-Auth-Email`；Cellar 直接信任，无自有登录 |
| `registry.w33d.xyz/v2/`（仓库协议） | `auth=public` | 网关放行，**由 Cellar 自己做 HTTP Basic 认证**（`CELLAR_USER`/`CELLAR_PASSWORD`） |

- **写操作（push）与 `docker login` 探测**：必须携带有效 Basic 凭据，否则返回
  `401 WWW-Authenticate: Basic`——这正是促使 docker 客户端补交凭据的机制。
- **读操作（公开仓库 pull）**：未带凭据可匿名读取；带了**错误**凭据则拒绝（不静默降级为匿名）。
- 当 `CELLAR_USER` 为空（dev 默认）时，`/v2/` 认证关闭，便于本地与无库测试。

## OCI Distribution V2 端点

- `GET /v2/`：版本探测 / 认证探针，返回 `Docker-Distribution-Api-Version: registry/2.0`。
- Blob 上传：`POST /v2/{name}/blobs/uploads/`（→ `202` + `Location` + `Docker-Upload-Uuid`）→
  `PATCH`（追加分块）→ `PUT ?digest=`（终结、校验摘要）。亦支持 `POST ?digest=` 单请求直传，
  以及 `?mount=&from=` 跨仓库挂载（blob 已存在时直接复用）。
- `HEAD`/`GET /v2/{name}/blobs/{digest}`：blob 存在性 / 取回。
- `PUT`/`GET`/`HEAD /v2/{name}/manifests/{reference}`：按 tag 或 digest 读写 manifest（保存
  `Content-Type` 原样回放，并以 sha256 内容寻址）。
- `GET /v2/{name}/tags/list`、`GET /v2/_catalog`。
- 错误以 OCI 信封 `{"errors":[{"code","message","detail"}]}` 返回。

## 存储

- **元数据**：Postgres（库 `cellar`），仅可移植标准 SQL + 运行时查询（**无编译期宏**，构建不需要
  数据库），日后可在 pgwire / FusionDB 原样运行；启动幂等迁移（`CREATE TABLE IF NOT EXISTS`）。
  - `repositories(name PK, created_at)`
  - `manifests(id PK, repo, digest, media_type, raw, size, created_at, UNIQUE(repo,digest))`
  - `tags(repo, tag, manifest_digest, updated_at, PRIMARY KEY(repo,tag))`
  - `blobs(digest PK, size, created_at)`
- **Blob 字节**：内容寻址在挂载卷 `CELLAR_DATA` 上，路径 `blobs/sha256/<hex>`；原子发布
  （先写临时文件再 `rename`），相同层跨仓库自动去重。上传会话在 `uploads/<uuid>`。

两个存储层都各有内存实现，所以默认 `cargo test` 不需要数据库与卷。

## Web 控制台（SSO）

仓库列表（镜像数 / tag 数 / 体积 / 最近推送时间）+ 仓库详情（各 tag 的 manifest 摘要、媒体
类型、镜像体积、更新时间）。提供一个**带 CSRF 的删除 tag** 操作（删除指针；manifest 与 blob
保留，回收为延后的 GC）。企业级 Steadholme UI（内联 CSS、app-bar、登录邮箱、网关登出）。所有
生产者文本均做 HTML 转义。

## 配置（环境变量）

| 变量 | 默认 | 说明 |
|------|------|------|
| `BIND_ADDR` | `0.0.0.0:9040` | 监听地址 |
| `CELLAR_STORE` | `memory` | `memory` \| `postgres` |
| `DATABASE_URL` | — | `postgres` 模式必填，指向 `postgres:5432/cellar` |
| `CELLAR_BLOBS` | 随 store（postgres→`fs`，否则 `memory`） | `memory` \| `fs` |
| `CELLAR_DATA` | `/data` | 内容寻址 blob 卷根目录 |
| `CELLAR_USER` / `CELLAR_PASSWORD` | 空（认证关闭） | `/v2/` HTTP Basic 凭据 |
| `PUBLIC_BASE_URL` | `https://registry.w33d.xyz` | 公网基址（realm 提示 + 展示） |

## 构建 / 测试 / 运行

```bash
cargo test                 # 内存端到端 + 单元（无库、无卷）
cargo clippy --all-targets -- -D warnings
docker build -t holdfast/cellar:dev .

# 部署：网关在 HTTPS 之后，docker login/push/pull 直接可用：
docker login registry.w33d.xyz
docker tag alpine registry.w33d.xyz/alpine:latest
docker push registry.w33d.xyz/alpine:latest
docker pull registry.w33d.xyz/alpine:latest
```

健康检查内置子命令 `cellar healthcheck`（裸 TCP GET `/healthz`），镜像无需 curl。

## 延后项（DEFERRED）

- Bearer token 认证服务器（Basic 已足够 `docker login`/push/pull，且更简单）。
- 未引用 blob / 无 tag manifest 的垃圾回收（GC）扫描。
- 分块上传的边界细节（断点续传 `Range` 精确语义）与超大层的流式落盘（当前整体缓冲，
  body 上限 1 GiB）。
- `DELETE /v2/.../manifests|blobs` 协议删除（可选；改由 Web 控制台删 tag 替代）。
- Helm chart / 超出镜像范围的 OCI artifact、manifest list/index 的深度校验、`tags`/`_catalog`
  分页。
