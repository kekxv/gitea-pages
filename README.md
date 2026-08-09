# Gitea Pages - Actionless Static Site Hosting

[![Build and Push Docker Images](https://github.com/kekxv/gitea-pages/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/kekxv/gitea-pages/actions/workflows/docker-publish.yml)
[![Deployer Image](https://img.shields.io/badge/ghcr.io%2Fkekxv%2Fgitea-pages%2Fdeployer-latest)](https://github.com/kekxv/gitea-pages/pkgs/container/deployer)
[![Nginx Image](https://img.shields.io/badge/ghcr.io%2Fkekxv%2Fgitea-pages%2Fnginx-latest)](https://github.com/kekxv/gitea-pages/pkgs/container/nginx)

[English](#english) | [中文](#中文)

---

<a name="english"></a>

## English

A GitHub Pages-like static site hosting system for Gitea. Automatically deploys sites when code is pushed to the `gh-pages` branch.

### Features

- **Zero User Action**: Push to `gh-pages` branch → automatic deployment
- **Automatic Cleanup**: Delete `gh-pages` branch → site automatically removed
- **Wildcard Domain Routing**: `username.pages.yourdomain.com` and `username.pages.yourdomain.com/repo`
- **Security Hardened**: Non-root containers, symlink blocking, path traversal protection
- **Private Repo Support**: OAuth2 user authorization
- **Scoped Webhook Registration**: Each Gitea hook has an independent key and HMAC secret
- **Contained Topology**: Nginx is the only host-published service; Deployer has no Docker socket or SSH key

### Quick Start

#### Using Pre-built Images (Recommended)

```bash
# Create docker-compose.yml
curl -O https://raw.githubusercontent.com/kekxv/gitea-pages/main/docker-compose.yml
curl -O https://raw.githubusercontent.com/kekxv/gitea-pages/main/.env.example
cp .env.example .env
# Edit .env with your settings

# The Compose file names GHCR images, so this path does not need the source
# build contexts. Create the three secret files, then pull and run.
docker compose pull
docker compose up -d
```

Pre-built images available at:
- **Deployer**: `ghcr.io/kekxv/gitea-pages/deployer:latest`
- **Nginx**: `ghcr.io/kekxv/gitea-pages/nginx:latest`

#### Building from Source

```bash
git clone https://github.com/kekxv/gitea-pages.git
cd gitea-pages
docker compose up -d --build
```

### OAuth2 Configuration (Recommended)

Users can self-authorize to enable automatic webhook registration and private repo access.

#### Step 1: Create OAuth2 Application in Gitea

1. Login to Gitea
2. Go to **Settings → Applications → OAuth2 Applications**
3. Click **Create OAuth2 Application**
4. Fill in:
   - **Application Name**: `Gitea Pages`
   - **Redirect URI**: `https://pages.yourdomain.com/oauth/callback`
   - **Confidential Client**: **YES** (Important!)
5. Copy **Client ID** and **Client Secret**

#### Step 2: Configure Deployer

Set the client ID in `.env`; keep the client secret in the
`OAUTH_CLIENT_SECRET_HOST_FILE` file described by `.env.example`. Compose
constructs public callback and webhook URLs from `DOMAIN`:
```bash
OAUTH_CLIENT_ID=your-client-id
GITEA_PUBLIC_URL=https://gitea.example.com
```

#### Step 3: User Authorization

1. Visit `https://pages.yourdomain.com`
2. Click **"Authorize Gitea Pages"**
3. Login to Gitea and approve the authorization
4. A scoped webhook is automatically registered for your authorized personal
   and organization scopes

### Permission Explanation

When users authorize Gitea Pages, the following permissions are requested:

| Permission | Scope | Purpose |
|------------|-------|---------|
| Read User Info | `read:user` | Get username to identify site ownership |
| Manage User Settings | `write:user` | Register a personal-scope webhook |
| Read Repositories | `read:repository` | Clone repository code for deployment |
| Manage Organization Webhooks | `write:organization` | Automatically register organization hooks through the approved administrator token pool |

Users can revoke authorization anytime in Gitea **Settings → Applications → OAuth2 Applications**.
Organization hooks are automatic by default through the approved administrator
token pool. Keep `ENABLE_ORGANIZATION_HOOKS=true` for this architecture; set
it to `false` only when an installation intentionally serves personal scopes.

### Private Repository Support

With OAuth2 authorization, private repositories are automatically supported. The deployer uses the user's OAuth token to clone private repos when deploying their sites.

### Offline security credential migration

The offline migration command, `migrate-security`, encrypts legacy OAuth
tokens and replaces the shared webhook secret with one credential per Gitea
hook. It uses existing OAuth grants (and the retained organization-authorizer
pool) so users do not need to authorize again unless Gitea rejects the actual
token, scope, administrator permission, or a manually-created hook. Stop the
Deployer before running either maintenance command; Nginx can keep serving the
already-published static files.

The migration requires `TOKEN_ENCRYPTION_KEY_FILE`,
`LEGACY_WEBHOOK_SECRET_FILE`, `GITEA_API_URL`, and `WEBHOOK_PUBLIC_URL`. Create
the database backup yourself first, protect it with `0600`, and choose a new
manifest filename. The command refuses to run without those guards:

```bash
deployer migrate-security \
  --backup /secure/backups/tokens.db.before-security-migration \
  --manifest /secure/backups/legacy-hooks.manifest
```

The manifest is AES-GCM encrypted and mode `0600`; retain it only for the
rollback window. A named organization reported with “requires manual
reauthorization” was skipped only when
`--skip-failed-organizations` was explicitly supplied.

Production sequence:

1. Back up Pages data and `tokens.db`; record old image digests.
2. Stop only Deployer; keep Nginx serving existing static files.
3. Run the new image with `migrate-security` and secret files mounted.
4. Verify encrypted rows, per-hook row counts, and Gitea hook delivery tests.
5. Start the new Deployer and send one personal plus one organization test delivery.
6. Remove the legacy secret file from the host after the rollback window.
7. For rollback, stop new Deployer, run `restore-legacy-hooks`, restore the v1 database backup, and start the pinned old image.

To restore Gitea before restoring the database backup, mount the same
encryption key and legacy webhook secret files and run:

```bash
deployer restore-legacy-hooks --manifest /secure/backups/legacy-hooks.manifest
```

The restore command attempts every recorded hook and exits non-zero unless all
of them are restored.

#### Create Your Site

**Root Site (username.pages.domain.com):**
```bash
# Repository name format: username.pages.<domain>
git init yourname.pages.example.com
cd yourname.pages.example.com
git checkout -b gh-pages
echo "<html><body>Hello from root!</body></html>" > index.html
git add . && git commit -m "Initial site"
git remote add origin https://gitea.example.com/username/yourname.pages.example.com.git
git push -u origin gh-pages
```
Site available at: `https://username.pages.example.com/`

**Subdirectory Site (username.pages.domain.com/repo):**
```bash
git init my-site
cd my-site
git checkout -b gh-pages
echo "<html><body>Hello!</body></html>" > index.html
git add . && git commit -m "Initial site"
git remote add origin https://gitea.example.com/username/my-site.git
git push -u origin gh-pages
```
Site available at: `https://username.pages.example.com/my-site`

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         Gitea Server                         │
│    signed, per-hook delivery → pages.<DOMAIN>/webhook        │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ Nginx (only host port) → private backend → Deployer          │
│  • forwards /webhook and OAuth routes to internal Deployer   │
│  • serves Pages data read-only                               │
│  • Deployer verifies per-hook HMAC and Gitea metadata        │
│  • Deployer publishes untrusted static content atomically    │
│  • Deployer has no Docker socket, SSH key, or host port      │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     Published Pages volume                   │
│  • root: username.pages.domain → _root/                      │
│  • subsite: username.pages.domain/repo → repo/               │
└─────────────────────────────────────────────────────────────┘
```

### Security Features

| Feature | Implementation |
|---------|---------------|
| Non-root containers | UID/GID 1000 (`pagesuser`) |
| No-new-privileges | `security_opt: no-new-privileges:true` |
| Read-only root filesystem | `read_only: true` with tmpfs |
| Symlink blocking | `disable_symlinks on` + code filter |
| Path traversal protection | Input sanitization |
| .git directory removal | Automatic cleanup |
| Webhook authentication | Per-hook key and HMAC-SHA256 secret; Gitea metadata is canonical |
| Site size limit | `MAX_SITE_SIZE_MB` (default 100MB) |
| Private repo support | OAuth2 user tokens |
| Network exposure | Only Nginx publishes a port; Deployer is private to Compose networks |

### Directory Structure

```
gitea-pages/
├── .env.example           # Environment configuration
├── docker-compose.yml     # Container orchestration
├── nginx/
│   ├── Dockerfile
│   └── nginx.conf
├── deployer/
│   ├── Dockerfile
│   ├── main.go            # Entry point
│   ├── handler.go         # Webhook handler
│   ├── git.go             # Git operations
│   ├── gitea.go           # Gitea API client
│   ├── oauth.go           # OAuth2 handler
│   ├── web.go             # Web UI
│   └── security.go        # Security utilities
└── examples/quickstart/   # Hardened deployment guide
```

### Testing

```bash
# Go unit and end-to-end regression tests
cd deployer && go test -race ./...

# Compose and Nginx containment checks
cd .. && bash tests/compose_security_test.sh && bash tests/nginx_test.sh
```

### License

MIT License

---

<a name="中文"></a>

## 中文

为 Gitea 实现类似 GitHub Pages 的静态网站托管系统。向 `gh-pages` 分支推送代码后自动部署。

### 功能特性

- **零用户操作**：推送代码到 `gh-pages` 分支 → 自动部署
- **自动清理**：删除 `gh-pages` 分支 → 自动删除站点
- **泛域名路由**：支持 `username.pages.yourdomain.com` 和 `username.pages.yourdomain.com/repo`
- **安全加固**：非 root 容器、阻止软链接、路径遍历防护
- **私有仓库支持**：OAuth2 用户授权
- **范围化 Webhook 注册**：每个 Gitea hook 均拥有独立 key 和 HMAC secret

### 快速开始

#### 使用预构建镜像（推荐）

```bash
# 创建 docker-compose.yml
curl -O https://raw.githubusercontent.com/kekxv/gitea-pages/main/docker-compose.yml
curl -O https://raw.githubusercontent.com/kekxv/gitea-pages/main/.env.example
cp .env.example .env
# 编辑 .env 填入你的配置

# Compose 文件已指定 GHCR 镜像，此流程不需要源码构建上下文；拉取并运行
docker compose pull
docker compose up -d
```

预构建镜像地址：
- **Deployer**: `ghcr.io/kekxv/gitea-pages/deployer:latest`
- **Nginx**: `ghcr.io/kekxv/gitea-pages/nginx:latest`

#### 从源码构建

```bash
git clone https://github.com/kekxv/gitea-pages.git
cd gitea-pages
docker compose up -d --build
```

### OAuth2 配置（推荐）

用户可以自助授权，启用自动 webhook 注册和私有仓库访问。

#### 步骤 1：在 Gitea 创建 OAuth2 应用

1. 登录 Gitea
2. 进入 **设置 → 应用 → OAuth2 应用**
3. 点击 **创建 OAuth2 应用**
4. 填写：
   - **应用名称**：`Gitea Pages`
   - **重定向 URI**：`https://pages.yourdomain.com/oauth/callback`
   - **机密客户端**：**是**（重要！）
5. 复制 **客户端 ID** 和 **客户端密钥**

#### 步骤 2：配置 Deployer

在 `.env` 中设置客户端 ID；客户端密钥必须保存在 `.env.example` 所述的
`OAUTH_CLIENT_SECRET_HOST_FILE` 文件中。Compose 会根据 `DOMAIN` 构造公开回调
和 webhook 地址：
```bash
OAUTH_CLIENT_ID=你的客户端ID
GITEA_PUBLIC_URL=https://gitea.example.com
```

#### 步骤 3：用户授权

1. 访问 `https://pages.yourdomain.com`
2. 点击 **"授权 Gitea Pages"**
3. 登录 Gitea 并批准授权
4. 系统会为已授权的个人和组织范围自动注册独立 webhook

### 权限说明

用户授权 Gitea Pages 时，请求以下权限：

| 权限 | Scope | 用途 |
|------|-------|------|
| 读取用户信息 | `read:user` | 获取用户名以标识站点所有权 |
| 管理用户设置 | `write:user` | 注册个人范围的 webhook |
| 读取仓库 | `read:repository` | 克隆仓库代码进行部署 |
| 管理组织 Webhook | `write:organization` | 通过已批准的管理员 token 池自动注册组织 webhook |

用户可随时在 Gitea **设置 → 应用 → OAuth2 应用** 中撤销授权。
组织 webhook 通过已批准的管理员 token 池默认自动注册。此架构应保持
`ENABLE_ORGANIZATION_HOOKS=true`；只有明确只服务个人范围时才设为 `false`。

### 私有仓库支持

通过 OAuth2 授权，私有仓库自动获得支持。部署时 Deployer 使用用户的 OAuth token 克隆私有仓库。

#### 创建站点

**根目录站点 (username.pages.domain.com)：**
```bash
# 仓库名格式：username.pages.<domain>
git init yourname.pages.example.com
cd yourname.pages.example.com
git checkout -b gh-pages
echo "<html><body>根目录站点</body></html>" > index.html
git add . && git commit -m "初始化站点"
git remote add origin https://gitea.example.com/username/yourname.pages.example.com.git
git push -u origin gh-pages
```
访问地址：`https://username.pages.example.com/`

**子目录站点 (username.pages.domain.com/repo)：**
```bash
git init my-site
cd my-site
git checkout -b gh-pages
echo "<html><body>子目录站点</body></html>" > index.html
git add . && git commit -m "初始化站点"
git remote add origin https://gitea.example.com/username/my-site.git
git push -u origin gh-pages
```
访问地址：`https://username.pages.example.com/my-site`

### 架构图

```
┌─────────────────────────────────────────────────────────────┐
│                         Gitea Server                         │
│    每个 hook 的签名投递 → pages.<DOMAIN>/webhook             │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ Nginx（唯一宿主机端口）→ 私有后端网络 → Deployer              │
│  • /webhook 和 OAuth 路由只经内部 Deployer                   │
│  • Nginx 以只读方式提供 Pages 数据                           │
│  • Deployer 校验每个 hook 的 HMAC 和 Gitea 元数据            │
│  • Deployer 原子发布不可信静态内容                           │
│  • Deployer 没有 Docker socket、SSH 密钥或宿主机端口          │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      已发布的 Pages 卷                       │
│  • 根目录: username.pages.domain → _root/                   │
│  • 子站点: username.pages.domain/repo → repo/               │
└─────────────────────────────────────────────────────────────┘
```

### 安全特性

| 特性 | 实现方式 |
|------|---------|
| 非 root 容器 | UID/GID 1000 (`pagesuser`) |
| 禁止提权 | `security_opt: no-new-privileges:true` |
| 只读根文件系统 | `read_only: true` + tmpfs |
| 阻止软链接 | `disable_symlinks on` + 代码过滤 |
| 路径遍历防护 | 输入净化 |
| 删除 .git 目录 | 自动清理 |
| Webhook 鉴权 | 每个 hook 独立 key 和 HMAC-SHA256 secret；Gitea 元数据为准 |
| 站点大小限制 | `MAX_SITE_SIZE_MB` (默认 100MB) |
| 私有仓库支持 | OAuth2 用户令牌 |
| 网络暴露 | 仅 Nginx 发布端口；Deployer 仅存在于 Compose 私有网络 |

### 目录结构

```
gitea-pages/
├── .env.example           # 环境变量配置
├── docker-compose.yml     # 容器编排
├── nginx/
│   ├── Dockerfile
│   └── nginx.conf
├── deployer/
│   ├── Dockerfile
│   ├── main.go            # 入口
│   ├── handler.go         # Webhook 处理
│   ├── git.go             # Git 操作
│   ├── gitea.go           # Gitea API 客户端
│   ├── oauth.go           # OAuth2 处理
│   ├── web.go             # Web UI
│   └── security.go        # 安全工具函数
└── examples/quickstart/   # 安全部署指南
```

### 测试

```bash
# Go 单元和端到端回归测试
cd deployer && go test -race ./...

# Compose 与 Nginx 隔离检查
cd .. && bash tests/compose_security_test.sh && bash tests/nginx_test.sh
```

### 许可证

MIT License
