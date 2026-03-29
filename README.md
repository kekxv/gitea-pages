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
- **Auto Webhook Registration**: Users authorize once, webhooks auto-registered for all repos

### Quick Start

#### Using Pre-built Images (Recommended)

```bash
# Create docker-compose.yml
curl -O https://raw.githubusercontent.com/kekxv/gitea-pages/main/docker-compose.yml
curl -O https://raw.githubusercontent.com/kekxv/gitea-pages/main/.env.example
cp .env.example .env
# Edit .env with your settings

# Pull and run
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
docker-compose up -d --build
```

### OAuth2 Configuration (Recommended)

Users can self-authorize to enable automatic webhook registration and private repo access.

#### Step 1: Create OAuth2 Application in Gitea

1. Login to Gitea
2. Go to **Settings → Applications → OAuth2 Applications**
3. Click **Create OAuth2 Application**
4. Fill in:
   - **Application Name**: `Gitea Pages`
   - **Redirect URI**: `http://your-deployer-host:8080/oauth/callback`
   - **Confidential Client**: **YES** (Important!)
5. Copy **Client ID** and **Client Secret**

#### Step 2: Configure Deployer

Add to `.env`:
```bash
OAUTH_CLIENT_ID=your-client-id
OAUTH_CLIENT_SECRET=your-client-secret
OAUTH_REDIRECT_URL=http://your-deployer-host:8080/oauth/callback
WEBHOOK_PUBLIC_URL=http://deployer:8080/webhook
GITEA_PUBLIC_URL=http://your-gitea-host:3000
```

#### Step 3: User Authorization

1. Visit `http://your-deployer-host:8080`
2. Click **"Authorize Gitea Pages"**
3. Login to Gitea and approve the authorization
4. Webhooks are automatically registered for all your repositories

### Permission Explanation

When users authorize Gitea Pages, the following permissions are requested:

| Permission | Scope | Purpose |
|------------|-------|---------|
| Read User Info | `read:user` | Get username to identify site ownership |
| Manage User Settings | `write:user` | Register user-level webhooks for all personal repos |
| Read Repositories | `read:repository` | Clone repository code for deployment |
| Manage Repository Webhooks | `write:repository` | Auto-register webhooks for push/delete events |
| Manage Organization Webhooks | `write:organization` | Register org-level webhooks for all org repos |

Users can revoke authorization anytime in Gitea **Settings → Applications → OAuth2 Applications**.

### Private Repository Support

With OAuth2 authorization, private repositories are automatically supported. The deployer uses the user's OAuth token to clone private repos when deploying their sites.

### Legacy Mode: Shared Access Token

Alternatively, you can use a shared access token (less secure, requires manual user management):

1. Create a `pages-bot` user in Gitea
2. Generate an Access Token with `write:repository`, `write:admin`, `write:user` scopes
3. Users add `pages-bot` as collaborator to their repos
4. Configure in `.env`:
   ```bash
   GITEA_ACCESS_TOKEN=pages-bot-token
   GITEA_API_URL=https://gitea.example.com
   ```

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
│  [Push to gh-pages] → [Webhook] → POST /webhook             │
│  [Delete gh-pages] → [Webhook] → POST /webhook (delete)     │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Deployer Container                        │
│  • Verify HMAC-SHA256 signature                             │
│  • Filter gh-pages branch only                              │
│  • git clone --single-branch --depth 1                      │
│  • Remove .git directory                                    │
│  • Set permissions 644/755                                  │
│  • Block symlinks                                           │
│  • OAuth2 user authorization                                │
│  • Auto-register webhooks for authorized users              │
│  • Delete site on branch deletion                           │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Nginx Container                           │
│  • Wildcard domain routing                                  │
│  • Root site: username.pages.domain → _root/                │
│  • Sub site: username.pages.domain/repo → repo/             │
│  • Security: disable_symlinks, block /.git                  │
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
| Webhook signature | HMAC-SHA256 verification |
| Site size limit | `MAX_SITE_SIZE_MB` (default 100MB) |
| Private repo support | OAuth2 user tokens |

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
│   ├── auto_register.go   # Auto webhook registration
│   └── security.go        # Security utilities
└── examples/quickstart/   # Complete test environment
```

### Testing

```bash
# Unit tests
cd deployer && go test -v ./...

# Integration test environment
cd examples/quickstart
./test.sh
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
- **自动注册 Webhook**：用户授权一次，自动为所有仓库注册 webhook

### 快速开始

#### 使用预构建镜像（推荐）

```bash
# 创建 docker-compose.yml
curl -O https://raw.githubusercontent.com/kekxv/gitea-pages/main/docker-compose.yml
curl -O https://raw.githubusercontent.com/kekxv/gitea-pages/main/.env.example
cp .env.example .env
# 编辑 .env 填入你的配置

# 拉取并运行
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
docker-compose up -d --build
```

### OAuth2 配置（推荐）

用户可以自助授权，启用自动 webhook 注册和私有仓库访问。

#### 步骤 1：在 Gitea 创建 OAuth2 应用

1. 登录 Gitea
2. 进入 **设置 → 应用 → OAuth2 应用**
3. 点击 **创建 OAuth2 应用**
4. 填写：
   - **应用名称**：`Gitea Pages`
   - **重定向 URI**：`http://your-deployer-host:8080/oauth/callback`
   - **机密客户端**：**是**（重要！）
5. 复制 **客户端 ID** 和 **客户端密钥**

#### 步骤 2：配置 Deployer

添加到 `.env`：
```bash
OAUTH_CLIENT_ID=你的客户端ID
OAUTH_CLIENT_SECRET=你的客户端密钥
OAUTH_REDIRECT_URL=http://your-deployer-host:8080/oauth/callback
WEBHOOK_PUBLIC_URL=http://deployer:8080/webhook
GITEA_PUBLIC_URL=http://your-gitea-host:3000
```

#### 步骤 3：用户授权

1. 访问 `http://your-deployer-host:8080`
2. 点击 **"授权 Gitea Pages"**
3. 登录 Gitea 并批准授权
4. Webhook 自动为你所有仓库注册

### 权限说明

用户授权 Gitea Pages 时，请求以下权限：

| 权限 | Scope | 用途 |
|------|-------|------|
| 读取用户信息 | `read:user` | 获取用户名以标识站点所有权 |
| 管理用户设置 | `write:user` | 注册用户级 webhook，覆盖所有个人仓库 |
| 读取仓库 | `read:repository` | 克隆仓库代码进行部署 |
| 管理仓库 Webhook | `write:repository` | 自动注册推送/删除事件的 webhook |
| 管理组织 Webhook | `write:organization` | 注册组织级 webhook，覆盖组织下所有仓库 |

用户可随时在 Gitea **设置 → 应用 → OAuth2 应用** 中撤销授权。

### 私有仓库支持

通过 OAuth2 授权，私有仓库自动获得支持。部署时 Deployer 使用用户的 OAuth token 克隆私有仓库。

### 传统模式：共享 Access Token

或者，可以使用共享的 access token（安全性较低，需要手动管理用户）：

1. 在 Gitea 创建 `pages-bot` 用户
2. 生成具有 `write:repository`、`write:admin`、`write:user` 权限的 Access Token
3. 用户将 `pages-bot` 添加为协作者
4. 在 `.env` 中配置：
   ```bash
   GITEA_ACCESS_TOKEN=pages-bot-token
   GITEA_API_URL=https://gitea.example.com
   ```

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
│  [推送 gh-pages] → [Webhook] → POST /webhook                │
│  [删除 gh-pages] → [Webhook] → POST /webhook (delete)      │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Deployer 容器                             │
│  • HMAC-SHA256 签名验证                                      │
│  • 仅处理 gh-pages 分支                                      │
│  • git clone --single-branch --depth 1 浅克隆               │
│  • 删除 .git 目录                                           │
│  • 设置权限 644/755                                         │
│  • 阻止软链接                                               │
│  • OAuth2 用户授权                                          │
│  • 为授权用户自动注册 webhook                                │
│  • 分支删除时自动清理站点                                   │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Nginx 容器                                │
│  • 泛域名路由                                               │
│  • 根目录站点: username.pages.domain → _root/               │
│  • 子目录站点: username.pages.domain/repo → repo/           │
│  • 安全: disable_symlinks, 屏蔽 /.git                       │
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
| Webhook 签名验证 | HMAC-SHA256 |
| 站点大小限制 | `MAX_SITE_SIZE_MB` (默认 100MB) |
| 私有仓库支持 | OAuth2 用户令牌 |

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
│   ├── auto_register.go   # 自动注册 webhook
│   └── security.go        # 安全工具函数
└── examples/quickstart/   # 完整测试环境
```

### 测试

```bash
# 单元测试
cd deployer && go test -v ./...

# 集成测试环境
cd examples/quickstart
./test.sh
```

### 许可证

MIT License
