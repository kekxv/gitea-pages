# Gitea Pages - Actionless Static Site Hosting

[![Build and Push Docker Images](https://github.com/kekxv/gitea-pages/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/kekxv/gitea-pages/actions/workflows/docker-publish.yml)
[![Deployer Image](https://img.shields.io/badge/ghcr.io%2Fkekxv%2Fgitea-pages%2Fdeployer-latest-blue)](https://github.com/kekxv/gitea-pages/pkgs/container/deployer)
[![Nginx Image](https://img.shields.io/badge/ghcr.io%2Fkekxv%2Fgitea-pages%2Fnginx-latest-blue)](https://github.com/kekxv/gitea-pages/pkgs/container/nginx)

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
- **Private Repo Support**: Access Token authentication
- **Auto Webhook Registration**: Automatically registers webhooks for all repositories

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

#### Configure Environment

After starting services, configure Gitea Access Token:

```bash
cp .env.example .env
# Edit .env with your settings
```

Key settings:
- `DOMAIN`: Your domain (e.g., `example.com`)
- `WEBHOOK_SECRET`: Secret for Gitea webhook verification
- `GITEA_ACCESS_TOKEN`: Token for private repos and auto webhook registration
- `GITEA_API_URL`: Your Gitea server URL

Then restart deployer to apply:

```bash
docker compose up -d
```

#### Configure Gitea Access Token

1. Login to Gitea
2. Go to **Settings → Applications → Access Tokens**
3. Create token with `write:repository`, `write:admin`, `write:user` scopes
4. Add to `.env`:
   ```bash
   GITEA_ACCESS_TOKEN=your-token
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
│  • Auto-register webhooks on startup                        │
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
| Private repo support | Access Token authentication |

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
- **私有仓库支持**：Access Token 认证
- **自动注册 Webhook**：启动时自动为所有仓库注册 webhook

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

#### 配置环境变量

启动服务后，配置 Gitea Access Token：

```bash
cp .env.example .env
# 编辑 .env 填入你的配置
```

关键配置：
- `DOMAIN`：你的域名（如 `example.com`）
- `WEBHOOK_SECRET`：Gitea webhook 验证密钥
- `GITEA_ACCESS_TOKEN`：用于私有仓库和自动注册 webhook
- `GITEA_API_URL`：Gitea 服务器地址

然后重启 deployer 使配置生效：

```bash
docker compose up -d
```

#### 配置 Gitea Access Token

1. 登录 Gitea
2. 进入 **设置 → 应用 → Access Tokens**
3. 创建 token，选择 `write:repository`、`write:admin`、`write:user` 权限
4. 添加到 `.env`：
   ```bash
   GITEA_ACCESS_TOKEN=your-token
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
│  • 启动时自动注册 webhook                                   │
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
| 私有仓库支持 | Access Token 认证 |

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