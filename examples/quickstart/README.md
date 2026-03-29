# Gitea Pages Quickstart / 快速开始

[English](#english) | [中文](#中文)

---

<a name="english"></a>

## English

Complete test environment including Gitea, Deployer, and Nginx.

### Quick Start

```bash
chmod +x *.sh
./test.sh
```

### Services After Startup

| Service | URL | Credentials |
|---------|-----|-------------|
| Gitea | http://localhost:3000 | `testuser` / `testpassword123` |
| Deployer UI | http://localhost:8080 | - |
| Nginx (Sites) | http://localhost:8888 | - |

### OAuth2 Configuration (Recommended)

Users can self-authorize to enable automatic webhook registration:

1. **Create OAuth2 Application in Gitea:**
   - Login to Gitea: http://localhost:3000
   - Go to **Settings → Applications → OAuth2 Applications**
   - Click **Create OAuth2 Application**
   - Fill in:
     - Application Name: `Gitea Pages`
     - Redirect URI: `http://localhost:8080/oauth/callback`
     - **Confidential Client: YES** (Important!)
   - Copy Client ID and Client Secret

2. **Configure `.env`:**
   ```bash
   OAUTH_CLIENT_ID=your-client-id
   OAUTH_CLIENT_SECRET=your-client-secret
   OAUTH_REDIRECT_URL=http://localhost:8080/oauth/callback
   WEBHOOK_PUBLIC_URL=http://deployer:8080/webhook
   GITEA_PUBLIC_URL=http://localhost:3000
   ```

3. **Restart deployer:**
   ```bash
   docker compose up -d
   ```

4. **Authorize:**
   - Visit http://localhost:8080
   - Click "Authorize Gitea Pages"
   - Login and approve

### Permission Explanation

| Permission | Purpose |
|------------|---------|
| Read User Info | Get username to identify site ownership |
| Read Repositories | Clone repository code for deployment |
| Manage Webhooks | Auto-register webhooks for push/delete events |

Users can revoke authorization in Gitea **Settings → Applications → OAuth2 Applications**.

### Legacy Mode: Access Token

Alternatively, configure a shared access token:

1. Login to Gitea: http://localhost:3000
2. Go to **Settings → Applications → Access Tokens**
3. Create token with scopes: `write:repository`, `write:admin`, `write:user`
4. Add to `.env`:
   ```bash
   GITEA_ACCESS_TOKEN=your-token
   ```

### Test Sites

Add to `/etc/hosts`:
```
127.0.0.1 testuser.pages.local
```

Access:
- Root site: http://testuser.pages.local:8888/ (repo: `testuser.pages.local`)
- Sub site: http://testuser.pages.local:8888/test-pages/ (repo: `test-pages`)

### Available Scripts

| Script | Description |
|--------|-------------|
| `test.sh` | Complete test flow (first run) |
| `cleanup.sh` | Stop containers and clean up |

### test.sh Subcommands

```bash
./test.sh setup-gitea     # Create user and token
./test.sh create-webhook  # Create system webhook
./test.sh create-repo     # Create test repository
./test.sh trigger         # Trigger deployment
./test.sh verify          # Verify deployment
```

---

<a name="中文"></a>

## 中文

完整的测试环境，包含 Gitea、Deployer 和 Nginx。

### 快速开始

```bash
chmod +x *.sh
./test.sh
```

### 启动后的服务

| 服务 | 地址 | 凭据 |
|------|------|------|
| Gitea | http://localhost:3000 | `testuser` / `testpassword123` |
| Deployer UI | http://localhost:8080 | - |
| Nginx (站点) | http://localhost:8888 | - |

### OAuth2 配置（推荐）

用户可以自助授权，启用自动 webhook 注册：

1. **在 Gitea 创建 OAuth2 应用：**
   - 登录 Gitea: http://localhost:3000
   - 进入 **设置 → 应用 → OAuth2 应用**
   - 点击 **创建 OAuth2 应用**
   - 填写：
     - 应用名称：`Gitea Pages`
     - 重定向 URI：`http://localhost:8080/oauth/callback`
     - **机密客户端：是**（重要！）
   - 复制客户端 ID 和客户端密钥

2. **配置 `.env`：**
   ```bash
   OAUTH_CLIENT_ID=你的客户端ID
   OAUTH_CLIENT_SECRET=你的客户端密钥
   OAUTH_REDIRECT_URL=http://localhost:8080/oauth/callback
   WEBHOOK_PUBLIC_URL=http://deployer:8080/webhook
   GITEA_PUBLIC_URL=http://localhost:3000
   ```

3. **重启 deployer：**
   ```bash
   docker compose up -d
   ```

4. **授权：**
   - 访问 http://localhost:8080
   - 点击"授权 Gitea Pages"
   - 登录并批准

### 权限说明

| 权限 | 用途 |
|------|------|
| 读取用户信息 | 获取用户名以标识站点所有权 |
| 读取仓库 | 克隆仓库代码进行部署 |
| 管理 Webhook | 自动注册推送/删除事件的 webhook |

用户可随时在 Gitea **设置 → 应用 → OAuth2 应用** 中撤销授权。

### 传统模式：Access Token

或者，配置共享 access token：

1. 登录 Gitea: http://localhost:3000
2. 进入 **设置 → 应用 → Access Tokens**
3. 创建 token，选择权限: `write:repository`、`write:admin`、`write:user`
4. 添加到 `.env`：
   ```bash
   GITEA_ACCESS_TOKEN=你的token
   ```

### 测试站点

添加到 `/etc/hosts`:
```
127.0.0.1 testuser.pages.local
```

访问：
- 根目录站点: http://testuser.pages.local:8888/ (仓库: `testuser.pages.local`)
- 子目录站点: http://testuser.pages.local:8888/test-pages/ (仓库: `test-pages`)

### 可用脚本

| 脚本 | 说明 |
|------|------|
| `test.sh` | 完整测试流程（首次运行） |
| `cleanup.sh` | 停止容器并清理环境 |

### test.sh 子命令

```bash
./test.sh setup-gitea     # 创建用户和 token
./test.sh create-webhook  # 创建系统 webhook
./test.sh create-repo     # 创建测试仓库
./test.sh trigger         # 触发部署
./test.sh verify          # 验证部署
```