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
| Nginx | http://localhost:8080 | - |
| Deployer Health | http://localhost:8080/health | - |

### Access Token Configuration

Access Token is required for auto webhook registration and private repo access.

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
- Root site: http://testuser.pages.local:8080/ (repo: `testuser.pages.local`)
- Sub site: http://testuser.pages.local:8080/test-pages/ (repo: `test-pages`)

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
| Nginx | http://localhost:8080 | - |
| Deployer 健康检查 | http://localhost:8080/health | - |

### Access Token 配置

需要 Access Token 才能自动注册 webhook 和访问私有仓库。

1. 登录 Gitea: http://localhost:3000
2. 进入 **设置 → 应用 → Access Tokens**
3. 创建 token，选择权限: `write:repository`、`write:admin`、`write:user`
4. 添加到 `.env`:
   ```bash
   GITEA_ACCESS_TOKEN=你的token
   ```

### 测试站点

添加到 `/etc/hosts`:
```
127.0.0.1 testuser.pages.local
```

访问：
- 根目录站点: http://testuser.pages.local:8080/ (仓库: `testuser.pages.local`)
- 子目录站点: http://testuser.pages.local:8080/test-pages/ (仓库: `test-pages`)

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