# Gitea Pages Examples / 示例

[English](#english) | [中文](#中文)

---

<a name="english"></a>

## English

This directory contains test examples for Gitea Pages.

### quickstart

Complete test environment with one-click startup of Gitea + Deployer + Nginx.

```bash
cd quickstart
./test.sh
```

After running, you will have:
- **Gitea**: http://localhost:3000 (user: `testuser`, password: `testpassword123`)
- **Nginx**: http://localhost:8080
- **Deployer Health**: http://localhost:8080/health

#### Available Commands

| Command | Description |
|---------|-------------|
| `./test.sh` | Run complete test flow (first time) |
| `./test.sh setup-gitea` | Setup Gitea user and token |
| `./test.sh create-webhook` | Create system-wide webhook |
| `./test.sh create-repo` | Create test repository |
| `./test.sh trigger` | Trigger deployment |
| `./test.sh verify` | Verify deployment |
| `./cleanup.sh` | Clean up environment |

---

<a name="中文"></a>

## 中文

本目录包含 Gitea Pages 的测试示例。

### quickstart

完整的测试环境，一键启动 Gitea + Deployer + Nginx。

```bash
cd quickstart
./test.sh
```

运行后你将获得：
- **Gitea**: http://localhost:3000 (用户名: `testuser`, 密码: `testpassword123`)
- **Nginx**: http://localhost:8080
- **Deployer 健康检查**: http://localhost:8080/health

#### 可用命令

| 命令 | 说明 |
|------|------|
| `./test.sh` | 运行完整测试流程（首次运行） |
| `./test.sh setup-gitea` | 设置 Gitea 用户和 token |
| `./test.sh create-webhook` | 创建系统级 webhook |
| `./test.sh create-repo` | 创建测试仓库 |
| `./test.sh trigger` | 触发部署 |
| `./test.sh verify` | 验证部署 |
| `./cleanup.sh` | 清理环境 |