### 角色设定
你现在是一位资深的 DevOps 工程师和安全专家。你的任务是帮我开发一套名为 **"Gitea-Pages-Actionless"** 的自动化部署系统。

### 项目目标
为 Gitea 实现类似早期 GitHub Pages 的全自动静态网站托管功能。
1. **用户零操作**：只要向任意仓库的 `gh-pages` 分支推送代码，就能自动部署上线。
2. **完美路由还原**：
   - 根目录站点：仓库名为 `username.pages.domain.com`，访问 `https://username.pages.domain.com`
   - 子目录站点：仓库名为 `my-repo`，访问 `https://username.pages.domain.com/my-repo`
3. **极致安全性（核心需求）**：禁止直接在宿主机运行代码。必须通过 Docker 容器化运行，彻底防范容器逃逸、恶意脚本执行和软链接越权读取攻击。

---

### 架构设计要求
系统将由一个 `docker-compose.yml` 编排，包含两个核心容器：

1. **Webhook 接收与处理容器 (Deployer Service)**
   - 语言建议：使用 Go 或 Node.js 编写的轻量级 API 服务。
   - 职责：接收 Gitea 的 System Webhook -> 校验分支 -> 执行 `git clone` -> 处理文件存储。
   - 挂载：将宿主机的 `/data/gitea-pages` 目录挂载进容器用于写入文件。
2. **Nginx 静态代理容器 (Web Server)**
   - 职责：利用 `try_files` 正则匹配域名，提供静态文件 HTTP 服务。
   - 挂载：将同样的 `/data/gitea-pages` 目录以 **Read-Only (只读)** 模式挂载进容器。

---

### 第一阶段：Nginx 容器安全与路由配置设计 (需生成 `nginx.conf`)
请编写 Nginx 的配置文件，满足以下要求：
1. **泛域名解析**：使用正则 `server_name ~^(?<username>[^.]+)\.pages\.yourdomain\.com$;` 捕获用户名。
2. **智能路由（Try_Files 魔法）**：
   - 设定网站根目录为 `/var/www/pages/$username`。
   - 匹配规则：先查找子目录 `$uri`，如果找不到，再降级查找 `/_root$uri`（根目录站点的特殊文件夹）。
3. **安全加固（防御重点）**：
   - **禁止软链接**：配置 `disable_symlinks on;`，防止用户推送恶意软链接读取宿主机敏感文件。
   - **目录屏蔽**：禁止外部通过 HTTP 直接访问 `/_root/` 路径和 `/.git/` 隐藏文件夹。
   - **关闭列目录**：`autoindex off;`。

---

### 第二阶段：Deployer Webhook 服务设计 (需生成服务源码)
请编写 Webhook 接收服务的代码（推荐 Go 或轻量级 Node.js/Python），需满足：
1. **接口定义**：监听 `POST /webhook`。
2. **鉴权**：校验 Gitea Webhook 的 Secret（使用 HMAC SHA256 等方式，或简单的自定义 Header Token校验）。
3. **逻辑判断**：
   - 解析 Payload，获取 `repository.owner.username`、`repository.name`、`ref`、`repository.clone_url`。
   - 如果 `ref` 不是 `refs/heads/gh-pages`，返回 200 并忽略操作。
4. **目录计算逻辑**：
   - 判断仓库名：如果是 `${username}.pages.yourdomain.com` 或与 `${username}` 相同，则目标路径为 `/_root`。否则目标路径为 `/${repository.name}`。
5. **安全 Git 操作（防御重点）**：
   - 清空目标目录（如果存在）。
   - 使用 `git clone --branch gh-pages --single-branch --depth 1` 进行浅克隆。
   - **关键清理**：克隆完成后，**必须立即删除**目标目录下的 `.git` 文件夹。
   - **权限剥离**：确保拉取下来的文件权限不包含执行权限（chmod -R 644 / 755）。

---

### 第三阶段：Docker Compose 编排与防逃逸设计 (需生成 `docker-compose.yml` 和 `Dockerfile`)
请编写完整的 `docker-compose.yml` 及构建文件，严格遵循以下防逃逸原则：
1. **非 Root 运行**：两个容器内部都必须创建专用的非特权用户（如 UID/GID 1000 的 `pagesuser`），不允许使用 root 身份运行 Nginx 和 Deployer。
2. **文件系统隔离**：
   - Webhook 容器需要对映射的 Volume 具有读写权限。
   - Nginx 容器对 Volume 必须使用 `ro` (只读) 挂载。
3. **特权剥离**：为容器添加 `security_opt: ["no-new-privileges:true"]`。
4. **只读根文件系统**：尽可能将容器的根文件系统设为只读 `read_only: true`（除日志、缓存等必要目录外）。
5. **网络隔离**：
   - Nginx 容器暴露 80 端口（或通过反向代理网络连接）。
   - Webhook 容器仅暴露指定 Webhook 接收端口，且不需要公网直接访问（可通过你的主 Nginx 或网关代理访问）。

---

### 交付物要求
请一步步为我输出以下内容：
1. **项目目录结构**的规划。
2. **Nginx 配置文件** (`gitea-pages.conf`)。
3. **Webhook 服务的核心代码**（请选择你认为最适合此场景的后端语言并说明理由）。
4. **Dockerfile**（用于打包 Webhook 服务）。
5. **安全加固版的 docker-compose.yml**。
6. 简短的**启动与 Gitea 联调说明**。

请确保代码健壮，包含错误日志处理，可以直接用于生产环境。现在，请开始输出！

