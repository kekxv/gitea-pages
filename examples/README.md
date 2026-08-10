# Gitea Pages examples / 示例

The runnable all-in-one example was retired with the hardened architecture.
It formerly exposed Deployer directly and used credential handling that the
current runtime intentionally rejects.

For deployment, use the repository-root `docker-compose.yml` and
`.env.example`. Nginx is the sole public entry point; Deployer is private to
the Compose networks and reads only file-mounted secrets. `DOMAIN` is the
complete Pages domain; the OAuth callback and webhook target are
`https://<DOMAIN>/oauth/callback` and `https://<DOMAIN>/webhook`.

See the [hardened deployment guide](quickstart/README.md) for setup and
offline-migration instructions, and use the root `tests/` scripts for
repository validation.

---

可运行的一体化示例已随加固架构退役。它曾直接暴露 Deployer，并使用当前运行时
有意拒绝的凭据处理方式。

部署时请使用仓库根目录的 `docker-compose.yml` 和 `.env.example`。Nginx 是唯一的
公网入口；Deployer 仅存在于 Compose 私有网络，并且只读取文件挂载的密钥。`DOMAIN`
是完整 Pages 域名；OAuth 回调和 webhook 目标分别是
`https://<DOMAIN>/oauth/callback` 与 `https://<DOMAIN>/webhook`。

请参阅[安全部署指南](quickstart/README.md)了解配置和离线迁移，并使用根目录的
`tests/` 脚本验证仓库。
