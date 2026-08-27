# Vertex AI Proxy

免费使用 Google Gemini 模型的代理工具。将 **OpenAI 兼容的 API 请求**无缝转换为对 Google 匿名端点的调用——让你的客户端以为在调用 OpenAI，实际上使用的是免费的 Gemini 服务。也支持原始Gemini格式

**免安装、解压即用的绿色软件。** 全面支持 Windows、Linux、macOS 以及 Android 手机等平台。

## ✨ 核心特性

- **完整兼容 OpenAI 接口**：支持聊天（流式/非流式）、工具调用（Function Calling）、多模态输入（图片/文件）。
- **丰富的多媒体支持**：支持文生图、图片编辑、语音合成（TTS）。
- **内置反爬突破**：内置 TLS 指纹伪装及 reCAPTCHA token 自动获取，轻松通过 Google 匿名端点校验。
- **内置代理节点池**：内嵌 mihomo 内核，支持批量导入订阅和节点，提供并发竞速功能，有效应对429
- **可视化管理面板**：提供精美的 Web 后台，无需修改 JSON 文件，在浏览器中即可轻松管理 API 密钥、模型别名、代理节点和系统设置。
- **高级功能**：支持 Token 计数、Gemini 原生端点透传等。

## 🚀 三步上手

**1. 下载解压**：下载对应平台的压缩包并解压到任意位置。

**2. 一键启动**：
- **Windows**：双击运行 `启动.bat`
- **Linux/macOS**：终端执行 `sh start.sh`
- **Android (Termux)**：终端执行 `sh start.sh`

**3. 配置密钥**：
首次启动时控制台会输出**管理员密码**。使用浏览器访问 `http://127.0.0.1:2156/admin/` 登录管理面板。
进入左侧「密钥」菜单，添加一个自定义的 API Key（如 `sk-mykey123`），必须以 `sk-` 开头，或点击“✨”按钮随机生成。

> **如何使用？**
> 在你的客户端（如 Cherry Studio、ChatBox 等）中，将 API Key 填为刚才设置的 `sk-...`，API 地址填为 `http://127.0.0.1:2156/v1` 即可开始使用！

**完整的分平台部署教程**（包括开机自启、代理配置、手机部署、常见问题解答）见 **[部署指南](部署指南.md)**。

## 🛠 自己编译（可选）

如果你想从源码自行编译：

```bash
go build -o vertex-proxy ./cmd/vproxy
go build -o vertex-proxy.exe ./cmd/vproxy
```

交叉编译示例（例如在 macOS/Windows 上编译 Linux 适用版本）：
```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o vertex-proxy ./cmd/vproxy
```

## ⚙️ 配置说明

强烈建议直接使用**管理面板**的「设置」页进行配置修改，所有修改即时生效，无需重启。
如果需要手动修改，配置文件路径为 `config/config.json`：

| 选项 | 默认值 | 说明 |
|------|------|------|
| `port_api` | 2156 | 服务监听端口 |
| `admin_password` | 自动生成 | 管理面板登录密码 |
| `max_retries` | 10 | 请求失败重试次数 |
| `proxy_url` | 空 | 全局入口代理；业务节点启用时作为第一跳，否则单独出站 |
| `proxy_url_candidates` | `[]` | 由管理页维护的入口代理候选、测速结果和显示名称 |
| `parallel_pool_enabled` | true | 是否开启并发竞速节点池 |

详细配置说明请参阅 [部署指南](部署指南.md#配置怎么改)。

## ☁️ Koyeb（无持久化硬盘容器）部署

Koyeb 容器没有持久化磁盘，每次部署/重启都是全新环境。本项目已适配无状态启动，全部通过环境变量注入：

| 环境变量 | 说明 | 示例 |
|---|---|---|
| `VPROXY_NODES` | **必填**。节点池代理 URI，逗号/分号分隔（启动时自动导入，否则无节点） | `http://Default.slot1:pass@host:2260,http://Default.slot3:pass@host:2260` |
| `VPROXY_API_KEYS_ENV` | **必填**。API 密钥，`name:sk-xxx:desc` 格式，分号分隔 | `k1:sk-hello123:desc` |
| `ADMIN_PASSWORD` | 管理后台密码（不设则每次启动自动生成并打印到日志） | `my-secret-pw` |
| `PORT` | 监听端口（Koyeb 会自动注入） | `8080` |

部署要点：

1. **构建方式**：Koyeb 选择 Docker build（仓库根 `Dockerfile`）。
2. **健康检查**：`GET /health` 免鉴权返回 `200`，可直接作为 Koyeb 健康检查路径。
3. **无状态自动初始化**：入口脚本自动完成规则同意、配置文件初始化；`data.db`（节点健康状态）每次重建，节点池依赖 `VPROXY_NODES`。
4. **日志**：`logs/` 非持久化，建议对接 Koyeb 日志收集。

> 本地/自建部署则无需这些环境变量：配置写在 `config/config.json`，节点通过管理面板或 `config/data.db` 维护。

