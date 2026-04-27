# Vertex AI Proxy (Anonymous)

基于 FastAPI 的 Vertex AI 代理服务，支持将 Google Gemini 匿名接口转为标准 OpenAI 格式。

## 🚀 快速启动

### 使用 Docker (推荐)

1. 克隆并进入目录:
   ```bash
   docker compose up -d --build
   ```
2. 访问管理面板: `http://localhost:2156/admin`
3. 默认管理员密码: 见启动日志 `docker logs vertex-proxy 2>&1 | grep "密码:"`

## 🛠️ 功能特性

- **双标准支持**: 兼容 OpenAI (`/v1/chat/completions`) 和 Gemini 接口格式。
- **Web 面板**: 图形化管理 API Key、Server 设置。
- **出站代理**: 支持面板内粘贴订阅链接或手动设置出站代理（Socks5/Http）。
- **匿名访问**: 无需配置 Google 官方 API Key，自动处理匿名 Token。

## 接入详情

- **API 端口**: 2156
- **默认 Key**: `sk-123456` (可在面板修改)
- **OpenAI Base URL**: `http://<host>:2156/v1`
- **支持模型**: `gemini-1.5-pro`, `gemini-2.0-flash` 等。

## 开源协议
MIT
