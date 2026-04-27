# Vertex AI Proxy (Anonymous)

基于 FastAPI 的 Vertex AI 代理服务，支持将 Google Gemini 匿名接口转为标准 OpenAI 格式。

## 🚀 快速启动

直接使用 `docker-compose.yml` 运行：

```yaml
services:
  vertex:
    image: iwvw/vertex2api:main
    container_name: vertex2api
    restart: unless-stopped
    ports:
      - "2156:2156"
    environment:
      - ADMIN_PASSWORD=your_secure_password
    volumes:
      - ./config:/app/config
```

### 说明

1. **管理面板**: `http://<ip>:2156/admin`
2. **管理员密码**: 优先从 `ADMIN_PASSWORD` 环境变量读取。若未设置，则第一次启动时会随机生成并打印在日志中：
   ```bash
   docker logs vertex-proxy 2>&1 | grep "密码:"
   ```
3. **API 地址**: `http://<ip>:2156/v1`

## 开源协议

MIT
