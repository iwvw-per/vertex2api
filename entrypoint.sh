#!/bin/bash
set -e

# 确保配置存放目录存在（Koyeb 无持久化硬盘：每次全新容器，运行时文件自动重建）
mkdir -p /app/config

# 无持久化容器内自动同意运行规则（对应 cmd/vproxy/rules.txt 的当前哈希），
# 避免交互式输入卡住启动。若 rules.txt 变更，需同步更新此哈希。
RULES_HASH="36800adeec862126"
mkdir -p /app/config/state
if ! grep -q "$RULES_HASH" /app/config/state/.rules_agreed 2>/dev/null; then
    echo "[Entrypoint] 写入运行规则同意文件（无交互容器）"
    printf '%s\t%s\n' "$(date -Iseconds)" "$RULES_HASH" > /app/config/state/.rules_agreed
fi
if [ ! -f /app/config/state/agreed-rules-docker.txt ]; then
    echo "$RULES_HASH" > /app/config/state/agreed-rules-docker.txt
fi

# 若未检测到用户的配置文件，则从系统备用区初始化一份默认配置文件
if [ ! -f "$VPROXY_CONFIG" ]; then
    echo "[Entrypoint] 未检测到 config.json，正在初始化默认配置..."
    cp /app/config.example.json "$VPROXY_CONFIG"
fi

if [ ! -f "$VPROXY_API_KEYS" ]; then
    echo "[Entrypoint] 未检测到 api_keys.txt，正在初始化默认密钥..."
    cp /app/api_keys.example.txt "$VPROXY_API_KEYS"
fi

if [ ! -f "$VPROXY_MODELS" ]; then
    echo "[Entrypoint] 未检测到 models.json，正在初始化模型清单..."
    cp /app/models.json "$VPROXY_MODELS"
fi

# 打印无状态部署（Koyeb）的环境变量配置提示
if [ -n "$VPROXY_NODES" ]; then
    COUNT=$(echo "$VPROXY_NODES" | tr ',;|\n\r ' '\n\n\n\n\n' | grep -c '://' || true)
    echo "[Entrypoint] 已通过 VPROXY_NODES 注入节点池（约 $COUNT 个节点）"
else
    echo "[Entrypoint] 提示: 未设置 VPROXY_NODES。无持久化环境请用该环境变量注入节点池（逗号分隔的代理 URI）"
fi
if [ -n "$VPROXY_API_KEYS_ENV" ]; then
    echo "[Entrypoint] 已通过 VPROXY_API_KEYS_ENV 注入 API 密钥"
else
    echo "[Entrypoint] 提示: 未设置 VPROXY_API_KEYS_ENV。可用它注入 'name:sk-xxx:desc' 格式密钥（; 分隔）"
fi
if [ -n "$ADMIN_PASSWORD" ]; then
    echo "[Entrypoint] 已通过 ADMIN_PASSWORD 指定管理后台密码"
else
    echo "[Entrypoint] 提示: 未设置 ADMIN_PASSWORD，首次启动将自动生成密码并打印到日志"
fi
if [ -n "$PORT" ]; then
    echo "[Entrypoint] 监听端口由 PORT 环境变量控制: $PORT"
fi

# 使用 exec 确保系统信号能够直接透传给 Go 程序，支持 SIGHUP 配置热重载
echo "[Entrypoint] 启动 Vertex AI Proxy 服务..."
exec /app/vproxy