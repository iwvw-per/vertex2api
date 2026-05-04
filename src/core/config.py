"""配置加载"""

import json
import os
from typing import Any, cast
from pathlib import Path
from src.utils.logger import get_logger
from .types import AppConfig

# 初始化日志
logger = get_logger(__name__)

CONFIG_FILE = str(Path(__file__).parent.parent.parent / "config" / "config.json")

def load_config() -> dict[str, Any]:
    """加载配置文件，支持环境变量覆盖"""
    default_config = AppConfig()
    config_dict = default_config.model_dump()
    
    # 1. 加载配置文件
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                file_config = json.load(f)
                config_dict.update(file_config)
        except Exception as e:
            logger.error(f"配置文件加载失败: {e}", extra={"config_file": CONFIG_FILE})
    else:
        logger.debug("配置文件不存在，使用默认值和环境变量", extra={"config_file": CONFIG_FILE})

    # 2. 环境变量覆盖 (优先级最高)
    # PORT_API
    env_port = os.environ.get("PORT_API")
    if env_port and env_port.isdigit():
        config_dict["port_api"] = int(env_port)
    
    # DEBUG
    env_debug = os.environ.get("DEBUG", "").lower()
    if env_debug in ("true", "1", "yes"):
        config_dict["debug"] = True
    elif env_debug in ("false", "0", "no"):
        config_dict["debug"] = False
        
    # PROXY_URL
    env_proxy = os.environ.get("PROXY_URL", "").strip()
    if env_proxy:
        config_dict["proxy_url"] = env_proxy
        
    # ADMIN_PASSWORD
    env_pw = os.environ.get("ADMIN_PASSWORD", "").strip()
    if env_pw:
        config_dict["admin_password"] = env_pw

    try:
        # 验证并创建模型实例
        final_config = AppConfig(**config_dict)
        final_dict = final_config.model_dump()
        
        # 只有在没有请求上下文时（即启动时）打印加载日志
        from src.utils.logger import get_request_id
        if not get_request_id():
            logger.info("配置加载成功", extra={
                "port_api": final_dict.get("port_api"),
                "debug_mode": final_dict.get("debug"),
                "has_config_file": os.path.exists(CONFIG_FILE)
            })
        return final_dict
            
    except Exception as e:
        logger.error(f"配置验证失败: {e}")
        return config_dict
