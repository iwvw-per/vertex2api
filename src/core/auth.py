"""API密钥认证模块 - 简化版"""

import os
import threading
from typing import Any
from pathlib import Path
from ..utils.logger import get_logger

# 初始化日志
logger = get_logger(__name__)

class APIKeyManager:
    """简化的API密钥管理器 - 只保留基本验证功能"""

    def __init__(self, keys_file: str | None = None):
        logger.info("初始化 API 密钥管理器")
        
        self.keys_file: str = keys_file or str(Path(__file__).parent.parent.parent / "config" / "api_keys.txt")
        self.api_keys: set[str] = set()
        self.key_names: dict[str, str] = {}  # api_key -> name
        self._lock: threading.Lock = threading.Lock()
        
        logger.debug(f"API 密钥文件路径: {self.keys_file}")

    def load_keys(self) -> bool:
        """从配置文件和环境变量加载API密钥"""
        logger.info("开始加载 API 密钥")
        
        with self._lock:
            self.api_keys.clear()
            self.key_names.clear()
            
            valid_count = 0
            error_count = 0

            # 1. 从环境变量加载
            env_keys = os.environ.get("API_KEYS", "").strip()
            if env_keys:
                logger.info("正在从环境变量 API_KEYS 加载密钥")
                # 支持 comma 分隔的 name:key 或 纯 key
                for part in env_keys.split(","):
                    part = part.strip()
                    if not part:
                        continue
                    
                    if ":" in part:
                        name, key = part.split(":", 1)
                        name = name.strip()
                        key = key.strip()
                    else:
                        key = part
                        name = f"env_key_{valid_count + 1}"
                    
                    if key:
                        self.api_keys.add(key)
                        self.key_names[key] = name
                        valid_count += 1
                        logger.debug(f"从环境变量加载密钥: {name} ({key[:8]}...)")

            # 2. 从文件加载
            if os.path.exists(self.keys_file):
                logger.debug(f"读取密钥文件: {self.keys_file}")
                try:
                    with open(self.keys_file, 'r', encoding='utf-8') as f:
                        for line_num, line in enumerate(f, 1):
                            line = line.strip()

                            # 跳过空行和注释行
                            if not line or line.startswith('#'):
                                continue

                            # 解析格式: key_name:api_key:description
                            parts = line.split(':', 2)
                            if len(parts) < 2:
                                logger.warning(f"第 {line_num} 行格式错误，跳过")
                                error_count += 1
                                continue

                            key_name = parts[0].strip()
                            api_key = parts[1].strip()

                            # 如果已从环境变量加载，文件中的同名或同 key 会被覆盖/合并
                            self.api_keys.add(api_key)
                            self.key_names[api_key] = key_name
                            valid_count += 1
                            logger.debug(f"从文件加载密钥: {key_name} ({api_key[:8]}...)")
                except Exception as e:
                    logger.error(f"读取密钥文件失败: {e}")
            else:
                if not env_keys:
                    logger.warning(f"API 密钥文件不存在且未设置环境变量: {self.keys_file}")

            if valid_count > 0:
                logger.success(f"成功加载 {valid_count} 个 API 密钥")
            if error_count > 0:
                logger.warning(f"跳过 {error_count} 个无效条目")
                
            return valid_count > 0

    def validate_key(self, api_key: str) -> bool:
        """验证API密钥是否有效"""
        if not api_key:
            logger.debug("API 密钥为空")
            return False

        is_valid = api_key.strip() in self.api_keys
        if is_valid:
            key_name = self.key_names.get(api_key.strip(), 'unknown')
            logger.debug(f"API 密钥验证成功: {key_name} ({api_key[:8]}...)")
        else:
            logger.debug(f"API 密钥验证失败: {api_key[:8]}...")
            
        return is_valid


# 全局密钥管理器实例
api_key_manager = APIKeyManager()
