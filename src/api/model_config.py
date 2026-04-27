"""模型配置构建器"""

import json
import time
from typing import Any, cast

from src.core import MODELS_CONFIG_FILE
from ..utils.logger import get_logger
from ..utils.string_utils import snake_to_camel

# 初始化日志
logger = get_logger(__name__)


class ModelConfigBuilder:
    """解析模型名称、处理后缀、构建生成配置"""
    
    _cached_map: dict[str, str] | None = None
    _cached_models: list[str] | None = None
    _last_load_time: float = 0
    
    def __init__(self) -> None:
        # 只有在启动阶段打印
        from src.utils.logger import get_request_id
        if not get_request_id():
            logger.info("模型配置构建器初始化完成", extra={
                "model_count": len(self._get_model_map())
            })
    
    def _load_config(self) -> None:
        """从文件加载配置并缓存"""
        current_time = time.time()
        # 缓存 60 秒
        if ModelConfigBuilder._cached_map is not None and current_time - ModelConfigBuilder._last_load_time < 60:
            return
            
        try:
            if not os.path.exists(MODELS_CONFIG_FILE):
                # 如果文件不存在，自动创建一个默认的，避免用户手动配置麻烦
                logger.warning(f"模型配置文件 {MODELS_CONFIG_FILE} 不存在，正在创建默认配置...")
                default_models = {
                    "models": [
                        "gemini-1.5-flash", 
                        "gemini-1.5-pro", 
                        "gemini-2.0-flash-exp", 
                        "gemini-2.0-pro-exp-02-05"
                    ],
                    "alias_map": {}
                }
                os.makedirs(os.path.dirname(MODELS_CONFIG_FILE), exist_ok=True)
                with open(MODELS_CONFIG_FILE, 'w', encoding='utf-8') as f:
                    json.dump(default_models, f, ensure_ascii=False, indent=2)
                logger.success(f"已自动生成默认模型配置文件: {MODELS_CONFIG_FILE}")

            with open(MODELS_CONFIG_FILE, 'r', encoding='utf-8') as f:
                config = json.load(f)
                ModelConfigBuilder._cached_map = cast(dict[str, str], config.get('alias_map', {}))
                ModelConfigBuilder._cached_models = cast(list[str], config.get('models', []))
                ModelConfigBuilder._last_load_time = current_time
                logger.debug("模型配置文件加载成功", extra={
                    "config_file": MODELS_CONFIG_FILE,
                    "alias_count": len(ModelConfigBuilder._cached_map),
                    "model_count": len(ModelConfigBuilder._cached_models)
                })
        except Exception as e:
            logger.error(f"模型配置文件 {MODELS_CONFIG_FILE} 加载失败: {e}", exc_info=True)
            if ModelConfigBuilder._cached_map is None:
                ModelConfigBuilder._cached_map = {}
            if ModelConfigBuilder._cached_models is None:
                ModelConfigBuilder._cached_models = []

    def _get_model_map(self) -> dict[str, str]:
        self._load_config()
        return ModelConfigBuilder._cached_map or {}
    
    def get_available_models(self) -> list[str]:
        """获取所有可用的模型 ID 列表"""
        self._load_config()
        return ModelConfigBuilder._cached_models or []
    
    def parse_model_name(self, model: str) -> str:
        """
        解析模型名称，返回 backend_model
        """
        return self._get_model_map().get(model, model)
    
    def build_generation_config(
        self,
        gen_config: dict[str, Any],
        gemini_payload: dict[str, Any] | None = None,
        **kwargs: Any
    ) -> dict[str, Any]:
        """构建生成配置"""
        # 防止修改原始配置对象
        final_config = gen_config.copy()
        
        # 1. 直接合并用户提供的配置
        if gemini_payload:
            user_gen_config_raw = gemini_payload.get('generationConfig', {}) or gemini_payload.get('generation_config', {})
            if user_gen_config_raw:
                user_gen_config: dict[str, Any] = {}
                # 显式转换为 Dict (如果它是 Pydantic model)
                if hasattr(user_gen_config_raw, 'model_dump'):
                     user_gen_config = user_gen_config_raw.model_dump(exclude_none=True)
                elif isinstance(user_gen_config_raw, dict):
                     user_gen_config = cast(dict[str, Any], user_gen_config_raw)
                
                if user_gen_config:
                    final_config.update(user_gen_config)

        # 1.5 合并 kwargs 中的生成配置参数
        for k, v in kwargs.items():
            # 直接添加所有 kwargs 参数，让转换函数处理驼峰转换
            final_config[k] = v

        # 2. 统一转换为 camelCase (适配 Vertex AI API)
        return self._convert_to_gemini_format(final_config)

    def _convert_to_gemini_format(self, config: dict[str, Any]) -> dict[str, Any]:
        """将 snake_case 配置转换为 camelCase"""
        converted: dict[str, Any] = {}
        for k, v in config.items():
            camel_key = snake_to_camel(k)
            
            # 特殊处理 thinkingConfig 中的 thinkingLevel 值
            if camel_key == "thinkingConfig" and isinstance(v, dict):
                thinking_config: dict[str, Any] = cast(dict[str, Any], v).copy()
                if "thinkingLevel" in thinking_config:
                    # 将小写的 thinking level 转换为大写
                    level = thinking_config["thinkingLevel"]
                    if isinstance(level, str):
                        thinking_config["thinkingLevel"] = level.upper()
                converted[camel_key] = thinking_config
            elif camel_key == "topK" and isinstance(v, (int, float)):
                # topK 最大值为 63，防止 API 报错
                converted[camel_key] = min(63, int(v))
            else:
                converted[camel_key] = v
                
        return converted
    
    def build_safety_settings(self) -> list[dict[str, str]]:
        """构建安全设置"""
        return [
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_CIVIC_INTEGRITY", "threshold": "BLOCK_NONE"}
        ]
