"""OpenAI 兼容适配层

将 OpenAI Chat Completion 格式转换为 Gemini 格式（请求），
将 Gemini SSE 格式转换为 OpenAI 格式（响应）。
"""

import json
import time
import uuid
from typing import Any

from src.utils.logger import get_logger

logger = get_logger(__name__)

FINISH_REASON_MAP = {
    "STOP": "stop",
    "MAX_TOKENS": "length",
    "SAFETY": "content_filter",
    "RECITATION": "content_filter",
}


class OAIRequestConverter:
    """OpenAI → Gemini 请求转换"""

    @staticmethod
    def convert(body: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        """将 OAI ChatCompletion 请求转为 (model, gemini_payload)"""
        model = body["model"]
        messages = body.get("messages", [])

        contents: list[dict[str, Any]] = []
        system_parts: list[dict[str, str]] = []

        for msg in messages:
            role = msg.get("role", "")
            content = msg.get("content")

            if role == "system":
                if isinstance(content, str):
                    system_parts.append({"text": content})
                elif isinstance(content, list):
                    for item in content:
                        if isinstance(item, dict) and item.get("type") == "text":
                            system_parts.append({"text": item["text"]})
                        elif isinstance(item, str):
                            system_parts.append({"text": item})

            elif role == "user":
                parts = _convert_user_content(content)
                if parts:
                    contents.append({"role": "user", "parts": parts})

            elif role == "assistant":
                parts: list[dict[str, Any]] = []
                if content:
                    parts.append({"text": content})
                tool_calls = msg.get("tool_calls")
                if tool_calls:
                    for tc in tool_calls:
                        func = tc.get("function", {})
                        args = func.get("arguments", "{}")
                        try:
                            args_obj = json.loads(args) if isinstance(args, str) else args
                        except json.JSONDecodeError:
                            args_obj = {"raw": args}
                        parts.append({"functionCall": {"name": func.get("name", ""), "args": args_obj}})
                if parts:
                    contents.append({"role": "model", "parts": parts})

            elif role == "tool":
                name = msg.get("name") or msg.get("tool_call_id", "unknown")
                raw = msg.get("content", "")
                try:
                    resp_obj = json.loads(raw) if isinstance(raw, str) else raw
                except json.JSONDecodeError:
                    resp_obj = {"result": raw}
                contents.append({
                    "role": "function",
                    "parts": [{"functionResponse": {"name": name, "response": resp_obj}}]
                })

        gemini_payload: dict[str, Any] = {"contents": contents}

        if system_parts:
            gemini_payload["systemInstruction"] = {"parts": system_parts}

        # tools
        oai_tools = body.get("tools")
        if oai_tools:
            func_decls = []
            for t in oai_tools:
                if t.get("type") == "function":
                    f = t["function"]
                    decl: dict[str, Any] = {"name": f["name"]}
                    if f.get("description"):
                        decl["description"] = f["description"]
                    if f.get("parameters"):
                        decl["parameters"] = f["parameters"]
                    func_decls.append(decl)
            if func_decls:
                gemini_payload["tools"] = [{"functionDeclarations": func_decls}]

        # tool_choice
        tc = body.get("tool_choice")
        if tc:
            if tc == "none":
                gemini_payload["toolConfig"] = {"functionCallingConfig": {"mode": "NONE"}}
            elif tc == "auto":
                gemini_payload["toolConfig"] = {"functionCallingConfig": {"mode": "AUTO"}}
            elif tc == "required":
                gemini_payload["toolConfig"] = {"functionCallingConfig": {"mode": "ANY"}}
            elif isinstance(tc, dict) and tc.get("type") == "function":
                fn_name = tc.get("function", {}).get("name")
                if fn_name:
                    gemini_payload["toolConfig"] = {
                        "functionCallingConfig": {"mode": "ANY", "allowedFunctionNames": [fn_name]}
                    }

        # generationConfig
        gen_cfg: dict[str, Any] = {}
        for oai_key, gemini_key in [
            ("temperature", "temperature"),
            ("top_p", "topP"),
            ("presence_penalty", "presencePenalty"),
            ("frequency_penalty", "frequencyPenalty"),
        ]:
            if oai_key in body and body[oai_key] is not None:
                gen_cfg[gemini_key] = body[oai_key]

        max_tokens = body.get("max_tokens") or body.get("max_completion_tokens")
        if max_tokens is not None:
            gen_cfg["maxOutputTokens"] = max_tokens

        stop = body.get("stop")
        if stop is not None:
            gen_cfg["stopSequences"] = [stop] if isinstance(stop, str) else stop

        rf = body.get("response_format")
        if isinstance(rf, dict):
            rf_type = rf.get("type")
            if rf_type == "json_object":
                gen_cfg["responseMimeType"] = "application/json"
            elif rf_type == "json_schema":
                gen_cfg["responseMimeType"] = "application/json"
                schema = rf.get("json_schema", {}).get("schema")
                if schema:
                    gen_cfg["responseSchema"] = schema

        if gen_cfg:
            gemini_payload["generationConfig"] = gen_cfg

        return model, gemini_payload


class OAIResponseConverter:
    """Gemini → OpenAI 响应转换"""

    @staticmethod
    def convert_realtime_chunk(chunk: dict[str, Any], model: str, request_id: str, is_first: bool) -> list[str]:
        """将单个 Gemini 增量 dict 转为 OAI SSE 事件列表（真流式用）"""
        candidate = (chunk.get("candidates") or [{}])[0] if chunk.get("candidates") else {}
        parts = (candidate.get("content") or {}).get("parts", [])
        finish = candidate.get("finishReason")
        usage_meta = chunk.get("usageMetadata")

        created = int(time.time())
        base = {"id": f"chatcmpl-{request_id}", "object": "chat.completion.chunk", "created": created, "model": model}
        events: list[str] = []

        if is_first:
            events.append(_sse_line({**base, "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}]}))

        text_content, tool_calls, reasoning = _extract_parts(parts)

        if reasoning:
            events.append(_sse_line({**base, "choices": [{"index": 0, "delta": {"reasoning_content": reasoning}, "finish_reason": None}]}))

        if text_content:
            events.append(_sse_line({**base, "choices": [{"index": 0, "delta": {"content": text_content}, "finish_reason": None}]}))

        if tool_calls:
            events.append(_sse_line({**base, "choices": [{"index": 0, "delta": {"tool_calls": tool_calls}, "finish_reason": None}]}))

        # 只在有 finishReason 且没有内容的 chunk 才发 finish（最后一个 chunk）
        if finish and not parts:
            oai_finish = FINISH_REASON_MAP.get(finish, "stop")
            finish_evt: dict[str, Any] = {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": oai_finish}]}
            if usage_meta:
                finish_evt["usage"] = _convert_usage(usage_meta)
            events.append(_sse_line(finish_evt))

        return events

    @staticmethod
    def gemini_sse_to_oai_stream(gemini_chunk: str, model: str, request_id: str) -> list[str]:
        """将单条 Gemini SSE 转为多条 OAI SSE 事件（假流式用）"""
        data = _parse_gemini_sse(gemini_chunk)
        if data is None:
            return []
        return OAIResponseConverter.convert_realtime_chunk(data, model, request_id, is_first=True)

    @staticmethod
    def gemini_json_to_oai_json(gemini_response: dict[str, Any], model: str) -> dict[str, Any]:
        """将 Gemini 非流式响应转为 OAI ChatCompletion JSON"""
        request_id = uuid.uuid4().hex[:24]
        candidate = (gemini_response.get("candidates") or [{}])[0]
        parts = (candidate.get("content") or {}).get("parts", [])
        finish = candidate.get("finishReason")
        usage_meta = gemini_response.get("usageMetadata")

        text_content, tool_calls, reasoning = _extract_parts(parts)
        oai_finish = FINISH_REASON_MAP.get(finish, "stop") if finish else "stop"

        message: dict[str, Any] = {"role": "assistant", "content": text_content or None}
        if tool_calls:
            message["tool_calls"] = tool_calls
        if reasoning:
            message["reasoning_content"] = reasoning

        result: dict[str, Any] = {
            "id": f"chatcmpl-{request_id}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [{"index": 0, "message": message, "finish_reason": oai_finish}],
        }
        if usage_meta:
            result["usage"] = _convert_usage(usage_meta)

        return result


# ==================== 内部工具函数 ====================

def _convert_user_content(content: Any) -> list[dict[str, Any]]:
    """将 OAI user message content 转为 Gemini parts"""
    if content is None:
        return []
    if isinstance(content, str):
        return [{"text": content}]

    parts: list[dict[str, Any]] = []
    if isinstance(content, list):
        for item in content:
            if isinstance(item, str):
                parts.append({"text": item})
            elif isinstance(item, dict):
                t = item.get("type")
                if t == "text":
                    parts.append({"text": item["text"]})
                elif t == "image_url":
                    url = item.get("image_url", {}).get("url", "")
                    if url.startswith("data:"):
                        mime, b64 = _parse_data_uri(url)
                        if mime and b64:
                            parts.append({"inlineData": {"mimeType": mime, "data": b64}})
    return parts


def _parse_data_uri(uri: str) -> tuple[str, str]:
    """解析 data:mime;base64,DATA 格式"""
    try:
        header, data = uri.split(",", 1)
        mime = header.split(":")[1].split(";")[0]
        return mime, data
    except (ValueError, IndexError):
        return "", ""


def _parse_gemini_sse(chunk: str) -> dict[str, Any] | None:
    """从 Gemini SSE 行解析 JSON"""
    s = chunk.strip()
    if s.startswith("data: "):
        s = s[6:]
    if not s:
        return None
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        return None


def _extract_parts(parts: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]] | None, str]:
    """从 Gemini parts 提取 (text_content, tool_calls, reasoning_content)"""
    texts: list[str] = []
    thoughts: list[str] = []
    tool_calls: list[dict[str, Any]] = []

    for i, part in enumerate(parts):
        if part.get("thought") and "text" in part:
            thoughts.append(str(part["text"]))
        elif "text" in part and not part.get("thought"):
            texts.append(str(part["text"]))
        elif "functionCall" in part:
            fc = part["functionCall"]
            tool_calls.append({
                "id": f"call_{uuid.uuid4().hex[:24]}",
                "type": "function",
                "function": {
                    "name": fc.get("name", ""),
                    "arguments": json.dumps(fc.get("args", {}), ensure_ascii=False),
                },
            })

    text_content = "".join(texts)
    reasoning = "".join(thoughts)
    return text_content, tool_calls if tool_calls else None, reasoning


def _convert_usage(meta: dict[str, Any]) -> dict[str, int]:
    """Gemini usageMetadata → OAI usage"""
    prompt = meta.get("promptTokenCount", 0)
    completion = meta.get("candidatesTokenCount", 0)
    return {
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "total_tokens": meta.get("totalTokenCount", prompt + completion),
    }


def _sse_line(obj: dict[str, Any]) -> str:
    return f"data: {json.dumps(obj, ensure_ascii=False)}\n\n"
