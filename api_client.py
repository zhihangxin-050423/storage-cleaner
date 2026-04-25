"""
api_client.py - 统一 HTTP 客户端层

移植自 claude-code-best 的核心设计思路：
  - src/services/api/withRetry.ts  — 应用层重试、指数退避 + jitter、529 独立上限
  - src/services/api/errorUtils.ts — SSL 错误码链遍历、HTML 错误页脱敏
  - src/services/api/errors.ts     — API 错误分类、上下文溢出解析
  - src/services/api/client.ts     — x-client-request-id 请求追踪注入

关键移植要点：
1. 异常分类体系含 OverloadedError (529) 专用类（源自 withRetry.ts is529Error）
2. x-client-request-id 注入，每请求生成 UUID，与 request_id 关联排障
3. SSL 错误码枚举 + 异常因果链遍历（Python __cause__/__context__，对应 TS cause 链）
4. HTML 错误页脱敏（CloudFlare / 网关错误页提取 <title>，对应 sanitizeMessageHTML）
5. 上下文溢出解析（"prompt is too long: X tokens > Y maximum"，对应 parsePromptTooLongTokenCounts）
6. RetryClient：BASE_DELAY_S * 2^attempt + jitter，MAX_529_RETRIES 独立封顶
7. Retry-After 响应头解析，优先遵从服务端指示（对应 getRetryAfterMs）
8. 不可重试错误（401/403/404）立即终止，不消耗重试配额
9. maxRetries=0 on SDK / 应用层接管重试 —— 与 claude-code-best getAnthropicClient maxRetries:0 同理
"""
import json
import re
import time
import random
import urllib.request
import urllib.error
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple


# ═══════════════════════════════════════════════════════════════════════════════
# 1. 异常分类体系
#    对应 claude-code-best withRetry.ts + errors.ts 的错误类型划分
# ═══════════════════════════════════════════════════════════════════════════════

class APIError(Exception):
    """LLM API 调用失败（可分类）。"""


class AuthError(APIError):
    """认证失败 (401/403)：API Key 无效或无权限，不可重试。"""


class RateLimitError(APIError):
    """请求频率超限 (429)：指数退避后重试。"""


class OverloadedError(APIError):
    """
    服务过载 (529)：对应 claude-code-best withRetry.ts is529Error 概念。
    有独立 MAX_529_RETRIES 计数器，避免过载级联时无限放大请求。
    """


class ModelNotFoundError(APIError):
    """模型不存在 (404)：拼写错误或无权限，不可重试。"""


class NetworkError(APIError):
    """网络/连接错误（DNS / ECONNRESET / SSL 等），可重试。"""


class TimeoutErrorLLM(APIError):
    """请求超时（connect timeout / read timeout），可重试。"""


class ContextOverflowError(APIError):
    """Prompt 超出模型上下文限制 (400)，需压缩后重新请求。"""


ERROR_MESSAGES: Dict[str, str] = {
    "api_key_missing":  "未配置 API Key。请在设置中填写对应 Provider 的 API Key，"
                        "或设置环境变量（如 OPENAI_API_KEY / DEEPSEEK_API_KEY）。",
    "auth_failed":      "API Key 无效或无权限。请确认 Key 属于所选服务商，并检查 Base URL/账号权限。",
    "rate_limit":       "请求频率超限（429）。请稍等 30 秒后重试，或减少批量分析数量。",
    "overloaded":       "服务过载（529）。服务器当前压力过大，将自动重试；如持续失败请稍后再试。",
    "model_not_found":  "模型名称不存在（404）。请检查模型名是否拼写正确或是否已开通权限。",
    "network_error":    "网络请求失败。请检查网络连接，或确认 Base URL 是否正确。",
    "timeout":          "请求超时（>30s）。建议切换更快模型或稍后重试。",
    "context_overflow": "Prompt 超出模型上下文限制。请减少分析文件数量或切换更长上下文的模型。",
    "parse_failed":     "模型返回格式异常，已尝试多种解析策略仍失败。建议改用单文件分析。",
    "ssl_error":        "SSL 证书验证失败。若处于企业代理/VPN 环境，"
                        "请联系 IT 配置正确的 CA 证书或将 API 域名加入白名单。",
}


# ═══════════════════════════════════════════════════════════════════════════════
# 2. 连接错误细节提取
#    对应 claude-code-best packages/@ant/model-provider/src/errorUtils.ts
#    extractConnectionErrorDetails — 遍历 cause 链寻找根因错误码
# ═══════════════════════════════════════════════════════════════════════════════

# SSL/TLS 错误码（来自 OpenSSL，与 claude-code-best SSL_ERROR_CODES 对齐）
_SSL_ERROR_CODES: frozenset = frozenset({
    "UNABLE_TO_VERIFY_LEAF_SIGNATURE", "UNABLE_TO_GET_ISSUER_CERT",
    "UNABLE_TO_GET_ISSUER_CERT_LOCALLY", "CERT_SIGNATURE_FAILURE",
    "CERT_NOT_YET_VALID", "CERT_HAS_EXPIRED", "CERT_REVOKED", "CERT_REJECTED",
    "CERT_UNTRUSTED", "DEPTH_ZERO_SELF_SIGNED_CERT", "SELF_SIGNED_CERT_IN_CHAIN",
    "CERT_CHAIN_TOO_LONG", "PATH_LENGTH_EXCEEDED", "ERR_TLS_CERT_ALTNAME_INVALID",
    "HOSTNAME_MISMATCH", "ERR_TLS_HANDSHAKE_TIMEOUT",
    "ERR_SSL_WRONG_VERSION_NUMBER", "ERR_SSL_DECRYPTION_FAILED_OR_BAD_RECORD_MAC",
    # Python ssl 模块常见错误码
    "CERTIFICATE_VERIFY_FAILED",
})

# urllib/socket 层面的连接错误关键词（用于无 code 属性的异常）
_ECONNRESET_KEYWORDS = ("connection reset", "econnreset", "epipe", "broken pipe",
                         "connection aborted")
_SSL_KEYWORDS = ("ssl", "certificate", "handshake", "tls")


def extract_connection_error_details(exc: Exception) -> Optional[Dict[str, Any]]:
    """
    遍历异常因果链（Python __cause__ / __context__），寻找根因错误码。

    对应 claude-code-best errorUtils.ts extractConnectionErrorDetails 的因果链遍历逻辑，
    但 Python 中用 __cause__/__context__ 而非 TS 的 cause 属性。

    返回 {"code": str, "message": str, "is_ssl_error": bool} 或 None。
    """
    current: Any = exc
    max_depth = 5
    visited = set()

    for _ in range(max_depth):
        if current is None or id(current) in visited:
            break
        visited.add(id(current))

        msg_lower = str(current).lower()

        # 优先使用 errno/code 属性
        for attr in ("errno", "code"):
            raw_code = getattr(current, attr, None)
            if raw_code is not None:
                code_str = str(raw_code).upper()
                is_ssl = code_str in _SSL_ERROR_CODES
                return {"code": code_str, "message": str(current), "is_ssl_error": is_ssl}

        # 从消息字符串识别已知 SSL 错误码
        for ssl_code in _SSL_ERROR_CODES:
            if ssl_code.lower() in msg_lower:
                return {"code": ssl_code, "message": str(current), "is_ssl_error": True}

        # 遍历下一层因果
        nxt = getattr(current, "__cause__", None) or getattr(current, "__context__", None)
        if nxt is current:
            break
        current = nxt

    return None


def _get_ssl_error_hint(exc: Exception) -> Optional[str]:
    """
    返回 SSL 错误的用户可读提示。
    对应 claude-code-best errorUtils.ts getSSLErrorHint。
    """
    details = extract_connection_error_details(exc)
    if not details or not details.get("is_ssl_error"):
        return None
    code = details.get("code", "SSL_ERROR")
    return (
        f"SSL 证书错误（{code}）。若处于企业代理或 TLS 拦截防火墙后，"
        "请配置正确的 CA 证书路径，或请 IT 将 API 域名加入白名单。"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 3. HTML 错误页脱敏
#    对应 claude-code-best errorUtils.ts sanitizeMessageHTML
#    CloudFlare / 网关错误页返回 HTML 时，提取 <title> 而非泄露原始 HTML
# ═══════════════════════════════════════════════════════════════════════════════

def _sanitize_html_error(message: str) -> str:
    """
    若响应是 HTML 错误页（CloudFlare / 网关错误），提取 <title> 返回。
    对应 claude-code-best errorUtils.ts sanitizeMessageHTML。
    """
    if not message:
        return message
    lower = message.lower()
    if "<!doctype html" in lower or "<html" in lower:
        m = re.search(r"<title>([^<]+)</title>", message, re.IGNORECASE)
        if m:
            return m.group(1).strip()
        return ""
    return message


# ═══════════════════════════════════════════════════════════════════════════════
# 4. 上下文溢出解析
#    对应 claude-code-best errors.ts parsePromptTooLongTokenCounts
# ═══════════════════════════════════════════════════════════════════════════════

def parse_context_overflow(body: str) -> Tuple[Optional[int], Optional[int]]:
    """
    解析 "prompt is too long: X tokens > Y maximum" 形式的超限错误。
    对应 claude-code-best errors.ts parsePromptTooLongTokenCounts。

    返回 (actual_tokens, limit_tokens)，解析失败返回 (None, None)。
    """
    if not body:
        return None, None
    m = re.search(
        r"prompt is too long[^0-9]*(\d+)\s*tokens?\s*>\s*(\d+)",
        body, re.IGNORECASE,
    )
    if m:
        try:
            return int(m.group(1)), int(m.group(2))
        except Exception:
            pass
    return None, None


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Retry-After 解析
#    对应 claude-code-best withRetry.ts getRetryAfterMs
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_retry_after_s(headers: Dict[str, str], body: str = "") -> float:
    """
    从响应头或错误体中解析 Retry-After（秒）。
    对应 claude-code-best withRetry.ts getRetryAfterMs（此处简化为秒）。
    """
    for k, v in headers.items():
        if k.lower() == "retry-after":
            try:
                return max(0.0, float(v))
            except Exception:
                pass
    if body:
        m = re.search(r'"retry_after"\s*:\s*(\d+(?:\.\d+)?)', body)
        if m:
            try:
                return max(0.0, float(m.group(1)))
            except Exception:
                pass
    return 0.0


def _parse_retry_after_from_message(msg: str) -> float:
    """尝试从错误消息字符串中提取 retry-after 秒数（备用，无法读取响应头时用）。"""
    m = re.search(r"retry.?after[:\s]+(\d+(?:\.\d+)?)", msg, re.IGNORECASE)
    if m:
        try:
            return max(0.0, float(m.group(1)))
        except Exception:
            pass
    return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# 6. HTTP 错误分类
#    对应 claude-code-best errors.ts 中的错误状态码分类逻辑
# ═══════════════════════════════════════════════════════════════════════════════

def classify_api_error(
    status_code: int,
    body: str,
    headers: Dict[str, str],
    model: str = "",
    last_request_id: str = "",
) -> APIError:
    """
    将 HTTP 错误状态码转换为类型化的 APIError 子类。

    对应 claude-code-best errors.ts getAssistantMessageFromError 中的
    状态码分支逻辑，并融入 withRetry.ts 中对 429/529 的区分处理。
    """
    # 从响应头提取 request id（不同网关字段名不同）
    rid = last_request_id
    for k, v in headers.items():
        if k and k.lower() in (
            "request-id", "x-request-id", "x-amzn-requestid", "x-amz-request-id",
            "cf-ray", "x-cloud-trace-context", "x-client-request-id",
        ) and v:
            rid = str(v)
            break

    def _with_rid(s: str) -> str:
        s = (s or "").strip()
        return f"{s}（request_id: {rid}）" if rid else s

    # 从响应体提取结构化错误信息
    msg = ""
    err_type = ""
    try:
        data = json.loads(body) if body else None
        if isinstance(data, dict):
            if isinstance(data.get("error"), dict):
                err = data["error"]
                msg = str(err.get("message") or err.get("msg") or "").strip()
                err_type = str(err.get("type") or err.get("code") or "").strip()
            elif isinstance(data.get("message"), str):
                msg = str(data["message"]).strip()
    except Exception:
        pass

    # HTML 页面脱敏（对应 claude-code-best sanitizeAPIError）
    if msg:
        msg = _sanitize_html_error(msg)
    if not msg and body:
        msg = _sanitize_html_error(body.strip().replace("\n", " ")[:200])

    if status_code in (401, 403):
        return AuthError(_with_rid(msg or ERROR_MESSAGES["auth_failed"]))

    if status_code == 429:
        retry_after = _parse_retry_after_s(headers, body)
        suffix = f"，{int(retry_after)}秒后可重试" if retry_after > 0 else ""
        return RateLimitError(_with_rid((msg or ERROR_MESSAGES["rate_limit"]) + suffix))

    if status_code == 529:
        return OverloadedError(_with_rid(msg or ERROR_MESSAGES["overloaded"]))

    if status_code == 404:
        base = ERROR_MESSAGES["model_not_found"]
        if model:
            base = f"{base}（当前模型：{model}）"
        return ModelNotFoundError(_with_rid(msg or base))

    if status_code == 400:
        actual, limit = parse_context_overflow(body)
        if actual is not None:
            overflow_msg = (
                f"Prompt 超出上下文限制：{actual:,} tokens > {limit:,} 最大值。"
                "请减少分析文件数量或切换更长上下文的模型。"
            )
            return ContextOverflowError(_with_rid(overflow_msg))

    if status_code >= 500:
        detail = msg or f"服务端错误（{status_code}），请稍后重试"
        return NetworkError(_with_rid(detail))

    snippet = msg or (body or "").strip().replace("\n", " ")[:180]
    if err_type and snippet:
        snippet = f"{err_type}: {snippet}"
    elif err_type:
        snippet = err_type
    return APIError(_with_rid(f"API 错误 {status_code}: {snippet}"))


# ═══════════════════════════════════════════════════════════════════════════════
# 7. HTTP 工具函数
#    对应 claude-code-best client.ts 的 request id 注入 + 错误传播模式
# ═══════════════════════════════════════════════════════════════════════════════

def http_post_json(
    url: str,
    headers: Dict[str, str],
    payload: dict,
    timeout_s: int = 30,
    model: str = "",
) -> Tuple[dict, str]:
    """
    HTTP POST JSON，注入 x-client-request-id，将 HTTP 错误分类为 APIError 子类。

    对应 claude-code-best client.ts 的 fetch 包装：
    - 注入 x-client-request-id（CLIENT_REQUEST_ID_HEADER）用于端到端排障
    - HTTP 错误通过 classify_api_error 转换为类型化异常（而非原始 HTTPError）

    返回 (response_data, request_id)。失败时抛出 APIError 子类（由上层 RetryClient 处理）。
    """
    req_id = uuid.uuid4().hex
    headers = dict(headers or {})
    headers.setdefault("x-client-request-id", req_id)
    headers.setdefault("X-Client-Request-Id", req_id)

    body_bytes = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body_bytes, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return json.loads(raw), req_id
    except urllib.error.HTTPError as e:
        try:
            body_txt = e.read().decode("utf-8", errors="replace")
        except Exception:
            body_txt = ""
        hdrs: Dict[str, str] = {}
        try:
            hdrs = {str(k): str(v) for k, v in (e.headers or {}).items()}
        except Exception:
            pass
        raise classify_api_error(
            getattr(e, "code", 0), body_txt, hdrs,
            model=model, last_request_id=req_id,
        ) from None
    except urllib.error.URLError as ue:
        ssl_hint = _get_ssl_error_hint(ue)
        if ssl_hint:
            raise NetworkError(ssl_hint) from None
        raise NetworkError(ERROR_MESSAGES["network_error"]) from None
    except TimeoutError:
        raise TimeoutErrorLLM(ERROR_MESSAGES["timeout"]) from None
    except json.JSONDecodeError:
        raise NetworkError(
            "服务返回非 JSON 响应，可能是代理/网关错误或 Base URL 不正确"
        ) from None


def http_post_openai_stream_text(
    url: str,
    headers: Dict[str, str],
    payload: dict,
    idle_timeout_s: int = 90,
    model: str = "",
) -> Tuple[Optional[str], str]:
    """
    OpenAI 兼容 SSE 流式：逐行解析 data: {...} 并拼接 delta.content。

    对应 claude-code-best claude.ts 中 stream: true 路径的简化版：
    - idle_timeout_s 对应 CLAUDE_STREAM_IDLE_TIMEOUT_MS（空闲看门狗）
    - [DONE] 检测、心跳行忽略、非 JSON data 行忽略
    - 返回空文本时触发上层降级（非流式回退）

    返回 (text, request_id)。失败时抛出 APIError 子类。
    """
    req_id = uuid.uuid4().hex
    headers = dict(headers or {})
    headers.setdefault("x-client-request-id", req_id)
    headers.setdefault("X-Client-Request-Id", req_id)

    payload = dict(payload or {})
    payload["stream"] = True
    payload.setdefault("stream_options", {"include_usage": True})

    body_bytes = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body_bytes, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=idle_timeout_s) as resp:
            text_parts: List[str] = []
            while True:
                line = resp.readline()
                if not line:
                    break
                try:
                    s = line.decode("utf-8", errors="replace").strip()
                except Exception:
                    continue
                if not s or not s.startswith("data:"):
                    continue
                data_str = s[len("data:"):].strip()
                if data_str == "[DONE]":
                    break
                if not data_str:
                    continue
                try:
                    obj = json.loads(data_str)
                except Exception:
                    continue
                try:
                    choices = obj.get("choices") or []
                    if not choices:
                        continue
                    delta = (choices[0] or {}).get("delta") or {}
                    piece = delta.get("content")
                    if isinstance(piece, str) and piece:
                        text_parts.append(piece)
                except Exception:
                    continue
            out = "".join(text_parts).strip()
            return (out if out else None), req_id
    except urllib.error.HTTPError as e:
        try:
            body_txt = e.read().decode("utf-8", errors="replace")
        except Exception:
            body_txt = ""
        hdrs: Dict[str, str] = {}
        try:
            hdrs = {str(k): str(v) for k, v in (e.headers or {}).items()}
        except Exception:
            pass
        raise classify_api_error(
            getattr(e, "code", 0), body_txt, hdrs,
            model=model, last_request_id=req_id,
        ) from None
    except urllib.error.URLError as ue:
        ssl_hint = _get_ssl_error_hint(ue)
        if ssl_hint:
            raise NetworkError(ssl_hint) from None
        raise NetworkError(ERROR_MESSAGES["network_error"]) from None
    except TimeoutError:
        raise TimeoutErrorLLM(
            "流式读取超时（无数据到达），已中止；可关闭 LLM_STREAM/OPENAI_STREAM 环境变量"
        ) from None


# ═══════════════════════════════════════════════════════════════════════════════
# 8. RetryClient — 应用层重试（对应 claude-code-best withRetry.ts）
#
#    关键移植点：
#    - 应用层重试而非 SDK 内部重试（对应 maxRetries: 0 给 Anthropic SDK）
#    - BASE_DELAY_S * 2^attempt + jitter（对应 BASE_DELAY_MS = 500）
#    - MAX_529_RETRIES = 3 独立计数器，避免 529 级联时无限放大
#    - Retry-After 响应头优先（对应 getRetryAfterMs）
#    - 不可重试错误（AuthError/ModelNotFoundError）立即终止
# ═══════════════════════════════════════════════════════════════════════════════

class RetryClient:
    """
    带指数退避 + jitter 的重试包装器。

    设计对应 claude-code-best withRetry.ts：
    - DEFAULT_MAX_RETRIES = 3（对应 TS DEFAULT_MAX_RETRIES = 10，但本场景更保守）
    - MAX_529_RETRIES = 3：529 有独立计数器，独立封顶
    - BASE_DELAY_S = 0.5：对应 TS BASE_DELAY_MS = 500ms
    - MAX_DELAY_S = 60：对应 TS MAX_RETRY_DELAY_MS 的量级
    - 不可重试错误立即透传，不消耗重试配额
    """

    DEFAULT_MAX_RETRIES = 3
    MAX_529_RETRIES = 3
    BASE_DELAY_S = 0.5
    MAX_DELAY_S = 60.0

    def __init__(
        self,
        max_retries: int = DEFAULT_MAX_RETRIES,
        max_529_retries: int = MAX_529_RETRIES,
        base_delay_s: float = BASE_DELAY_S,
        max_delay_s: float = MAX_DELAY_S,
    ):
        self.max_retries = max_retries
        self.max_529_retries = max_529_retries
        self.base_delay_s = base_delay_s
        self.max_delay_s = max_delay_s

    def get_delay(self, attempt: int, retry_after_s: float = 0.0) -> float:
        """
        计算当前重试等待时间。
        对应 claude-code-best withRetry.ts getRetryDelay：
            delay = min(BASE * 2^attempt + jitter, MAX)
        若有 Retry-After 则取两者较大值（优先遵从服务端）。
        """
        base = self.base_delay_s * (2 ** attempt)
        jitter = random.uniform(0.0, base * 0.5)
        delay = base + jitter
        if retry_after_s > 0.0:
            delay = max(delay, retry_after_s)
        return min(delay, self.max_delay_s)

    def call(self, fn: Callable[[], Any]) -> Any:
        """
        执行 fn() 并按需重试。fn 应是无参 callable（用 lambda 包裹 args/kwargs）。

        重试策略：
        - AuthError / ModelNotFoundError：立即抛出，不重试
        - OverloadedError (529)：独立 consecutive_529 计数，超 MAX_529_RETRIES 停止
        - RateLimitError (429)：解析错误消息中的 Retry-After 时间
        - NetworkError / TimeoutErrorLLM：标准指数退避
        - 其他 Exception：标准指数退避
        """
        consecutive_529 = 0
        last_exc: Optional[Exception] = None

        for attempt in range(self.max_retries + 1):
            try:
                return fn()

            except (AuthError, ModelNotFoundError):
                raise

            except OverloadedError as e:
                last_exc = e
                consecutive_529 += 1
                if consecutive_529 >= self.max_529_retries or attempt >= self.max_retries:
                    raise
                time.sleep(self.get_delay(attempt))

            except RateLimitError as e:
                last_exc = e
                retry_after = _parse_retry_after_from_message(str(e))
                if attempt >= self.max_retries:
                    raise
                time.sleep(self.get_delay(attempt, retry_after))

            except (NetworkError, TimeoutErrorLLM) as e:
                last_exc = e
                if attempt >= self.max_retries:
                    raise
                time.sleep(self.get_delay(attempt))

            except Exception as e:
                last_exc = e
                if attempt >= self.max_retries:
                    raise
                time.sleep(self.get_delay(attempt))

        if last_exc is not None:
            raise last_exc
        raise APIError("重试耗尽但未捕获到具体异常")
