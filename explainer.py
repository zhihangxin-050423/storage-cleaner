"""
explainer.py - 大模型解释生成模块

改进要点（基于 claude-code-best 设计模式）：
1) Prompt 分层：system/user 分离，结构化 JSON 输出
2) 上下文优化：规则引擎结论、目录语义、重复文件信息；避免泄露完整路径隐私
3) 批量策略：智能分批 + (可配置)并发 + 指数退避重试
4) 解析健壮：多策略提取 JSON，支持代码块/前后缀/序号列表降级
5) 缓存升级：结构化缓存(TTL + 最大条目数裁剪)
6) 错误反馈：last_error 可用于 UI 提示(认证/限速/网络/超时等)
7) 增强错误分类：连接细节提取(ECONNRESET/EPIPE/SSL)，上下文超限解析
8) 独立 HTTP 客户端层：api_client.py 统一管理重试策略

注意：LLM 仅生成"解释与建议"，不覆盖规则引擎的高风险判定，不执行任何删除。
"""
import os
import re
import json
import math
import hashlib
import threading
import uuid
import concurrent.futures
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import List, Optional, Dict, Tuple

from config import (
    LOG_DIR,
    LLM_MAX_TOKENS,
    LLMProvider,
    LLM_PROVIDER,
    DEFAULT_LLM_MODELS,
    DEFAULT_OPENAI_BASE_URL,
    DEFAULT_DEEPSEEK_BASE_URL,
    DEFAULT_DEEPSEEK_ANTHROPIC_BASE_URL,
)
from scanner import FileInfo

# 引入 claude-code-best 风格的 API 客户端层
from api_client import (
    APIError,
    AuthError,
    RateLimitError,
    ModelNotFoundError,
    NetworkError,
    TimeoutErrorLLM,
    OverloadedError,
    ContextOverflowError,
    RetryClient,
    classify_api_error,
    extract_connection_error_details,
    parse_context_overflow,
    http_post_json,
    http_post_openai_stream_text,
    ERROR_MESSAGES,
)


_CACHE_PATH = LOG_DIR / "explain_cache_v2.json"


SUGGESTION_NORMALIZE = {
    # 中文变体
    "可以删除": "safe_to_delete",
    "建议删除": "safe_to_delete",
    "安全删除": "safe_to_delete",
    "保留": "keep",
    "建议保留": "keep",
    "不建议删除": "keep",
    "谨慎": "caution",
    "需谨慎": "caution",
    "不确定": "caution",
    # 英文变体
    "delete": "safe_to_delete",
    "remove": "safe_to_delete",
    "safe": "safe_to_delete",
    "retain": "keep",
    "warning": "caution",
    "unknown": "caution",
}


SINGLE_SYSTEM_PROMPT = """你是一个 Windows 系统文件用途分析助手。
规则引擎已完成路径匹配与扩展名分类，你的任务是补充规则无法判断的“语义信息”，帮助用户理解陌生文件用途。

【输出格式——严格遵守，仅输出 JSON，不添加任何其他内容】
{
  "origin": "<文件来源/归属软件，15字以内，无法判断填'未知'>",
  "function": "<文件功能，20字以内>",
  "delete_impact": "<无影响|可恢复|功能受损|系统风险 四档，附一句说明>",
  "suggestion": "<safe_to_delete|keep|caution 三选一>",
  "confidence": <0.0~1.0>
}

【判断标准】
- safe_to_delete：缓存/临时文件/可自动重建
- keep：用户数据/不可恢复的配置/业务关键文件
- caution：无法确定用途，或删除影响不可预测

【注意】聚焦“为什么这个文件存在于这个目录”，不要重复解释扩展名含义。"""

# few-shot：校准“safe_to_delete / keep / caution”的边界（提升一致性）
UNKNOWN_FILE_EXAMPLES = """
【示例】
文件名：ab3f9c21d4.tmp | 目录：AppData\\Local\\Temp | 大小：2.3 MB | 访问：45天前 | 规则：低风险·临时文件·位于系统临时目录
→ {"origin":"系统临时文件","function":"程序运行产生的临时数据","delete_impact":"无影响（可重建）","suggestion":"safe_to_delete","confidence":0.95}

文件名：user_profile_backup_2022.dat | 目录：Documents\\OldBackups | 大小：128 KB | 访问：730天前 | 规则：高风险·未知文件·无匹配
→ {"origin":"未知应用的用户数据备份","function":"可能包含历史用户配置","delete_impact":"功能受损（数据可能丢失）","suggestion":"caution","confidence":0.55}

文件名：webpack-cache-9a2b.bin | 目录：project\\node_modules\\.cache | 大小：15 MB | 访问：7天前 | 规则：低风险·缓存文件·已知构建缓存
→ {"origin":"webpack 构建缓存","function":"加速前端项目编译","delete_impact":"可恢复（下次构建重建）","suggestion":"safe_to_delete","confidence":0.92}
"""

SINGLE_SYSTEM_PROMPT = SINGLE_SYSTEM_PROMPT + "\n\n" + UNKNOWN_FILE_EXAMPLES.strip()


BATCH_SYSTEM_PROMPT = """你是 Windows 文件分析助手，对文件列表进行批量分析。

输出必须是合法 JSON 对象，键为文件序号字符串（"1","2",...），值为分析结果：
{
  "1": {"origin":"...","suggestion":"safe_to_delete|keep|caution","reason":"...（10字以内）"},
  "2": {...}
}

规则：
- 仅输出 JSON，不要有任何前缀、后缀或 markdown 代码块
- [低风险-缓存] 标记的文件：suggestion 填 safe_to_delete，reason 填“已知缓存”
- [未知文件⚠] 标记的文件：认真分析文件名和目录语义
- reason 是建议理由，不是文件功能描述"""

SYSTEM_PROMPT_DYNAMIC_BOUNDARY = "__SYSTEM_PROMPT_DYNAMIC_BOUNDARY__"


BATCH_STRATEGY: Dict[LLMProvider, dict] = {
    LLMProvider.ANTHROPIC: {"batch_size": 15, "max_tokens_per_batch": 900, "concurrency": 2},
    LLMProvider.OPENAI:    {"batch_size": 20, "max_tokens_per_batch": 1000, "concurrency": 3},
    LLMProvider.DEEPSEEK:  {"batch_size": 10, "max_tokens_per_batch": 700, "concurrency": 1},
    LLMProvider.GEMINI:    {"batch_size": 20, "max_tokens_per_batch": 1200, "concurrency": 2},
}



def _env_first(*names: str) -> str:
    for n in names:
        v = os.environ.get(n, "")
        if v:
            return v
    return ""


def _env_truthy(name: str) -> bool:
    v = str(os.environ.get(name, "")).strip().lower()
    return v in ("1", "true", "yes", "on", "y")


def _env_defined_falsy(name: str) -> bool:
    if name not in os.environ:
        return False
    v = str(os.environ.get(name, "")).strip().lower()
    return v in ("0", "false", "no", "off", "n")


def _is_openai_thinking_enabled(model: str) -> bool:
    """
    参考 claude-code-best：为 DeepSeek 等“推理模型”自动启用 thinking，并允许 env 强制开关。
    - OPENAI_ENABLE_THINKING=0/false/no/off：强制关闭
    - OPENAI_ENABLE_THINKING=1/true/yes/on：强制开启
    - 否则：模型名包含 deepseek 时自动开启
    """
    if _env_defined_falsy("OPENAI_ENABLE_THINKING"):
        return False
    if _env_truthy("OPENAI_ENABLE_THINKING"):
        return True
    return "deepseek" in (model or "").lower()


def _resolve_api_timeout_s(default_s: int = 30) -> int:
    """
    统一读取 API_TIMEOUT_MS（与 claude-code-best 对齐），作为每次请求的超时上限。
    """
    try:
        ms = int(str(os.environ.get("API_TIMEOUT_MS", "")).strip() or "0")
        if ms > 0:
            return max(1, int(ms / 1000))
    except Exception:
        pass
    return default_s


def _is_streaming_enabled() -> bool:
    # 默认关闭；可通过环境变量启用（便于稳定性回滚）
    return _env_truthy("LLM_STREAM") or _env_truthy("OPENAI_STREAM")


def _resolve_stream_idle_timeout_s(default_s: int = 90) -> int:
    """
    流式读取的“无数据到达”超时（idle watchdog 简化版）：
    在 urllib 里表现为 socket read timeout，读不到下一行会超时抛异常。
    """
    try:
        ms = int(str(os.environ.get("LLM_STREAM_IDLE_TIMEOUT_MS", "")).strip() or "0")
        if ms > 0:
            return max(1, int(ms / 1000))
    except Exception:
        pass
    try:
        ms = int(str(os.environ.get("CLAUDE_STREAM_IDLE_TIMEOUT_MS", "")).strip() or "0")
        if ms > 0:
            return max(1, int(ms / 1000))
    except Exception:
        pass
    return default_s


class Explainer:
    """多 Provider 的文件解释生成器（UI 可配置 Provider/Model/BaseURL/Key）。"""

    def __init__(self,
                 provider: Optional[LLMProvider] = None,
                 api_key: str = "",
                 model: str = "",
                 base_url: str = "",
                 extra_params: Optional[dict] = None):
        self.provider: LLMProvider = provider or LLM_PROVIDER
        self.model: str = model or DEFAULT_LLM_MODELS.get(self.provider, "")
        self.base_url: str = base_url
        self.api_key: str = api_key or self._default_api_key_for_provider(self.provider)
        # OpenAI/DeepSeek 等兼容接口的额外请求参数（可选，JSON）
        self.extra_params: Dict = extra_params or {}
        self.last_error: str = ""
        self.last_request_id: str = ""

        self._cache = ExplainerCache(_CACHE_PATH)
        # system prompt 缓存：静态段落 + 动态段落（跨请求稳定，减少细微波动）
        self._system_prompt_cache: Dict[str, str] = {}

    # ──────────────────────────────────────────────────────────────────────────
    # 公共 API
    # ──────────────────────────────────────────────────────────────────────────

    def explain_file(self, fi: FileInfo) -> str:
        """
        为单个文件生成解释。
        返回人类可读字符串，失败时返回提示信息。
        """
        if not self.api_key:
            self.last_error = "未配置 API Key"
            return "（未配置 API Key，无法生成 AI 解释。请在设置中填写对应 Provider 的 API Key）"

        ck = self._cache_key(fi)
        cached = self._cache.get(ck)
        if cached:
            fi.ai_suggestion = cached.suggestion
            fi.ai_confidence = cached.confidence
            return cached.explanation

        raw = self._call_api_with_retry(
            system=self._get_system_prompt(mode="single"),
            user=self._build_single_user(fi),
            max_tokens=300,
            retries=2,
        )
        if not raw:
            rid = (self.last_request_id or "").strip()
            extra = f"\nrequest_id: {rid}" if rid else ""
            return f"（AI 解释生成失败：{self.last_error or '未知错误'}）{extra}"

        data = self._extract_json(raw)
        if data and isinstance(data, dict):
            explanation, suggestion, confidence = self._format_single_structured(fi, data)
        else:
            # 未按格式返回时降级为纯文本，并明确提示“解析失败”而不是看起来像乱码/残片
            rid = (self.last_request_id or "").strip()
            head = "（AI 返回未按 JSON 格式输出，已降级为原文截断显示；可尝试切换模型/重试。）"
            if rid:
                head += f"\nrequest_id: {rid}"
            explanation = head + "\n\n" + (raw or "")[:600]
            suggestion, confidence = "caution", 0.3

        entry = CacheEntry(
            explanation=explanation,
            suggestion=suggestion,
            confidence=confidence,
            provider=self.provider.value,
            model=self.model,
            created_at=datetime.now().isoformat(),
        )
        self._cache.set(ck, entry)
        self._cache.save()

        fi.ai_suggestion = suggestion
        fi.ai_confidence = confidence
        return explanation

    def explain_batch(self, files: List[FileInfo],
                      progress_callback=None) -> Dict[str, str]:
        """
        批量解释文件列表（每次最多 10 个，减少 API 调用）。
        返回: {file_path: explanation}
        """
        results: Dict[str, str] = {}
        if not self.api_key or not files:
            self.last_error = "未配置 API Key" if not self.api_key else ""
            return results

        # 过滤缓存命中
        to_fetch = [fi for fi in files if not self._cache.get(self._cache_key(fi))]
        if not to_fetch:
            for fi in files:
                cached = self._cache.get(self._cache_key(fi))
                if cached:
                    results[fi.path] = cached.explanation
                    fi.ai_suggestion = cached.suggestion
                    fi.ai_confidence = cached.confidence
            return results

        batches = self._smart_batch(to_fetch)
        strategy = BATCH_STRATEGY.get(self.provider, {"concurrency": 1, "max_tokens_per_batch": 600})
        max_workers = int(strategy.get("concurrency", 1))
        max_tokens_per_batch = int(strategy.get("max_tokens_per_batch", 600))

        completed = 0
        lock = threading.Lock()

        def process_batch(batch: List[FileInfo]) -> Dict[str, str]:
            nonlocal completed
            # 未知文件批次给更高 token 预算；已知缓存批次更省 token
            _, _, unknown = self._classify_files(batch)
            unknown_ratio = (len(unknown) / max(1, len(batch)))
            # 约束：每文件最多 150 tokens；未知文件占比越高，上限越靠近 max_tokens_per_batch
            per_file_cap = 150
            dynamic_cap = int(min(max_tokens_per_batch, max(300, (80 + 70 * unknown_ratio) * len(batch))))
            raw = self._call_api_with_retry(
                system=self._get_system_prompt(mode="batch"),
                user=self._build_batch_user(batch),
                max_tokens=min(dynamic_cap, per_file_cap * len(batch)),
                retries=2,
            )
            batch_results: Dict[str, str] = {}
            if not raw:
                rid = (self.last_request_id or "").strip()
                extra = f" request_id: {rid}" if rid else ""
                msg = f"（批量 AI 分析失败：{self.last_error or '未知错误'}）{extra}"
                for fi in batch:
                    batch_results[fi.path] = msg
                with lock:
                    completed += len(batch)
                    if progress_callback:
                        progress_callback(completed, len(to_fetch))
                return batch_results

            parsed = self._parse_batch_response_robust(raw, batch)
            for path, expl in parsed.items():
                fi = next((f for f in batch if f.path == path), None)
                if fi:
                    # 批量输出通常更简略：置信度给一个中间值，建议从文本里提取
                    suggestion = self._extract_suggestion_from_text(expl)
                    entry = CacheEntry(
                        explanation=expl,
                        suggestion=suggestion,
                        confidence=0.7 if suggestion != "caution" else 0.55,
                        provider=self.provider.value,
                        model=self.model,
                        created_at=datetime.now().isoformat(),
                    )
                    self._cache.set(self._cache_key(fi), entry)
                    fi.ai_suggestion = entry.suggestion
                    fi.ai_confidence = entry.confidence
                    batch_results[path] = expl

            with lock:
                completed += len(batch)
                if progress_callback:
                    progress_callback(completed, len(to_fetch))
            return batch_results

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = [ex.submit(process_batch, b) for b in batches]
            for f in concurrent.futures.as_completed(futures):
                try:
                    results.update(f.result(timeout=90))
                except Exception:
                    pass

        self._cache.save()

        # 补充缓存命中
        for fi in files:
            if fi.path not in results:
                cached = self._cache.get(self._cache_key(fi))
                if cached:
                    results[fi.path] = cached.explanation
                    fi.ai_suggestion = cached.suggestion
                    fi.ai_confidence = cached.confidence

        return results

    def _get_system_prompt(self, mode: str) -> str:
        """
        参考 claude-code-best 的“静态段落 + 边界 + 动态段落”思路：
        - 静态段落：提示词主体（含 few-shot），尽量不随运行环境变化
        - 动态段落：极少量运行时信息（provider/model），便于排障与轻度自适应
        """
        mode_key = "single" if mode == "single" else "batch"
        cache_key = f"{mode_key}|{self.provider.value}|{self.model}"
        cached = self._system_prompt_cache.get(cache_key)
        if cached:
            return cached

        static = SINGLE_SYSTEM_PROMPT if mode_key == "single" else BATCH_SYSTEM_PROMPT
        dynamic_lines = [
            SYSTEM_PROMPT_DYNAMIC_BOUNDARY,
            f"运行配置：provider={self.provider.value} | model={self.model or ''}",
            "注意：你的建议不得推翻规则引擎对高风险文件的判定（高风险默认不建议删除）。",
        ]
        prompt = static.rstrip() + "\n\n" + "\n".join(dynamic_lines).strip() + "\n"
        self._system_prompt_cache[cache_key] = prompt
        return prompt

    def configure(self,
                  provider: Optional[LLMProvider] = None,
                  api_key: Optional[str] = None,
                  model: Optional[str] = None,
                  base_url: Optional[str] = None,
                  extra_params: Optional[dict] = None):
        """更新运行时配置（由设置窗口调用）。"""
        if provider is not None:
            self.provider = provider
            if not self.model:
                self.model = DEFAULT_LLM_MODELS.get(self.provider, self.model)
            if not self.api_key:
                self.api_key = self._default_api_key_for_provider(self.provider)
        if api_key is not None:
            self.api_key = api_key
        if model is not None:
            self.model = model
        if base_url is not None:
            self.base_url = base_url
        if extra_params is not None:
            self.extra_params = extra_params

    # ──────────────────────────────────────────────────────────────────────────
    # Prompt / Context
    # ──────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _estimate_tokens(text: str) -> int:
        """粗略估算 token（中文约 1.5 字/token，其他约 4 字/token）"""
        if not text:
            return 0
        chinese = sum(1 for c in text if "\u4e00" <= c <= "\u9fff")
        other = len(text) - chinese
        return int(chinese / 1.5 + other / 4)

    @staticmethod
    def _extract_dir_context(path: str, depth: int = 3) -> str:
        parts = []
        current = os.path.dirname(path)
        for _ in range(depth):
            name = os.path.basename(current)
            if not name:
                break
            parts.insert(0, name)
            parent = os.path.dirname(current)
            if parent == current:
                break
            current = parent
        return "\\".join(parts) if parts else "(根目录)"

    def _build_context_for_file(self, fi: FileInfo, token_budget: int = 90) -> str:
        """
        在 token 预算内构建单文件上下文。
        优先级：文件名 > 目录语义 > 大小 > 规则原因(截断) > 访问时间 > 重复信息
        """
        parts = [f"文件名:{fi.name}"]

        dir_ctx = self._extract_dir_context(fi.path, depth=2)
        parts.append(f"目录:{dir_ctx}")

        if self._estimate_tokens(" | ".join(parts)) + 8 < token_budget:
            parts.append(f"大小:{fi.size_str}")

        reason_short = (fi.risk_reason or "").strip()
        if reason_short:
            reason_short = reason_short[:40]
            if self._estimate_tokens(" | ".join(parts)) + 20 < token_budget:
                parts.append(f"规则:{reason_short}")

        if self._estimate_tokens(" | ".join(parts)) + 12 < token_budget:
            parts.append(f"访问:{fi.atime_days_ago}天前")

        if fi.is_duplicate and fi.duplicate_of and self._estimate_tokens(" | ".join(parts)) + 16 < token_budget:
            parts.append(f"重复:{os.path.basename(fi.duplicate_of)}")

        return " | ".join(parts)

    def _build_single_user(self, fi: FileInfo) -> str:
        # 目录上下文/规则原因做动态裁剪，避免 token 浪费且提升语义密度
        ctx = self._build_context_for_file(fi, token_budget=110)
        return (
            f"{ctx}\n"
            f"规则引擎：{fi.risk_level} · {fi.category} · {fi.risk_reason}\n\n"
            f"请分析并严格按 JSON 返回："
        )

    def _classify_files(self, files: List[FileInfo]) -> Tuple[List[FileInfo], List[FileInfo], List[FileInfo]]:
        known_safe, known_risky, truly_unknown = [], [], []
        for fi in files:
            if fi.category in ("临时文件", "缓存文件") and fi.risk_level == "低风险":
                known_safe.append(fi)
            elif fi.category == "未知文件":
                truly_unknown.append(fi)
            else:
                known_risky.append(fi)
        return known_safe, known_risky, truly_unknown

    def _build_batch_user(self, files: List[FileInfo]) -> str:
        known_safe, known_risky, truly_unknown = self._classify_files(files)
        lines = []
        for i, fi in enumerate(files, 1):
            if fi in known_safe:
                tag = "[低风险-缓存]"
                ctx = self._build_context_for_file(fi, token_budget=60)
            elif fi in truly_unknown:
                tag = "[未知文件⚠]"
                ctx = self._build_context_for_file(fi, token_budget=110)
            else:
                tag = f"[{fi.risk_level}]"
                ctx = self._build_context_for_file(fi, token_budget=85)
            lines.append(f"{i}. {tag} {ctx}")
        stats = f"共 {len(files)} 个：低风险缓存 {len(known_safe)} 个，中风险 {len(known_risky)} 个，未知 {len(truly_unknown)} 个"
        return f"分析以下文件列表（{stats}），返回 JSON：\n\n" + "\n".join(lines)

    def _smart_batch(self, files: List[FileInfo]) -> List[List[FileInfo]]:
        strategy = BATCH_STRATEGY.get(self.provider, {"batch_size": 10})
        max_batch = int(strategy.get("batch_size", 10))
        _, _, unknown = self._classify_files(files)
        known = [fi for fi in files if fi not in unknown]
        batches: List[List[FileInfo]] = []
        unknown_batch_size = max(3, max_batch // 3)
        for i in range(0, len(unknown), unknown_batch_size):
            batches.append(unknown[i:i + unknown_batch_size])
        for i in range(0, len(known), max_batch):
            batches.append(known[i:i + max_batch])
        return batches

    # ──────────────────────────────────────────────────────────────────────────
    # API calling with system/user + retry
    # ──────────────────────────────────────────────────────────────────────────

    def _call_api_with_retry(self, system: str, user: str, max_tokens: int, retries: int = 2) -> Optional[str]:
        """
        带重试的 API 调用入口。重试逻辑委托给 RetryClient（对应 claude-code-best withRetry.ts）：
        - 指数退避 + jitter，不可重试错误（认证/模型不存在）立即返回 None
        - OverloadedError (529) 有独立计数器，上层 error 可用于 UI 提示
        """
        self.last_error = ""
        client = RetryClient(max_retries=retries)
        try:
            result = client.call(
                lambda: self._call_with_messages(system=system, user=user, max_tokens=max_tokens)
            )
            return result
        except AuthError as e:
            self.last_error = str(e) or ERROR_MESSAGES["auth_failed"]
        except ModelNotFoundError as e:
            self.last_error = str(e) or ERROR_MESSAGES["model_not_found"]
        except RateLimitError as e:
            self.last_error = str(e) or ERROR_MESSAGES["rate_limit"]
        except OverloadedError as e:
            self.last_error = str(e) or ERROR_MESSAGES["overloaded"]
        except ContextOverflowError as e:
            self.last_error = str(e) or ERROR_MESSAGES["context_overflow"]
        except TimeoutErrorLLM as e:
            self.last_error = str(e) or ERROR_MESSAGES["timeout"]
        except NetworkError as e:
            self.last_error = str(e) or ERROR_MESSAGES["network_error"]
        except Exception as e:
            self.last_error = str(e)[:200] if str(e) else "未知错误"
        return None

    def _call_with_messages(self, system: str, user: str, max_tokens: int) -> Optional[str]:
        # 不捕获异常：让 APIError 子类传播到 RetryClient 进行重试决策
        if self.provider == LLMProvider.ANTHROPIC:
            return self._call_anthropic_messages(system, user, max_tokens=max_tokens)
        if self.provider in (LLMProvider.OPENAI, LLMProvider.DEEPSEEK):
            return self._call_openai_messages(system, user, max_tokens=max_tokens)
        if self.provider == LLMProvider.GEMINI:
            return self._call_gemini_messages(system, user, max_tokens=max_tokens)
        raise APIError("不支持的 Provider")

    # ──────────────────────────────────────────────────────────────────────────
    # Provider implementations
    # ──────────────────────────────────────────────────────────────────────────

    def _call_anthropic_messages(self, system: str, user: str, max_tokens: int) -> Optional[str]:
        # 优先使用官方 SDK（如果已安装），否则走 HTTP
        try:
            import anthropic  # type: ignore
            client = anthropic.Anthropic(api_key=self.api_key)
            message = client.messages.create(
                model=self.model or DEFAULT_LLM_MODELS.get(LLMProvider.ANTHROPIC, ""),
                max_tokens=max_tokens,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
            return message.content[0].text if message.content else None
        except ImportError:
            pass
        except Exception:
            # SDK 失败也可降级到 HTTP
            pass

        base = self._anthropic_base_url().rstrip("/")
        url = f"{base}/v1/messages"
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
        }
        payload = {
            "model": self.model or DEFAULT_LLM_MODELS.get(LLMProvider.ANTHROPIC, ""),
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        data = self._http_post_json(url, headers=headers, payload=payload)
        try:
            content = data.get("content") or []
            if content and isinstance(content, list):
                # [{"type":"text","text":"..."}]
                return content[0].get("text")
        except Exception:
            self.last_error = "响应解析失败"
            return None
        return None

    def _call_openai_messages(self, system: str, user: str, max_tokens: int) -> Optional[str]:
        # OpenAI / DeepSeek：使用 OpenAI 兼容的 chat/completions
        if self.provider == LLMProvider.DEEPSEEK:
            # DeepSeek 支持：
            # - OpenAI 兼容 base_url: https://api.deepseek.com
            # - Anthropic 兼容 base_url: https://api.deepseek.com/anthropic
            base = (self.base_url or DEFAULT_DEEPSEEK_BASE_URL).rstrip("/")
            # DeepSeek 常见环境变量
            if not self.api_key:
                self.api_key = _env_first("DEEPSEEK_API_KEY", "OPENAI_API_KEY")
            # 若用户选择了 anthropic 兼容 base，则直接走 anthropic messages
            if base.lower().endswith("/anthropic"):
                # 当选择 anthropic base 时，若用户没显式填模型，给一个 DeepSeek 推荐模型
                if not self.model:
                    self.model = DEFAULT_LLM_MODELS.get(LLMProvider.DEEPSEEK, "deepseek-v4-flash")
                # 若用户没填 base_url，使用官方推荐的 anthropic base
                if not self.base_url:
                    self.base_url = DEFAULT_DEEPSEEK_ANTHROPIC_BASE_URL
                return self._call_anthropic_messages(system, user, max_tokens=max_tokens)
        else:
            base = (self.base_url or DEFAULT_OPENAI_BASE_URL).rstrip("/")
            if not self.api_key:
                self.api_key = _env_first("OPENAI_API_KEY")

        url = f"{base}/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        payload = {
            "model": self.model or DEFAULT_LLM_MODELS.get(self.provider, ""),
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "max_tokens": max_tokens,
            "temperature": 0.1,  # 降低随机性，提高 JSON 格式稳定性
        }
        # 透传额外参数（用于 DeepSeek/OpenAI 特性开关等）
        extra_params = self.extra_params if isinstance(self.extra_params, dict) else {}
        if extra_params:
            payload.update(extra_params)

        # DeepSeek thinking mode（参考 claude-code-best 的兼容字段注入；服务器识别其一即可）
        model_name = str(payload.get("model") or "")
        enable_thinking = _is_openai_thinking_enabled(model_name)
        already_set = any(
            k in (extra_params or {})
            for k in ("thinking", "enable_thinking", "chat_template_kwargs")
        )
        if enable_thinking and not already_set:
            payload.update({
                # Official DeepSeek API format
                "thinking": {"type": "enabled"},
                # Self-hosted DeepSeek-V3.2 format
                "enable_thinking": True,
                "chat_template_kwargs": {"thinking": True},
            })

        # 可选流式（参考 claude-code-best：优先流式，失败自动降级到非流式）
        if _is_streaming_enabled():
            try:
                streamed = self._http_post_openai_stream_text(url, headers=headers, payload=payload)
                if streamed is not None:
                    return streamed
            except APIError:
                # 已分类错误，直接抛给上层重试策略
                raise
            except Exception:
                # 流式解析失败：降级到非流式
                pass

        data = self._http_post_json(url, headers=headers, payload=payload)
        try:
            choices = data.get("choices") or []
            if choices:
                msg = choices[0].get("message") or {}
                return msg.get("content")
        except Exception:
            self.last_error = "响应解析失败"
            return None
        return None

    def _call_gemini_messages(self, system: str, user: str, max_tokens: int) -> Optional[str]:
        # Gemini：使用 Google Generative Language API（API Key 作为 query 参数）
        if not self.api_key:
            self.api_key = _env_first("GEMINI_API_KEY", "GOOGLE_API_KEY")

        model = self.model or DEFAULT_LLM_MODELS.get(LLMProvider.GEMINI, "")
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={self.api_key}"
        headers = {"Content-Type": "application/json"}
        payload = {
            "system_instruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": {
                "maxOutputTokens": max_tokens,
                "temperature": 0.1,
            },
        }
        data = self._http_post_json(url, headers=headers, payload=payload)
        try:
            cands = data.get("candidates") or []
            if not cands:
                return None
            content = cands[0].get("content") or {}
            parts = content.get("parts") or []
            if parts:
                return parts[0].get("text")
        except Exception:
            self.last_error = "响应解析失败"
            return None
        return None

    def _anthropic_base_url(self) -> str:
        """
        Anthropic HTTP base URL：
        - 默认 https://api.anthropic.com
        - 若 provider=DeepSeek 且 base_url 以 /anthropic 结尾，则使用该 base（官方文档）
        """
        if self.provider == LLMProvider.DEEPSEEK:
            if (self.base_url or "").rstrip("/").lower().endswith("/anthropic"):
                return (self.base_url or DEFAULT_DEEPSEEK_ANTHROPIC_BASE_URL).rstrip("/")
        return "https://api.anthropic.com"

    # ──────────────────────────────────────────────────────────────────────────
    # JSON extraction / formatting
    # ──────────────────────────────────────────────────────────────────────────

    def _extract_json(self, text: str) -> Optional[dict]:
        t = (text or "").strip()
        # 策略1：直接解析
        try:
            return json.loads(t)
        except Exception:
            pass

        # 策略2：去掉 markdown 代码块
        cleaned = re.sub(r"```(?:json)?\s*", "", t).strip().rstrip("`")
        try:
            return json.loads(cleaned)
        except Exception:
            pass

        # 策略3：栈匹配提取首个完整 JSON 对象
        start = t.find("{")
        if start == -1:
            return None
        depth = 0
        in_string = False
        escape_next = False
        for i, ch in enumerate(t[start:], start):
            if escape_next:
                escape_next = False
                continue
            if ch == "\\" and in_string:
                escape_next = True
                continue
            if ch == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(t[start:i + 1])
                    except Exception:
                        break
        return None

    def _parse_batch_response_robust(self, raw: str, files: List[FileInfo]) -> Dict[str, str]:
        result: Dict[str, str] = {}
        data = self._extract_json(raw)
        if data and isinstance(data, dict):
            for i, fi in enumerate(files, 1):
                val = data.get(str(i))
                if val is None:
                    continue
                if isinstance(val, dict):
                    result[fi.path] = self._format_batch_item(val)
                elif isinstance(val, str):
                    result[fi.path] = val
            if result:
                return result

        # 降级：按行序号匹配（"1. xxx"）
        numbered_pattern = re.compile(r"^(\d+)[.、:：]\s*(.+)$")
        for line in (raw or "").split("\n"):
            m = numbered_pattern.match(line.strip())
            if m:
                idx = int(m.group(1)) - 1
                if 0 <= idx < len(files):
                    result[files[idx].path] = m.group(2)
        if result:
            return result

        # 最终降级：为本批所有文件给出可读的降级结果（避免 UI 空白）
        summary = (raw or "")[:300].strip().replace("\r", " ")
        summary_short = (summary[:80] + "...") if len(summary) > 80 else summary
        for fi in files:
            prefix = "（解析失败，建议单独分析）"
            if fi.category == "未知文件":
                prefix = "（未知文件解析失败，建议单独分析）"
            result[fi.path] = f"{prefix}{summary_short}"
        return result

    def _normalize_suggestion(self, raw_suggestion: str) -> str:
        s = (raw_suggestion or "caution").strip().lower()
        if s in ("safe_to_delete", "keep", "caution"):
            return s
        return SUGGESTION_NORMALIZE.get(s, "caution")

    def _format_single_structured(self, fi: FileInfo, data: dict) -> Tuple[str, str, float]:
        suggestion = self._normalize_suggestion(str(data.get("suggestion", "caution")))
        confidence = 0.5
        try:
            confidence = float(data.get("confidence", 0.5))
            confidence = min(1.0, max(0.0, confidence))
        except Exception:
            confidence = 0.5

        # 安全约束：规则引擎高风险不允许被 AI 降级
        if fi.risk_level == "高风险" and suggestion == "safe_to_delete":
            suggestion = "caution"
            confidence = min(confidence, 0.6)

        parts = []
        if data.get("origin"):
            parts.append(f"📦 来源：{data.get('origin')}")
        if data.get("function"):
            parts.append(f"⚙️ 功能：{data.get('function')}")
        if data.get("delete_impact"):
            parts.append(f"🗑️ 删除影响：{data.get('delete_impact')}")
        parts.append({
            "safe_to_delete": "✅ 建议：可以删除",
            "keep": "🔒 建议：保留",
            "caution": "⚠️ 建议：谨慎确认后再决定",
        }[suggestion])
        parts.append(f"🎯 置信度：{int(confidence * 100)}%")
        return "\n".join(parts), suggestion, confidence

    def _format_batch_item(self, data: dict) -> str:
        suggestion = self._normalize_suggestion(str(data.get("suggestion", "caution")))
        icon = {"safe_to_delete": "✅", "keep": "🔒", "caution": "⚠️"}[suggestion]
        origin = str(data.get("origin", "")).strip()
        reason = str(data.get("reason", "")).strip()
        parts = [f"{icon} {suggestion}"]
        if origin:
            parts.append(f"来源：{origin}")
        if reason:
            parts.append(f"理由：{reason}")
        return "  ".join(parts)

    def _extract_suggestion_from_text(self, text: str) -> str:
        t = text or ""
        if "✅" in t or "safe_to_delete" in t:
            return "safe_to_delete"
        if "🔒" in t or "keep" in t:
            return "keep"
        return "caution"

    def _http_post_json(self, url: str, headers: Dict[str, str], payload: dict, timeout_s: int = 30) -> dict:
        """
        HTTP POST JSON 薄包装层。
        委托给 api_client.http_post_json（含 x-client-request-id 注入、错误分类）。
        失败时抛出 APIError 子类，由上层 RetryClient 处理重试。
        """
        timeout_s = _resolve_api_timeout_s(timeout_s)
        data, req_id = http_post_json(url, headers, payload, timeout_s=timeout_s, model=self.model)
        self.last_request_id = req_id
        return data

    def _http_post_openai_stream_text(self, url: str, headers: Dict[str, str], payload: dict) -> Optional[str]:
        """
        OpenAI SSE 流式薄包装层。
        委托给 api_client.http_post_openai_stream_text（含空闲看门狗、降级触发）。
        失败时抛出 APIError 子类；返回 None 时上层降级到非流式。
        """
        idle_timeout_s = _resolve_stream_idle_timeout_s()
        text, req_id = http_post_openai_stream_text(
            url, headers, payload,
            idle_timeout_s=idle_timeout_s,
            model=self.model,
        )
        self.last_request_id = req_id
        return text

    @staticmethod
    def _default_api_key_for_provider(provider: LLMProvider) -> str:
        if provider == LLMProvider.ANTHROPIC:
            return _env_first("ANTHROPIC_API_KEY")
        if provider == LLMProvider.OPENAI:
            return _env_first("OPENAI_API_KEY")
        if provider == LLMProvider.DEEPSEEK:
            return _env_first("DEEPSEEK_API_KEY", "OPENAI_API_KEY")
        if provider == LLMProvider.GEMINI:
            return _env_first("GEMINI_API_KEY", "GOOGLE_API_KEY")
        return ""

    # ──────────────────────────────────────────────────────────────────────────
    # Cache key
    # ──────────────────────────────────────────────────────────────────────────

    def _cache_key(self, fi: FileInfo) -> str:
        # 目录模式（不含完整路径，减少隐私暴露，同时提升语义）
        parent = os.path.basename(os.path.dirname(fi.path)).lower()
        grandparent = os.path.basename(os.path.dirname(os.path.dirname(fi.path))).lower()
        # 大小量级（对数分桶）
        size_bucket = max(0, int(math.log10(fi.size + 1)))
        raw = (
            f"{fi.name.lower()}|{fi.extension}|{grandparent}\\{parent}|{fi.category}|"
            f"{size_bucket}|{self.provider.value}|{self.model}"
        )
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


@dataclass
class CacheEntry:
    explanation: str
    suggestion: str
    confidence: float
    provider: str
    model: str
    created_at: str

    def is_expired(self, ttl_days: int) -> bool:
        try:
            created = datetime.fromisoformat(self.created_at)
            return datetime.now() - created > timedelta(days=ttl_days)
        except Exception:
            return True


class ExplainerCache:
    MAX_ENTRIES = 5000
    TTL_DAYS = 30

    def __init__(self, path):
        self._path = path
        self._lock = threading.Lock()
        self._data: Dict[str, CacheEntry] = {}
        self._load()

    def get(self, key: str) -> Optional[CacheEntry]:
        with self._lock:
            e = self._data.get(key)
            if e and not e.is_expired(self.TTL_DAYS):
                return e
            if e:
                del self._data[key]
            return None

    def set(self, key: str, entry: CacheEntry):
        with self._lock:
            self._data[key] = entry
            if len(self._data) > self.MAX_ENTRIES:
                oldest = min(self._data, key=lambda k: self._data[k].created_at)
                del self._data[oldest]

    def save(self):
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._lock:
                data = {k: entry.__dict__ for k, entry in self._data.items()}
            self._path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass

    def _load(self):
        try:
            if not self._path.exists():
                return
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                return
            for k, v in raw.items():
                try:
                    if not isinstance(v, dict):
                        continue
                    entry = CacheEntry(**v)
                    if not entry.is_expired(self.TTL_DAYS):
                        self._data[k] = entry
                except Exception:
                    continue
        except Exception:
            pass
