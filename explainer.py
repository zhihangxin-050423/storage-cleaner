"""
explainer.py - 大模型解释生成模块

支持多种常见大语言模型接口，用于为“未知/不常见文件”生成用户可读解释：
- Claude (Anthropic)
- ChatGPT (OpenAI)
- DeepSeek（OpenAI 兼容接口）
- Gemini (Google)

设计原则：
  - 规则引擎负责分类/风险；LLM 只负责解释文本
  - API 失败时优雅降级，不影响核心扫描/规则功能
  - 不允许 AI 直接执行任何删除操作
"""
import os
import json
import time
import hashlib
import urllib.request
import urllib.error
from typing import List, Optional, Dict

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


_CACHE_PATH = LOG_DIR / "explain_cache.json"


def _env_first(*names: str) -> str:
    for n in names:
        v = os.environ.get(n, "")
        if v:
            return v
    return ""


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

        self._cache: Dict[str, str] = self._load_cache()

    # ──────────────────────────────────────────────────────────────────────────
    # 公共 API
    # ──────────────────────────────────────────────────────────────────────────

    def explain_file(self, fi: FileInfo) -> str:
        """
        为单个文件生成解释。
        返回人类可读字符串，失败时返回提示信息。
        """
        if not self.api_key:
            return "（未配置 API Key，无法生成 AI 解释。请在设置中填写对应 Provider 的 API Key）"

        cache_key = self._cache_key(fi)
        if cache_key in self._cache:
            return self._cache[cache_key]

        prompt = self._build_single_prompt(fi)
        explanation = self._call_api(prompt)

        if explanation:
            self._cache[cache_key] = explanation
            self._save_cache()

        return explanation or "（AI 解释生成失败，请稍后重试）"

    def explain_batch(self, files: List[FileInfo],
                      progress_callback=None) -> Dict[str, str]:
        """
        批量解释文件列表（每次最多 10 个，减少 API 调用）。
        返回: {file_path: explanation}
        """
        results: Dict[str, str] = {}
        if not self.api_key:
            return results

        # 过滤已有缓存的文件
        to_fetch = [fi for fi in files if self._cache_key(fi) not in self._cache]

        batch_size = 8
        for i in range(0, len(to_fetch), batch_size):
            batch = to_fetch[i:i + batch_size]
            prompt = self._build_batch_prompt(batch)
            raw = self._call_api(prompt, max_tokens=LLM_MAX_TOKENS * len(batch))

            if raw:
                parsed = self._parse_batch_response(raw, batch)
                for fi, explanation in parsed.items():
                    self._cache[self._cache_key(fi)] = explanation
                    results[fi.path] = explanation
                self._save_cache()

            if progress_callback:
                progress_callback(min(i + batch_size, len(to_fetch)), len(to_fetch))

            time.sleep(0.3)  # 简单限速

        # 补充缓存命中的文件
        for fi in files:
            ck = self._cache_key(fi)
            if ck in self._cache and fi.path not in results:
                results[fi.path] = self._cache[ck]

        return results

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
    # 提示词构建
    # ──────────────────────────────────────────────────────────────────────────

    def _build_single_prompt(self, fi: FileInfo) -> str:
        days_ago = fi.atime_days_ago
        return f"""你是一个 Windows 系统文件分析专家。请用中文简洁地解释以下文件的用途，
以及删除它是否安全。回答控制在 100 字以内，直接给出结论，不要有多余客套话。

文件信息：
- 文件名：{fi.name}
- 路径：{fi.path}
- 大小：{fi.size_str}
- 扩展名：{fi.extension}
- 距今最后访问：{days_ago} 天
- 当前分类：{fi.category}
- 当前风险评级：{fi.risk_level}

请回答：① 这个文件是什么；② 删除后有什么影响；③ 给出一个简明建议（"可以删除"或"建议保留"或"需谨慎"）。"""

    def _build_batch_prompt(self, files: List[FileInfo]) -> str:
        lines = []
        for i, fi in enumerate(files):
            lines.append(
                f"{i+1}. 文件名={fi.name} | 路径={fi.path} | "
                f"大小={fi.size_str} | 扩展名={fi.extension} | "
                f"分类={fi.category} | 最后访问={fi.atime_days_ago}天前"
            )

        files_text = "\n".join(lines)
        return f"""你是 Windows 系统文件分析专家。请用中文分析以下 {len(files)} 个文件，
每个文件用一句话说明用途和删除建议（限 50 字）。

严格按 JSON 格式返回，不要有其他内容：
{{"1": "解释内容", "2": "解释内容", ...}}

文件列表：
{files_text}"""

    def _call_api(self, prompt: str, max_tokens: int = LLM_MAX_TOKENS) -> Optional[str]:
        """调用当前 provider 的 API，失败时返回 None"""
        try:
            if self.provider == LLMProvider.ANTHROPIC:
                return self._call_anthropic(prompt, max_tokens=max_tokens)
            if self.provider in (LLMProvider.OPENAI, LLMProvider.DEEPSEEK):
                return self._call_openai_compat(prompt, max_tokens=max_tokens)
            if self.provider == LLMProvider.GEMINI:
                return self._call_gemini(prompt, max_tokens=max_tokens)
        except Exception:
            return None
        return None

    # ──────────────────────────────────────────────────────────────────────────
    # Provider implementations
    # ──────────────────────────────────────────────────────────────────────────

    def _call_anthropic(self, prompt: str, max_tokens: int) -> Optional[str]:
        # 优先使用官方 SDK（如果已安装），否则走 HTTP
        try:
            import anthropic  # type: ignore
            client = anthropic.Anthropic(api_key=self.api_key)
            message = client.messages.create(
                model=self.model or DEFAULT_LLM_MODELS.get(LLMProvider.ANTHROPIC, ""),
                max_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}],
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
            "messages": [{"role": "user", "content": prompt}],
        }
        data = self._http_post_json(url, headers=headers, payload=payload)
        if not data:
            return None
        try:
            content = data.get("content") or []
            if content and isinstance(content, list):
                # [{"type":"text","text":"..."}]
                return content[0].get("text")
        except Exception:
            return None
        return None

    def _call_openai_compat(self, prompt: str, max_tokens: int) -> Optional[str]:
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
                return self._call_anthropic(prompt, max_tokens=max_tokens)
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
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
            "temperature": 0.2,
        }
        # 透传额外参数（用于 DeepSeek/OpenAI 特性开关等）
        if isinstance(self.extra_params, dict) and self.extra_params:
            payload.update(self.extra_params)
        data = self._http_post_json(url, headers=headers, payload=payload)
        if not data:
            return None
        try:
            choices = data.get("choices") or []
            if choices:
                msg = choices[0].get("message") or {}
                return msg.get("content")
        except Exception:
            return None
        return None

    def _call_gemini(self, prompt: str, max_tokens: int) -> Optional[str]:
        # Gemini：使用 Google Generative Language API（API Key 作为 query 参数）
        if not self.api_key:
            self.api_key = _env_first("GEMINI_API_KEY", "GOOGLE_API_KEY")

        model = self.model or DEFAULT_LLM_MODELS.get(LLMProvider.GEMINI, "")
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={self.api_key}"
        headers = {"Content-Type": "application/json"}
        payload = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {
                "maxOutputTokens": max_tokens,
                "temperature": 0.2,
            },
        }
        data = self._http_post_json(url, headers=headers, payload=payload)
        if not data:
            return None
        try:
            cands = data.get("candidates") or []
            if not cands:
                return None
            content = cands[0].get("content") or {}
            parts = content.get("parts") or []
            if parts:
                return parts[0].get("text")
        except Exception:
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
    # HTTP helper
    # ──────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _http_post_json(url: str, headers: Dict[str, str], payload: dict, timeout_s: int = 30) -> Optional[dict]:
        try:
            body = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(url, data=body, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
            return json.loads(raw)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            return None

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

    def _parse_batch_response(self, raw: str, files: List[FileInfo]) -> Dict[FileInfo, str]:
        """解析批量响应的 JSON"""
        result: Dict[FileInfo, str] = {}
        try:
            # 尝试提取 JSON 部分
            start = raw.find('{')
            end   = raw.rfind('}') + 1
            if start >= 0 and end > start:
                data = json.loads(raw[start:end])
                for i, fi in enumerate(files):
                    key = str(i + 1)
                    if key in data:
                        result[fi] = str(data[key])
        except (json.JSONDecodeError, Exception):
            # 降级：整体作为第一个文件的解释
            if files:
                result[files[0]] = raw[:200]
        return result

    # ──────────────────────────────────────────────────────────────────────────
    # 缓存
    # ──────────────────────────────────────────────────────────────────────────

    def _cache_key(self, fi: FileInfo) -> str:
        """
        用文件名+扩展名+路径片段+大小 构成缓存键（不含完整路径，允许跨机器复用）
        """
        # 缓存应与 provider/model 绑定，避免不同模型结果混用
        raw = (
            f"{fi.name}|{fi.extension}|{fi.category}|{fi.size // (1024*1024)}|"
            f"{getattr(fi, 'risk_level', '')}|{self.provider.value}|{self.model}"
        )
        return hashlib.md5(raw.encode()).hexdigest()

    def _load_cache(self) -> Dict[str, str]:
        try:
            if _CACHE_PATH.exists():
                return json.loads(_CACHE_PATH.read_text(encoding='utf-8'))
        except Exception:
            pass
        return {}

    def _save_cache(self):
        try:
            _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
            _CACHE_PATH.write_text(
                json.dumps(self._cache, ensure_ascii=False, indent=2),
                encoding='utf-8'
            )
        except Exception:
            pass
