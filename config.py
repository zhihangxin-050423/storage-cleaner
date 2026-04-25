# config.py - 全局配置与常量定义
import os
import pathlib
from enum import Enum
from typing import Set

# ──────────────────────────────────────────────────────────────────────────────
# 风险等级 & 文件类别
# ──────────────────────────────────────────────────────────────────────────────

class RiskLevel(Enum):
    LOW    = "低风险"
    MEDIUM = "中风险"
    HIGH   = "高风险"

class FileCategory(Enum):
    TEMP         = "临时文件"
    CACHE        = "缓存文件"
    LOG          = "日志文件"
    DUPLICATE    = "重复文件"
    LARGE        = "大文件"
    OLD_FILE     = "长期未访问"
    INSTALLER    = "安装包"
    SYSTEM       = "系统文件"
    CONFIG       = "配置文件"
    DOWNLOAD     = "下载文件"
    APP_RESIDUAL = "应用残留"
    ARCHIVE      = "压缩包"
    MEDIA        = "媒体文件"
    DOCUMENT     = "文档文件"
    UNKNOWN      = "未知文件"

# UI颜色
RISK_BG = {
    RiskLevel.LOW:    "#E8F5E9",  # 淡绿
    RiskLevel.MEDIUM: "#FFF3E0",  # 淡橙
    RiskLevel.HIGH:   "#FFEBEE",  # 淡红
}
RISK_FG = {
    RiskLevel.LOW:    "#2E7D32",
    RiskLevel.MEDIUM: "#E65100",
    RiskLevel.HIGH:   "#B71C1C",
}
RISK_TAG = {
    RiskLevel.LOW:    "low",
    RiskLevel.MEDIUM: "medium",
    RiskLevel.HIGH:   "high",
}

# ──────────────────────────────────────────────────────────────────────────────
# Windows 系统路径定义
# ──────────────────────────────────────────────────────────────────────────────

def _nc(p: str) -> str:
    """normcase + abspath，用于路径比较"""
    try:
        return os.path.normcase(os.path.abspath(p)) if p else ""
    except Exception:
        return ""

_env = os.environ

# 系统关键目录（高风险白名单）
SYSTEM_CRITICAL_DIRS = list(filter(None, [
    _nc(_env.get("SystemRoot",   r"C:\Windows")),
    _nc(_env.get("ProgramFiles", r"C:\Program Files")),
    _nc(_env.get("ProgramW6432", r"C:\Program Files")),
    _nc(r"C:\ProgramData\Microsoft"),
    _nc(r"C:\ProgramData\Windows"),
]))

# 已知临时/缓存目录（低风险）
_local = _env.get("LOCALAPPDATA", "")
_roaming = _env.get("APPDATA", "")
_temp = _env.get("TEMP", "")

KNOWN_TEMP_DIRS = list(filter(None, [
    _nc(_temp),
    _nc(_env.get("TMP", "")),
    _nc(os.path.join(_local, "Temp")),
    _nc(os.path.join(_local, "Microsoft", "Windows", "INetCache")),
    _nc(os.path.join(_local, "Microsoft", "Windows", "Temporary Internet Files")),
]))

# 缓存路径片段（小写，用于 in 判断）
KNOWN_CACHE_FRAGMENTS = [
    r"appdata\local\temp",
    r"appdata\locallow\temp",
    r"appdata\local\microsoft\windows\inetcache",
    r"appdata\local\microsoft\windows\wer",
    r"appdata\local\crashdumps",
    r"appdata\local\google\chrome\user data\default\cache",
    r"appdata\local\google\chrome\user data\default\code cache",
    r"appdata\local\google\chrome\user data\default\gpucache",
    r"appdata\local\microsoft\edge\user data\default\cache",
    r"appdata\local\microsoft\edge\user data\default\code cache",
    r"appdata\roaming\npm-cache",
    r"appdata\local\pip\cache",
    r"appdata\local\yarn\cache",
    r"appdata\local\nuget\cache",
    r"\node_modules\.cache",
    r"\__pycache__",
    r"\.pytest_cache",
    r"\.mypy_cache",
    r"\.tox",
    r"appdata\local\jetbrains",
    r"appdata\local\microsoft\visualstudio\*\componentmodelcache",
    # Windows / UWP 常见缓存
    r"appdata\local\microsoft\windows\webcache",
    r"appdata\local\microsoft\windows\explorer\thumbcache*.db",
    r"appdata\local\packages\*\localcache",
    r"appdata\local\packages\*\ac\inetcache",
    r"appdata\local\packages\*\tempstate",
    # 常见应用缓存（按需扩展）
    r"appdata\roaming\code\cache",
    r"appdata\roaming\code\cacheddata",
    r"appdata\roaming\code\gpuCache",
    r"appdata\roaming\discord\cache",
    r"appdata\roaming\discord\code cache",
    r"appdata\roaming\discord\gpuCache",
    r"appdata\roaming\slack\cache",
    r"appdata\roaming\slack\code cache",
    r"appdata\roaming\slack\gpuCache",
    r"appdata\roaming\microsoft\teams\cache",
    r"appdata\roaming\microsoft\teams\code cache",
    r"appdata\roaming\microsoft\teams\gpuCache",
]

# 应用残留路径片段（中风险）
APP_RESIDUAL_FRAGMENTS = [
    r"appdata\roaming\microsoft\windows\recent",
    r"appdata\local\microsoft\windows\explorer",  # thumbcache
    r"appdata\local\d3dscrapcache",
    r"appdata\local\microsoft\windows\inetcookies",
]

# 中风险：可再生成但可能影响体验/离线能力的“大型缓存/包仓库/构建产物”
MEDIUM_RISK_CACHE_FRAGMENTS = [
    r"\.gradle\caches",
    r"\.m2\repository",
    r"\.ivy2\cache",
    r"\.cargo\registry",
    r"\.cargo\git",
    r"\.nuget\packages",
    r"\pip\cache",
    r"\conda\pkgs",
    r"\pnpm-store",
]

# 中风险：常见构建/产物目录（通常可重建，但建议确认）
BUILD_ARTIFACT_FRAGMENTS = [
    r"\dist\\",
    r"\build\\",
    r"\out\\",
    r"\target\\",
    r"\coverage\\",
    r"\.next\\",
    r"\.nuxt\\",
    r"\.angular\\",
    r"\.svelte-kit\\",
    r"\obj\\",
    r"\bin\\",
    r"\.terraform\\",
]

# ──────────────────────────────────────────────────────────────────────────────
# 文件扩展名分组
# ──────────────────────────────────────────────────────────────────────────────

LOW_RISK_EXTENSIONS: Set[str] = {
    '.tmp', '.temp', '.cache', '.dmp',
    '.swp', '.swo', '.lock', '.lck',
    '.crdownload', '.part', '.partial', '.download',
}

MEDIUM_RISK_EXTENSIONS: Set[str] = {
    '.log', '.bak', '.old', '.orig', '.backup', '.bk',
}

INSTALLER_EXTENSIONS: Set[str] = {
    '.exe', '.msi', '.pkg', '.iso', '.img', '.bin',
}

ARCHIVE_EXTENSIONS: Set[str] = {
    '.zip', '.7z', '.rar', '.tar', '.gz', '.bz2', '.xz', '.zst', '.cab',
}

LOG_EXTENSIONS: Set[str] = {'.log', '.logs', '.log1', '.log2'}

HIGH_RISK_EXTENSIONS: Set[str] = {
    '.dll', '.sys', '.ini', '.cfg', '.conf', '.config',
    '.reg', '.bat', '.cmd', '.ps1', '.vbs', '.wsf',
    '.dat', '.db', '.sqlite', '.sqlite3', '.mdb', '.accdb',
    '.pem', '.key', '.pfx', '.p12', '.cer', '.crt',
}

MEDIA_EXTENSIONS: Set[str] = {
    '.mp4', '.mkv', '.avi', '.mov', '.wmv', '.flv', '.m4v', '.webm',
    '.mp3', '.flac', '.wav', '.aac', '.ogg', '.wma', '.m4a',
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.tiff',
    '.raw', '.cr2', '.nef', '.arw', '.heic',
}

DOCUMENT_EXTENSIONS: Set[str] = {
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.txt', '.md', '.rtf', '.odt', '.ods', '.odp', '.csv',
}

# ──────────────────────────────────────────────────────────────────────────────
# 阈值设置
# ──────────────────────────────────────────────────────────────────────────────

LARGE_FILE_THRESHOLD        = 500  * 1024 * 1024  # 500 MB
MEDIUM_LARGE_THRESHOLD      = 100  * 1024 * 1024  # 100 MB
PARTIAL_HASH_THRESHOLD      = 100  * 1024 * 1024  # >100MB 使用部分哈希
PARTIAL_HASH_READ_SIZE      =  64  * 1024          # 64 KB
OLD_FILE_DAYS               = 365                  # 1年未访问 -> 中风险
VERY_OLD_FILE_DAYS          = 730                  # 2年未访问 -> 提升关注度

DOWNLOADS_DIR = str(pathlib.Path.home() / "Downloads")

# ──────────────────────────────────────────────────────────────────────────────
# LLM 配置
# ──────────────────────────────────────────────────────────────────────────────

class LLMProvider(Enum):
    ANTHROPIC = "Claude (Anthropic)"
    OPENAI    = "ChatGPT (OpenAI)"
    DEEPSEEK  = "DeepSeek (OpenAI兼容)"
    GEMINI    = "Gemini (Google)"

# 默认 Provider（UI 可改）
LLM_PROVIDER: LLMProvider = LLMProvider.ANTHROPIC

# 默认模型（可在 UI 中覆盖）
DEFAULT_LLM_MODELS = {
    LLMProvider.ANTHROPIC: "claude-sonnet-4-20250514",
    # OpenAI: 这里用常见模型名作为默认值；你也可以填 gpt-4o / o3-mini 等
    LLMProvider.OPENAI:    "gpt-4o-mini",
    # DeepSeek: 官方推荐新模型
    LLMProvider.DEEPSEEK:  "deepseek-v4-flash",
    # Gemini: 常用 gemini-1.5-flash / gemini-1.5-pro / gemini-2.0-flash 等
    LLMProvider.GEMINI:    "gemini-1.5-flash",
}

# OpenAI/DeepSeek 兼容接口的 Base URL（可在 UI 中覆盖）
DEFAULT_OPENAI_BASE_URL   = "https://api.openai.com"
DEFAULT_DEEPSEEK_BASE_URL = "https://api.deepseek.com"
DEFAULT_DEEPSEEK_ANTHROPIC_BASE_URL = "https://api.deepseek.com/anthropic"

LLM_MAX_TOKENS = 600

# ──────────────────────────────────────────────────────────────────────────────
# 日志路径
# ──────────────────────────────────────────────────────────────────────────────

# 默认把日志放在“项目目录”下，避免散落在用户目录里难以区分/迁移
# 项目结构：<project_root>/storage_cleaner/config.py
PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]

# 允许用户在设置中自定义日志目录；这里提供默认值（目录而不是单文件）
LOG_BASE_DIR        = PROJECT_ROOT / "logs"
LOG_DIR             = LOG_BASE_DIR          # 向后兼容别名，供 explainer.py 等模块使用
OPERATION_LOG_DIR   = LOG_BASE_DIR / "operation"
OPERATION_LOG_PATH  = OPERATION_LOG_DIR / "operation_log.json"
