import os
from pathlib import Path
from typing import Iterable, List, Sequence, Set


def _norm_parts(path: str) -> List[str]:
    """
    将任意路径标准化为小写 parts（不依赖分隔符形式，避免 frag in path 误判）。
    例如：C:\\a\\b\\dist\\x -> ["c:", "a", "b", "dist", "x"]
    """
    try:
        p = Path(os.path.normcase(os.path.abspath(path)))
        return [str(x).strip().lower() for x in p.parts if str(x).strip()]
    except Exception:
        # 最差降级：按分隔符拆分
        s = os.path.normcase(path or "").replace("/", "\\")
        return [x.strip().lower() for x in s.split("\\") if x.strip()]


def has_segment(path: str, segment: str) -> bool:
    seg = (segment or "").strip().lower()
    if not seg:
        return False
    return seg in _norm_parts(path)


def has_any_segment(path: str, segments: Iterable[str]) -> bool:
    parts = set(_norm_parts(path))
    for s in segments:
        ss = (s or "").strip().lower()
        if ss and ss in parts:
            return True
    return False


def contains_sequence(path: str, seq: Sequence[str]) -> bool:
    """
    判断 parts 中是否包含连续片段序列（例如 ["node_modules", ".cache"]）。
    """
    parts = _norm_parts(path)
    needle = [str(x).strip().lower() for x in seq if str(x).strip()]
    if not needle:
        return False
    n = len(needle)
    for i in range(0, max(0, len(parts) - n) + 1):
        if parts[i:i + n] == needle:
            return True
    return False


def ends_with_any_segment(path: str, suffixes: Set[str]) -> bool:
    parts = _norm_parts(path)
    if not parts:
        return False
    last = parts[-1]
    return last in {s.strip().lower() for s in suffixes if s and s.strip()}


def is_chromium_profile_cache(path: str) -> bool:
    """
    识别 Chromium 系浏览器多 Profile 缓存：
    ...\\User Data\\Default\\Cache
    ...\\User Data\\Profile 1\\Code Cache
    ...\\User Data\\Profile 2\\GPUCache
    """
    parts = _norm_parts(path)
    # 快速路径：包含 user data
    try:
        idx = parts.index("user data")
    except ValueError:
        return False
    tail = parts[idx + 1 :]
    if len(tail) < 2:
        return False
    profile = tail[0]
    if profile != "default" and not profile.startswith("profile "):
        return False
    rest = tail[1:]
    # Cache / Code Cache / GPUCache
    for name in ("cache", "code cache", "gpucache"):
        if name in rest:
            return True
    return False


def is_firefox_profile_cache(path: str) -> bool:
    """
    识别 Firefox Profiles 缓存：
    ...\\Firefox\\Profiles\\*.default*\\cache2
    """
    parts = _norm_parts(path)
    if "profiles" not in parts:
        return False
    if "cache2" in parts:
        return True
    return False


def contains_all_segments(path: str, segments: Sequence[str]) -> bool:
    """判断 path.parts 是否同时包含所有给定段（不要求连续）。"""
    parts = set(_norm_parts(path))
    need = [str(s).strip().lower() for s in segments if str(s).strip()]
    return all(s in parts for s in need)


def any_segment_startswith(path: str, prefix: str) -> bool:
    """是否存在目录段以 prefix 开头（用于 cmake-build-* 等）。"""
    pre = (prefix or "").strip().lower()
    if not pre:
        return False
    for part in _norm_parts(path):
        if part.startswith(pre):
            return True
    return False

