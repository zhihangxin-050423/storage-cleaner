# scanner.py - 文件系统扫描器
"""
扫描用户指定目录，递归收集文件元数据，并通过哈希检测重复文件。
设计原则：
  - 只做数据收集，不做任何删除决策
  - 优雅处理权限错误与符号链接
  - 大文件使用部分哈希提升速度
  - 支持取消操作
"""
import os
import hashlib
import time
import threading
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable, Set

from config import (
    PARTIAL_HASH_THRESHOLD, PARTIAL_HASH_READ_SIZE,
    SYSTEM_CRITICAL_DIRS,
)


# ──────────────────────────────────────────────────────────────────────────────
# 数据结构
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class FileInfo:
    """单个文件的完整元数据"""
    path:          str
    name:          str
    size:          int          # bytes
    ctime:         float        # 创建时间 (epoch)
    mtime:         float        # 修改时间 (epoch)
    atime:         float        # 访问时间 (epoch)
    extension:     str          # 小写扩展名，含点
    hash_md5:      Optional[str] = None

    # 以下字段由 RuleEngine / RiskAssessor 填充
    category:      str          = ""
    risk_level:    str          = ""   # "低风险" / "中风险" / "高风险"
    risk_reason:   str          = ""   # 规则引擎给出的原因
    ai_explanation:str          = ""   # LLM 生成的解释

    # 重复文件信息
    is_duplicate:  bool         = False
    duplicate_of:  Optional[str] = None   # 原始文件路径

    # UI状态
    selected:      bool         = True   # 默认选中（低/中风险）

    @property
    def size_str(self) -> str:
        return _fmt_size(self.size)

    @property
    def atime_days_ago(self) -> int:
        return int((time.time() - self.atime) / 86400)

    @property
    def mtime_days_ago(self) -> int:
        return int((time.time() - self.mtime) / 86400)


@dataclass
class ScanResult:
    files:         List[FileInfo]         = field(default_factory=list)
    dir_sizes:     Dict[str, int]         = field(default_factory=dict)
    total_size:    int                    = 0
    total_files:   int                    = 0
    error_paths:   List[str]              = field(default_factory=list)
    scan_duration: float                  = 0.0
    # 重复组: hash -> [FileInfo, ...]
    duplicate_groups: Dict[str, List[FileInfo]] = field(default_factory=dict)


def _fmt_size(b: int) -> str:
    if b < 1024:
        return f"{b} B"
    elif b < 1024**2:
        return f"{b/1024:.1f} KB"
    elif b < 1024**3:
        return f"{b/1024**2:.1f} MB"
    else:
        return f"{b/1024**3:.2f} GB"


# ──────────────────────────────────────────────────────────────────────────────
# 扫描器
# ──────────────────────────────────────────────────────────────────────────────

class Scanner:
    """
    递归扫描指定根目录。

    progress_callback(scanned_files: int, total_size: int, current_path: str)
      在后台线程中被调用；UI 应通过 queue 或 after() 安全更新界面。
    """

    def __init__(self, progress_callback: Optional[Callable] = None):
        self.progress_callback = progress_callback
        self._cancel_flag = threading.Event()

    def cancel(self):
        """请求取消正在进行的扫描"""
        self._cancel_flag.set()

    def scan(self, root_path: str,
             skip_system: bool = True,
             compute_hashes: bool = True) -> ScanResult:
        """
        执行完整扫描。

        :param root_path:    扫描根目录
        :param skip_system:  是否跳过系统关键目录
        :param compute_hashes: 是否计算哈希（用于查重）
        :return: ScanResult
        """
        self._cancel_flag.clear()
        result = ScanResult()
        t0 = time.time()

        # 第一步：遍历目录树，收集文件元数据
        self._walk(root_path, result, skip_system)

        # 第二步：查找重复文件
        if compute_hashes and not self._cancel_flag.is_set():
            self._find_duplicates(result)

        result.scan_duration = time.time() - t0
        return result

    # ──────────────────────────────────────────────────────────────────────────
    # 内部方法
    # ──────────────────────────────────────────────────────────────────────────

    def _should_skip_dir(self, dirpath: str, skip_system: bool) -> bool:
        if not skip_system:
            return False
        nc = os.path.normcase(os.path.abspath(dirpath))
        for critical in SYSTEM_CRITICAL_DIRS:
            if nc == critical or nc.startswith(critical + os.sep):
                return True
        return False

    def _walk(self, root_path: str, result: ScanResult, skip_system: bool):
        """os.walk 递归，收集 FileInfo"""
        root_abs = os.path.normcase(os.path.abspath(root_path))
        scanned = 0
        for dirpath, dirnames, filenames in os.walk(root_path, followlinks=False):
            if self._cancel_flag.is_set():
                break

            # 跳过系统关键目录（就地修改 dirnames 阻止 os.walk 递归进入）
            if self._should_skip_dir(dirpath, skip_system):
                dirnames.clear()
                continue

            # 过滤子目录（防止递归进入已标记跳过的目录）
            dirnames[:] = [
                d for d in dirnames
                if not self._should_skip_dir(os.path.join(dirpath, d), skip_system)
            ]

            dir_size = 0
            for filename in filenames:
                if self._cancel_flag.is_set():
                    break

                filepath = os.path.join(dirpath, filename)
                try:
                    # 跳过符号链接，防止循环
                    if os.path.islink(filepath):
                        continue

                    stat = os.stat(filepath)
                    fi = FileInfo(
                        path      = filepath,
                        name      = filename,
                        size      = stat.st_size,
                        ctime     = stat.st_ctime,
                        mtime     = stat.st_mtime,
                        atime     = stat.st_atime,
                        extension = os.path.splitext(filename)[1].lower(),
                    )
                    result.files.append(fi)
                    dir_size         += fi.size
                    result.total_size += fi.size
                    scanned          += 1

                    # 递归目录聚合：将文件大小累加到所有父目录（直到扫描根目录）
                    # 这样 UI 的“目录占用 TOP”才是“包含子目录”的真实占用。
                    parent = os.path.normcase(os.path.abspath(os.path.dirname(filepath)))
                    while True:
                        result.dir_sizes[parent] = result.dir_sizes.get(parent, 0) + fi.size
                        if parent == root_abs:
                            break
                        next_parent = os.path.normcase(os.path.abspath(os.path.dirname(parent)))
                        if next_parent == parent:
                            break
                        # 防止跨盘/越界：不在 root_abs 下则停止
                        try:
                            if os.path.commonpath([root_abs, next_parent]) != root_abs:
                                break
                        except Exception:
                            break
                        parent = next_parent

                    if self.progress_callback and scanned % 50 == 0:
                        self.progress_callback(scanned, result.total_size, filepath)

                except (PermissionError, OSError, FileNotFoundError) as e:
                    result.error_paths.append(f"{filepath}: {e}")

            # 保留当前目录“直接子文件大小”统计（可用于未来扩展），不覆盖递归聚合值
            if dirpath not in result.dir_sizes:
                result.dir_sizes[dirpath] = dir_size

        result.total_files = len(result.files)
        if self.progress_callback:
            self.progress_callback(result.total_files, result.total_size, "扫描完成")

    def _find_duplicates(self, result: ScanResult):
        """
        两阶段查重：
          1. 按文件大小分组（>0 字节）；同组只有1个文件则跳过
          2. 同大小组内先计算“筛选哈希”（大文件用部分哈希，小文件用全量哈希），按哈希再次分组
          3. 对大文件候选重复组，再做一次全量哈希确认，避免部分哈希误判
        标记重复项（保留第一个为原始）。注意：只有通过确认哈希的才会被标记为重复。
        """
        size_groups: Dict[int, List[FileInfo]] = {}
        for fi in result.files:
            if fi.size > 0:
                size_groups.setdefault(fi.size, []).append(fi)

        hash_counter = 0
        for size, group in size_groups.items():
            if self._cancel_flag.is_set():
                break
            if len(group) < 2:
                continue

            hash_map: Dict[str, List[FileInfo]] = {}
            for fi in group:
                if self._cancel_flag.is_set():
                    break
                h = self._compute_hash(fi.path, size, mode="auto")
                if h:
                    # 先填入筛选哈希；若后续做全量确认，会覆盖为全量哈希
                    fi.hash_md5 = h
                    hash_map.setdefault(h, []).append(fi)
                hash_counter += 1
                if self.progress_callback and hash_counter % 20 == 0:
                    self.progress_callback(
                        result.total_files, result.total_size,
                        f"哈希检测中: {fi.name}"
                    )

            # 若为大文件，做全量哈希确认，避免部分哈希碰撞导致误判
            if size > PARTIAL_HASH_THRESHOLD:
                confirmed_map: Dict[str, List[FileInfo]] = {}
                for h, candidates in hash_map.items():
                    if self._cancel_flag.is_set():
                        break
                    if len(candidates) < 2:
                        continue
                    for fi in candidates:
                        if self._cancel_flag.is_set():
                            break
                        full = self._compute_hash(fi.path, size, mode="full")
                        if full:
                            fi.hash_md5 = full
                            confirmed_map.setdefault(full, []).append(fi)

                for full_h, dups in confirmed_map.items():
                    if len(dups) > 1:
                        result.duplicate_groups[full_h] = dups
                        for dup in dups[1:]:
                            dup.is_duplicate = True
                            dup.duplicate_of = dups[0].path
            else:
                for h, dups in hash_map.items():
                    if len(dups) > 1:
                        result.duplicate_groups[h] = dups
                        for dup in dups[1:]:
                            dup.is_duplicate = True
                            dup.duplicate_of = dups[0].path

    def _compute_hash(self, filepath: str, size: int, mode: str = "auto") -> Optional[str]:
        """
        计算文件 MD5。
        - mode="auto": 大文件（>PARTIAL_HASH_THRESHOLD）使用首尾各 64KB + 文件大小 拼接哈希（筛选用）
        - mode="full": 始终对全文件做 MD5（确认用，慢但准确）
        """
        try:
            hasher = hashlib.md5()
            with open(filepath, 'rb') as f:
                if mode == "full":
                    for chunk in iter(lambda: f.read(65536), b''):
                        hasher.update(chunk)
                elif size > PARTIAL_HASH_THRESHOLD:
                    # 首 64KB
                    hasher.update(f.read(PARTIAL_HASH_READ_SIZE))
                    # 尾 64KB
                    f.seek(-PARTIAL_HASH_READ_SIZE, 2)
                    hasher.update(f.read(PARTIAL_HASH_READ_SIZE))
                    # 文件大小作为区分因子
                    hasher.update(str(size).encode())
                else:
                    for chunk in iter(lambda: f.read(65536), b''):
                        hasher.update(chunk)
            return hasher.hexdigest()
        except (PermissionError, OSError, FileNotFoundError):
            return None
