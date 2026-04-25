# executor.py - 安全执行模块
"""
负责文件删除操作的安全执行。

安全机制：
  1. 优先使用 send2trash（移至系统回收站），支持恢复
  2. 永久删除需要二次确认
  3. 高风险文件拒绝删除（除非用户明确二次确认）
  4. 所有操作写入 JSON 操作日志，包含操作时间、文件信息、结果
  5. 批量删除在异常时继续处理其他文件，不整体中断
"""
import os
import json
import time
import shutil
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Callable, Tuple
from pathlib import Path

from config import RiskLevel, OPERATION_LOG_DIR, OPERATION_LOG_PATH, SYSTEM_CRITICAL_DIRS, HIGH_RISK_EXTENSIONS
from scanner import FileInfo, _fmt_size


# ──────────────────────────────────────────────────────────────────────────────
# 操作记录
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class OperationRecord:
    timestamp:   str
    action:      str          # "trash" | "delete" | "symlink" | "skip" | "error"
    file_path:   str
    file_size:   int
    file_name:   str
    risk_level:  str
    category:    str
    success:     bool
    error_msg:   str = ""

    def to_dict(self):
        return asdict(self)


@dataclass
class ExecutionResult:
    success_paths:    List[str] = field(default_factory=list)
    failed_paths:     List[str] = field(default_factory=list)
    skipped_paths:    List[str] = field(default_factory=list)
    freed_bytes:      int       = 0
    records:          List[OperationRecord] = field(default_factory=list)

    @property
    def freed_str(self) -> str:
        return _fmt_size(self.freed_bytes)

    @property
    def summary(self) -> str:
        return (f"成功: {len(self.success_paths)} 个 ({self.freed_str})  "
                f"失败: {len(self.failed_paths)} 个  "
                f"跳过: {len(self.skipped_paths)} 个")


# ──────────────────────────────────────────────────────────────────────────────
# 执行器
# ──────────────────────────────────────────────────────────────────────────────

class Executor:
    """
    安全执行文件删除操作。

    :param use_trash:   True  -> 移至回收站（可恢复，推荐）
                        False -> 永久删除（不可恢复，需额外确认）
    :param allow_high_risk: 是否允许删除高风险文件（默认 False）
    """

    def __init__(self,
                 use_trash: bool = True,
                 allow_high_risk: bool = False,
                 progress_callback: Optional[Callable] = None,
                 operation_log_dir: Optional[str] = None):
        self.use_trash      = use_trash
        self.allow_high_risk = allow_high_risk
        self.progress_callback = progress_callback
        self._has_send2trash = self._check_send2trash()
        self._operation_log_dir = Path(operation_log_dir) if operation_log_dir else Path(OPERATION_LOG_DIR)

    @property
    def operation_log_dir(self) -> Path:
        return self._operation_log_dir

    @operation_log_dir.setter
    def operation_log_dir(self, value):
        if value is None:
            self._operation_log_dir = Path(OPERATION_LOG_DIR)
        else:
            self._operation_log_dir = Path(str(value))

    @property
    def operation_log_path(self) -> Path:
        return self.operation_log_dir / "operation_log.json"

    # ──────────────────────────────────────────────────────────────────────────
    # 公共 API
    # ──────────────────────────────────────────────────────────────────────────

    def execute(self, files: List[FileInfo]) -> ExecutionResult:
        """
        对给定文件列表执行删除操作。
        每个文件均会记录到操作日志。
        """
        result = ExecutionResult()
        total = len(files)

        for idx, fi in enumerate(files):
            if self.progress_callback:
                self.progress_callback(idx + 1, total, fi.path)

            record = self._process_file(fi)
            result.records.append(record)

            if record.action == "skip":
                result.skipped_paths.append(fi.path)
            elif record.success:
                result.success_paths.append(fi.path)
                result.freed_bytes += fi.size
            else:
                result.failed_paths.append(fi.path)

        self._append_log(result.records)
        return result

    def get_operation_log(self) -> List[dict]:
        """读取历史操作日志"""
        try:
            p = self.operation_log_path
            if p.exists():
                return json.loads(p.read_text(encoding='utf-8'))
        except Exception:
            pass
        return []

    def clear_log(self):
        try:
            p = self.operation_log_path
            if p.exists():
                p.unlink()
        except Exception:
            pass

    # ──────────────────────────────────────────────────────────────────────────
    # 软链接
    # ──────────────────────────────────────────────────────────────────────────

    def is_symlink_candidate(self, fi: FileInfo) -> Tuple[bool, str]:
        """
        判断文件是否适合创建软链接。
        目标：避免对系统关键文件/高风险文件/特殊文件做软链接操作导致误用。
        """
        try:
            # 必须是普通文件且存在
            if not os.path.isfile(fi.path):
                return False, "仅支持为普通文件创建软链接（不支持目录/特殊项）"
            if not os.path.exists(fi.path):
                return False, "源文件不存在"
            if os.path.islink(fi.path):
                return False, "源文件本身已是链接，不建议再创建链接"

            # 高风险文件不支持（保守策略）
            if fi.risk_level == RiskLevel.HIGH.value:
                return False, "该文件被标记为高风险，默认不提供软链接功能"

            # 系统关键目录拒绝
            nc = os.path.normcase(os.path.abspath(fi.path))
            for critical in SYSTEM_CRITICAL_DIRS:
                if nc.startswith(critical + os.sep) or nc == critical:
                    return False, "位于系统关键目录，禁止创建软链接"

            # 高风险扩展名拒绝（双保险）
            if fi.extension in HIGH_RISK_EXTENSIONS:
                return False, f"扩展名 {fi.extension} 属于系统/配置关键类型，不适合创建软链接"

            # 常见系统关键文件名（防误用）
            name_l = (fi.name or "").lower()
            if name_l in ("pagefile.sys", "hiberfil.sys", "swapfile.sys"):
                return False, "系统内存文件，不适合创建软链接"

            return True, ""
        except Exception as e:
            return False, f"校验失败: {e}"

    def create_symlink(self, fi: FileInfo, link_path: str) -> OperationRecord:
        """
        创建指向源文件的软链接（Windows 符号链接）。
        说明：
          - 不会修改/移动源文件
          - 可能需要 Windows “开发者模式”或管理员权限
          - 会写入操作日志
        """
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        base = dict(
            timestamp=ts,
            file_path=fi.path,
            file_size=fi.size,
            file_name=fi.name,
            risk_level=fi.risk_level,
            category=fi.category,
        )

        ok, reason = self.is_symlink_candidate(fi)
        if not ok:
            rec = OperationRecord(
                **base, action="skip", success=False,
                error_msg=f"不适合创建软链接: {reason}",
            )
            self._append_log([rec])
            return rec

        try:
            link_abs = os.path.abspath(link_path)
            parent = os.path.dirname(link_abs)
            if not parent or not os.path.isdir(parent):
                os.makedirs(parent, exist_ok=True)

            if os.path.exists(link_abs) or os.path.islink(link_abs):
                rec = OperationRecord(
                    **base, action="error", success=False,
                    error_msg=f"链接路径已存在: {link_abs}",
                )
                self._append_log([rec])
                return rec

            # 创建文件软链接
            os.symlink(fi.path, link_abs, target_is_directory=False)

            rec = OperationRecord(
                **base, action="symlink", success=True,
                error_msg=f"已创建软链接 -> {link_abs}",
            )
            self._append_log([rec])
            return rec
        except OSError as e:
            # Windows 常见：权限不足 / 未开启开发者模式
            hint = (
                "创建软链接失败，可能原因：未开启 Windows 开发者模式或未以管理员权限运行。"
                "可在“设置 → 隐私和安全性 → 开发者选项”中开启开发者模式后重试。"
            )
            rec = OperationRecord(
                **base, action="error", success=False,
                error_msg=f"{e}；{hint}",
            )
            self._append_log([rec])
            return rec
        except Exception as e:
            rec = OperationRecord(
                **base, action="error", success=False,
                error_msg=f"创建软链接失败: {e}",
            )
            self._append_log([rec])
            return rec

    # ──────────────────────────────────────────────────────────────────────────
    # 内部方法
    # ──────────────────────────────────────────────────────────────────────────

    def _process_file(self, fi: FileInfo) -> OperationRecord:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        base = dict(
            timestamp  = ts,
            file_path  = fi.path,
            file_size  = fi.size,
            file_name  = fi.name,
            risk_level = fi.risk_level,
            category   = fi.category,
        )

        # 安全检查：高风险文件
        if fi.risk_level == RiskLevel.HIGH.value and not self.allow_high_risk:
            return OperationRecord(
                **base, action="skip", success=False,
                error_msg="高风险文件，已跳过（需在高风险确认模式下才能删除）",
            )

        # 检查文件是否仍然存在
        if not os.path.exists(fi.path):
            return OperationRecord(
                **base, action="skip", success=False,
                error_msg="文件不存在，可能已被其他操作删除",
            )

        # 执行删除
        if self.use_trash and self._has_send2trash:
            return self._trash(fi, base)
        else:
            return self._permanent_delete(fi, base)

    def _trash(self, fi: FileInfo, base: dict) -> OperationRecord:
        """移至回收站"""
        try:
            import send2trash
            send2trash.send2trash(fi.path)
            return OperationRecord(**base, action="trash", success=True)
        except Exception as e:
            # 安全策略：回收站失败时不得静默降级为永久删除（避免“以为可恢复，实际不可恢复”）
            return OperationRecord(
                **base,
                action="error",
                success=False,
                error_msg=f"移至回收站失败（未执行永久删除）: {e}",
            )

    def _permanent_delete(self, fi: FileInfo, base: dict) -> OperationRecord:
        """永久删除（不可恢复）"""
        try:
            if os.path.isfile(fi.path):
                os.remove(fi.path)
            elif os.path.isdir(fi.path):
                shutil.rmtree(fi.path, ignore_errors=True)
            return OperationRecord(**base, action="delete", success=True)
        except PermissionError as e:
            return OperationRecord(
                **base, action="error", success=False,
                error_msg=f"权限不足: {e}",
            )
        except Exception as e:
            return OperationRecord(
                **base, action="error", success=False,
                error_msg=f"删除失败: {e}",
            )

    def _append_log(self, records: List[OperationRecord]):
        """将新记录追加到 JSON 日志文件"""
        try:
            self.operation_log_dir.mkdir(parents=True, exist_ok=True)
            existing = self.get_operation_log()
            existing.extend([r.to_dict() for r in records])
            # 日志最多保留 10000 条
            if len(existing) > 10000:
                existing = existing[-10000:]
            self.operation_log_path.write_text(
                json.dumps(existing, ensure_ascii=False, indent=2),
                encoding='utf-8'
            )
        except Exception:
            pass

    @staticmethod
    def _check_send2trash() -> bool:
        try:
            import send2trash
            return True
        except ImportError:
            return False
