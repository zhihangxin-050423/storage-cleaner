# rule_engine.py - 规则引擎
"""
基于路径、文件类型、访问时间、系统目录白名单/黑名单等规则，
对文件进行分类和初步风险评估。

设计原则：
  - 规则之间独立，每条规则返回自己的 RuleResult
  - 规则不依赖 AI，所有判断均可解释
  - 规则引擎按优先级排序，最后由 RiskAssessor 综合决策
"""
import os
import time
import fnmatch
from dataclasses import dataclass
from typing import Optional, List, Tuple

from config import (
    RiskLevel, FileCategory,
    SYSTEM_CRITICAL_DIRS, KNOWN_TEMP_DIRS, KNOWN_CACHE_FRAGMENTS,
    APP_RESIDUAL_FRAGMENTS,
    MEDIUM_RISK_CACHE_FRAGMENTS, BUILD_ARTIFACT_FRAGMENTS,
    LOW_RISK_EXTENSIONS, MEDIUM_RISK_EXTENSIONS, HIGH_RISK_EXTENSIONS,
    INSTALLER_EXTENSIONS, ARCHIVE_EXTENSIONS, LOG_EXTENSIONS,
    MEDIA_EXTENSIONS, DOCUMENT_EXTENSIONS,
    LARGE_FILE_THRESHOLD, MEDIUM_LARGE_THRESHOLD,
    OLD_FILE_DAYS, VERY_OLD_FILE_DAYS,
    DOWNLOADS_DIR,
    LOG_DIR,
)
from scanner import FileInfo


# ──────────────────────────────────────────────────────────────────────────────
# 规则结果数据结构
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class RuleResult:
    matched:    bool
    risk_level: Optional[RiskLevel]
    category:   Optional[FileCategory]
    reason:     str                       # 人类可读原因
    priority:   int = 0                  # 数字越大优先级越高


# ──────────────────────────────────────────────────────────────────────────────
# 规则基类
# ──────────────────────────────────────────────────────────────────────────────

class BaseRule:
    """所有规则必须实现 apply() 方法"""
    name: str = "BaseRule"
    priority: int = 0

    def apply(self, fi: FileInfo) -> RuleResult:
        raise NotImplementedError

    @staticmethod
    def _normpath(p: str) -> str:
        return os.path.normcase(os.path.abspath(p))


# ──────────────────────────────────────────────────────────────────────────────
# 具体规则实现
# ──────────────────────────────────────────────────────────────────────────────

class SystemDirectoryRule(BaseRule):
    """在系统关键目录中的文件 -> 高风险"""
    name = "SystemDirectory"
    priority = 100   # 最高优先级

    def apply(self, fi: FileInfo) -> RuleResult:
        nc = self._normpath(fi.path)
        for critical in SYSTEM_CRITICAL_DIRS:
            if nc.startswith(critical + os.sep) or nc == critical:
                return RuleResult(
                    matched=True,
                    risk_level=RiskLevel.HIGH,
                    category=FileCategory.SYSTEM,
                    reason=f"位于系统关键目录 ({os.path.basename(critical)})，禁止自动删除",
                    priority=self.priority,
                )
        return RuleResult(matched=False, risk_level=None, category=None, reason="", priority=0)


class KnownTempDirRule(BaseRule):
    """在已知临时目录中的文件 -> 低风险"""
    name = "KnownTempDir"
    priority = 90

    def apply(self, fi: FileInfo) -> RuleResult:
        nc = self._normpath(fi.path)
        for temp_dir in KNOWN_TEMP_DIRS:
            if temp_dir and nc.startswith(temp_dir + os.sep):
                return RuleResult(
                    matched=True,
                    risk_level=RiskLevel.LOW,
                    category=FileCategory.TEMP,
                    reason=f"位于系统临时目录，可安全清理",
                    priority=self.priority,
                )
        return RuleResult(matched=False, risk_level=None, category=None, reason="", priority=0)


class KnownCacheDirRule(BaseRule):
    """路径包含已知缓存目录特征 -> 低风险"""
    name = "KnownCacheDir"
    priority = 85

    def apply(self, fi: FileInfo) -> RuleResult:
        nc = os.path.normcase(fi.path)
        for frag in KNOWN_CACHE_FRAGMENTS:
            # 支持通配符片段（如包含 * ?），否则使用简单子串匹配
            try:
                if ("*" in frag or "?" in frag) and fnmatch.fnmatch(nc, f"*{frag}*"):
                    app_hint = self._extract_app(frag)
                    return RuleResult(
                        matched=True,
                        risk_level=RiskLevel.LOW,
                        category=FileCategory.CACHE,
                        reason=f"位于已知缓存目录{app_hint}，可安全清理",
                        priority=self.priority,
                    )
            except Exception:
                pass

            if frag in nc:
                app_hint = self._extract_app(frag)
                return RuleResult(
                    matched=True,
                    risk_level=RiskLevel.LOW,
                    category=FileCategory.CACHE,
                    reason=f"位于已知缓存目录{app_hint}，可安全清理",
                    priority=self.priority,
                )
        return RuleResult(matched=False, risk_level=None, category=None, reason="", priority=0)

    @staticmethod
    def _extract_app(frag: str) -> str:
        if "chrome" in frag:   return " (Google Chrome)"
        if "edge" in frag:     return " (Microsoft Edge)"
        if "firefox" in frag:  return " (Firefox)"
        if "npm" in frag:      return " (npm)"
        if "pip" in frag:      return " (pip)"
        if "yarn" in frag:     return " (Yarn)"
        if "nuget" in frag:    return " (NuGet)"
        if "__pycache__" in frag: return " (Python字节码)"
        if "pytest" in frag:   return " (pytest)"
        if "visualstudio" in frag: return " (Visual Studio)"
        if "jetbrains" in frag: return " (JetBrains)"
        if "discord" in frag:  return " (Discord)"
        if "teams" in frag:    return " (Microsoft Teams)"
        if "slack" in frag:    return " (Slack)"
        if "code\\cache" in frag or "roaming\\code" in frag: return " (VS Code)"
        if "thumbcache" in frag: return " (缩略图缓存)"
        return ""


class MediumRiskCacheRule(BaseRule):
    """大型缓存/包仓库（可再生成，但可能影响体验） -> 中风险"""
    name = "MediumRiskCache"
    priority = 83

    def apply(self, fi: FileInfo) -> RuleResult:
        nc = os.path.normcase(fi.path)
        for frag in MEDIUM_RISK_CACHE_FRAGMENTS:
            try:
                if ("*" in frag or "?" in frag) and fnmatch.fnmatch(nc, f"*{frag}*"):
                    return RuleResult(
                        matched=True,
                        risk_level=RiskLevel.MEDIUM,
                        category=FileCategory.CACHE,
                        reason="位于大型缓存/包仓库目录，通常可重新下载或重建，但建议确认后清理",
                        priority=self.priority,
                    )
            except Exception:
                pass
            if frag in nc:
                return RuleResult(
                    matched=True,
                    risk_level=RiskLevel.MEDIUM,
                    category=FileCategory.CACHE,
                    reason="位于大型缓存/包仓库目录，通常可重新下载或重建，但建议确认后清理",
                    priority=self.priority,
                )
        return RuleResult(matched=False, risk_level=None, category=None, reason="", priority=0)


class BuildArtifactRule(BaseRule):
    """常见构建产物目录 -> 中风险"""
    name = "BuildArtifact"
    priority = 78

    def apply(self, fi: FileInfo) -> RuleResult:
        # 构建产物通常可重建，但可能影响当前项目构建/调试，因此默认中风险
        nc = os.path.normcase(fi.path)
        for frag in BUILD_ARTIFACT_FRAGMENTS:
            if frag in nc:
                return RuleResult(
                    matched=True,
                    risk_level=RiskLevel.MEDIUM,
                    category=FileCategory.CACHE,
                    reason="位于常见构建/产物目录（通常可重建），建议确认后清理",
                    priority=self.priority,
                )
        return RuleResult(matched=False, risk_level=None, category=None, reason="", priority=0)


class LogDirHeuristicRule(BaseRule):
    """目录名语义识别日志文件（logs/log） -> 低/中风险"""
    name = "LogDirHeuristic"
    priority = 68

    def apply(self, fi: FileInfo) -> RuleResult:
        # 只对常见“日志类扩展名”启发式判断，避免误伤普通文本/数据文件
        if fi.extension not in (".log", ".txt", ".json", ".csv"):
            return RuleResult(matched=False, risk_level=None, category=None, reason="", priority=0)

        parent = os.path.basename(os.path.dirname(fi.path)).lower()
        if parent not in ("log", "logs"):
            return RuleResult(matched=False, risk_level=None, category=None, reason="", priority=0)

        days = fi.mtime_days_ago
        risk = RiskLevel.LOW if days > 30 else RiskLevel.MEDIUM
        return RuleResult(
            matched=True,
            risk_level=risk,
            category=FileCategory.LOG,
            reason=(f"位于日志目录（{parent}），最后修改 {days} 天前，"
                    + ("可清理" if risk == RiskLevel.LOW else "可能仍在写入，建议确认")),
            priority=self.priority,
        )


class AppResidualRule(BaseRule):
    """应用残留路径 -> 中风险"""
    name = "AppResidual"
    priority = 80

    def apply(self, fi: FileInfo) -> RuleResult:
        nc = os.path.normcase(fi.path)
        for frag in APP_RESIDUAL_FRAGMENTS:
            # 支持通配符片段
            try:
                if ("*" in frag or "?" in frag) and fnmatch.fnmatch(nc, f"*{frag}*"):
                    return RuleResult(
                        matched=True,
                        risk_level=RiskLevel.MEDIUM,
                        category=FileCategory.APP_RESIDUAL,
                        reason="应用程序残留文件，通常可清理但建议确认",
                        priority=self.priority,
                    )
            except Exception:
                pass
            if frag in nc:
                return RuleResult(
                    matched=True,
                    risk_level=RiskLevel.MEDIUM,
                    category=FileCategory.APP_RESIDUAL,
                    reason="应用程序残留文件，通常可清理但建议确认",
                    priority=self.priority,
                )
        return RuleResult(matched=False, risk_level=None, category=None, reason="", priority=0)


class LowRiskExtensionRule(BaseRule):
    """低风险扩展名：.tmp/.cache/.dmp 等 -> 低风险"""
    name = "LowRiskExtension"
    priority = 70

    def apply(self, fi: FileInfo) -> RuleResult:
        if fi.extension in LOW_RISK_EXTENSIONS:
            return RuleResult(
                matched=True,
                risk_level=RiskLevel.LOW,
                category=FileCategory.TEMP,
                reason=f"扩展名 {fi.extension!r} 为典型临时文件，可安全删除",
                priority=self.priority,
            )
        return RuleResult(matched=False, risk_level=None, category=None, reason="", priority=0)


class LogFileRule(BaseRule):
    """.log 文件 -> 中风险（日志文件可能仍在写入）"""
    name = "LogFile"
    priority = 70

    def apply(self, fi: FileInfo) -> RuleResult:
        if fi.extension in LOG_EXTENSIONS:
            days = fi.mtime_days_ago
            risk = RiskLevel.LOW if days > 30 else RiskLevel.MEDIUM
            return RuleResult(
                matched=True,
                risk_level=risk,
                category=FileCategory.LOG,
                reason=(f"日志文件，最后修改 {days} 天前，"
                        + ("可清理" if risk == RiskLevel.LOW else "可能仍在使用，建议确认")),
                priority=self.priority,
            )
        return RuleResult(matched=False, risk_level=None, category=None, reason="", priority=0)


class MediumRiskExtensionRule(BaseRule):
    """.bak/.old/.orig 等 -> 中风险"""
    name = "MediumRiskExtension"
    priority = 65

    def apply(self, fi: FileInfo) -> RuleResult:
        if fi.extension in MEDIUM_RISK_EXTENSIONS:
            return RuleResult(
                matched=True,
                risk_level=RiskLevel.MEDIUM,
                category=FileCategory.TEMP,
                reason=f"扩展名 {fi.extension!r} 为备份/旧版文件，建议确认后删除",
                priority=self.priority,
            )
        return RuleResult(matched=False, risk_level=None, category=None, reason="", priority=0)


class InstallerRule(BaseRule):
    """安装包文件（.exe/.msi/.iso 在下载目录） -> 中风险"""
    name = "Installer"
    priority = 65

    def apply(self, fi: FileInfo) -> RuleResult:
        if fi.extension not in INSTALLER_EXTENSIONS:
            return RuleResult(matched=False, risk_level=None, category=None, reason="", priority=0)

        in_downloads = os.path.normcase(fi.path).startswith(
            os.path.normcase(DOWNLOADS_DIR)
        )
        risk = RiskLevel.MEDIUM
        location = "下载目录" if in_downloads else "非下载目录"
        return RuleResult(
            matched=True,
            risk_level=risk,
            category=FileCategory.INSTALLER,
            reason=f"安装包文件，位于{location}，请确认程序已安装后再删除",
            priority=self.priority,
        )


class ArchiveInDownloadsRule(BaseRule):
    """下载目录中的压缩包 -> 中风险"""
    name = "ArchiveInDownloads"
    priority = 60

    def apply(self, fi: FileInfo) -> RuleResult:
        if fi.extension not in ARCHIVE_EXTENSIONS:
            return RuleResult(matched=False, risk_level=None, category=None, reason="", priority=0)
        if not os.path.normcase(fi.path).startswith(os.path.normcase(DOWNLOADS_DIR)):
            return RuleResult(matched=False, risk_level=None, category=None, reason="", priority=0)

        return RuleResult(
            matched=True,
            risk_level=RiskLevel.MEDIUM,
            category=FileCategory.ARCHIVE,
            reason="下载目录中的压缩包，请确认已解压或不再需要后删除",
            priority=self.priority,
        )


class DuplicateFileRule(BaseRule):
    """重复文件（非原始副本） -> 中风险"""
    name = "DuplicateFile"
    priority = 75

    def apply(self, fi: FileInfo) -> RuleResult:
        if fi.is_duplicate:
            orig_name = os.path.basename(fi.duplicate_of) if fi.duplicate_of else "未知"
            return RuleResult(
                matched=True,
                risk_level=RiskLevel.MEDIUM,
                category=FileCategory.DUPLICATE,
                reason=f"与文件 '{orig_name}' 哈希一致（大文件已做全量确认），为重复副本",
                priority=self.priority,
            )
        return RuleResult(matched=False, risk_level=None, category=None, reason="", priority=0)


class LargeFileRule(BaseRule):
    """超大文件 -> 中风险（需要用户确认）"""
    name = "LargeFile"
    priority = 50

    def apply(self, fi: FileInfo) -> RuleResult:
        if fi.size >= LARGE_FILE_THRESHOLD:
            return RuleResult(
                matched=True,
                risk_level=RiskLevel.MEDIUM,
                category=FileCategory.LARGE,
                reason=f"大文件 ({fi.size_str})，请确认是否仍需要",
                priority=self.priority,
            )
        return RuleResult(matched=False, risk_level=None, category=None, reason="", priority=0)


class OldFileRule(BaseRule):
    """长期未访问文件 -> 中风险"""
    name = "OldFile"
    priority = 40

    def apply(self, fi: FileInfo) -> RuleResult:
        days = fi.atime_days_ago
        if days >= VERY_OLD_FILE_DAYS:
            return RuleResult(
                matched=True,
                risk_level=RiskLevel.MEDIUM,
                category=FileCategory.OLD_FILE,
                reason=f"超过 {days} 天未被访问，可能不再需要",
                priority=self.priority,
            )
        elif days >= OLD_FILE_DAYS:
            return RuleResult(
                matched=True,
                risk_level=RiskLevel.MEDIUM,
                category=FileCategory.OLD_FILE,
                reason=f"超过 {days} 天未被访问，建议确认",
                priority=self.priority,
            )
        return RuleResult(matched=False, risk_level=None, category=None, reason="", priority=0)


class HighRiskExtensionRule(BaseRule):
    """高风险扩展名（.dll/.sys/.reg 等） -> 高风险"""
    name = "HighRiskExtension"
    priority = 80

    def apply(self, fi: FileInfo) -> RuleResult:
        if fi.extension in HIGH_RISK_EXTENSIONS:
            return RuleResult(
                matched=True,
                risk_level=RiskLevel.HIGH,
                category=FileCategory.CONFIG,
                reason=f"扩展名 {fi.extension!r} 为系统/配置关键文件类型，禁止自动删除",
                priority=self.priority,
            )
        return RuleResult(matched=False, risk_level=None, category=None, reason="", priority=0)


class MediaFileRule(BaseRule):
    """媒体文件 -> 高风险（防止误删珍贵照片/视频）"""
    name = "MediaFile"
    priority = 35

    def apply(self, fi: FileInfo) -> RuleResult:
        if fi.extension in MEDIA_EXTENSIONS:
            return RuleResult(
                matched=True,
                risk_level=RiskLevel.HIGH,
                category=FileCategory.MEDIA,
                reason=f"媒体文件（{fi.extension}），可能包含重要照片或视频，默认不建议删除",
                priority=self.priority,
            )
        return RuleResult(matched=False, risk_level=None, category=None, reason="", priority=0)


class DocumentFileRule(BaseRule):
    """文档文件 -> 高风险"""
    name = "DocumentFile"
    priority = 35

    def apply(self, fi: FileInfo) -> RuleResult:
        if fi.extension in DOCUMENT_EXTENSIONS:
            return RuleResult(
                matched=True,
                risk_level=RiskLevel.HIGH,
                category=FileCategory.DOCUMENT,
                reason=f"文档文件（{fi.extension}），可能包含重要数据，默认不建议删除",
                priority=self.priority,
            )
        return RuleResult(matched=False, risk_level=None, category=None, reason="", priority=0)


# ──────────────────────────────────────────────────────────────────────────────
# 规则引擎
# ──────────────────────────────────────────────────────────────────────────────

class RuleEngine:
    """
    将所有规则按优先级排序后依次应用。
    取优先级最高的匹配结果作为最终分类。
    若无任何规则匹配，归类为"未知文件 / 高风险"（保守策略）。
    """

    DEFAULT_RULES: List[BaseRule] = [
        SystemDirectoryRule(),
        HighRiskExtensionRule(),
        KnownTempDirRule(),
        MediumRiskCacheRule(),
        KnownCacheDirRule(),
        DuplicateFileRule(),
        LowRiskExtensionRule(),
        LogFileRule(),
        LogDirHeuristicRule(),
        InstallerRule(),
        ArchiveInDownloadsRule(),
        MediumRiskExtensionRule(),
        BuildArtifactRule(),
        AppResidualRule(),
        LargeFileRule(),
        OldFileRule(),
        MediaFileRule(),
        DocumentFileRule(),
    ]

    def __init__(self, rules: Optional[List[BaseRule]] = None):
        self.rules = sorted(
            rules if rules is not None else self.DEFAULT_RULES,
            key=lambda r: r.priority,
            reverse=True,  # 高优先级先匹配
        )

    def apply(self, fi: FileInfo) -> Tuple[RiskLevel, FileCategory, str]:
        """
        对单个文件应用所有规则。

        返回: (risk_level, category, reason)
        """
        best: Optional[RuleResult] = None

        for rule in self.rules:
            try:
                result = rule.apply(fi)
                if result.matched:
                    if best is None or result.priority > best.priority:
                        best = result
                    # 高优先级规则直接采用（SystemDirectory/HighRiskExtension）
                    if result.priority >= 80:
                        break
            except Exception as e:
                self._log_rule_error(rule, fi, e)

        if best is None:
            # 无规则匹配 -> 未知，保守标记为高风险
            return (
                RiskLevel.HIGH,
                FileCategory.UNKNOWN,
                "未能识别文件用途，保守标记为高风险，建议使用 AI 分析后再决定",
            )

        return best.risk_level, best.category, best.reason

    @staticmethod
    def _log_rule_error(rule: BaseRule, fi: FileInfo, err: Exception) -> None:
        """规则异常日志（避免规则静默失效导致分类质量不可观测）"""
        try:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            p = LOG_DIR / "rule_engine_errors.log"
            msg = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] rule={getattr(rule, 'name', type(rule).__name__)} path={fi.path} err={type(err).__name__}: {err}\n"
            with open(p, "a", encoding="utf-8") as f:
                f.write(msg)
        except Exception:
            # 任何日志失败都不应影响主流程
            return

    def apply_all(self, files: List[FileInfo]) -> None:
        """批量应用规则，直接修改 FileInfo 对象"""
        for fi in files:
            risk, cat, reason = self.apply(fi)
            fi.risk_level  = risk.value
            fi.category    = cat.value
            fi.risk_reason = reason
            # 高风险文件默认不选中
            if risk == RiskLevel.HIGH:
                fi.selected = False
