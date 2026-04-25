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
    SYNC_DRIVE_DIR_NAMES,
)
from scanner import FileInfo
from path_matcher import (
    has_any_segment,
    contains_sequence,
    is_chromium_profile_cache,
    is_firefox_profile_cache,
    has_segment,
    contains_all_segments,
    any_segment_startswith,
)


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
        # 结构化匹配：优先识别常见“目录段序列”，减少 frag in path 误判
        if contains_sequence(nc, ("node_modules", ".cache")) or contains_sequence(nc, ("__pycache__",)):
            return RuleResult(
                matched=True,
                risk_level=RiskLevel.LOW,
                category=FileCategory.CACHE,
                reason="位于常见开发缓存目录，可安全清理",
                priority=self.priority,
            )
        # 浏览器缓存：支持多 Profile
        if is_chromium_profile_cache(nc):
            return RuleResult(
                matched=True,
                risk_level=RiskLevel.LOW,
                category=FileCategory.CACHE,
                reason="位于 Chromium 浏览器 Profile 缓存目录，可安全清理",
                priority=self.priority,
            )
        if is_firefox_profile_cache(nc):
            return RuleResult(
                matched=True,
                risk_level=RiskLevel.LOW,
                category=FileCategory.CACHE,
                reason="位于 Firefox Profiles 缓存目录（cache2），可安全清理",
                priority=self.priority,
            )
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

class DevToolCacheRule(BaseRule):
    """
    开发工具缓存/构建加速缓存（建议默认中风险）：
    这些目录经常位于项目目录，删除可能导致下次构建/检查变慢或丢失本地索引。
    """
    name = "DevToolCache"
    priority = 88

    def apply(self, fi: FileInfo) -> RuleResult:
        nc = os.path.normcase(fi.path)
        # cmake-build-*（常见 IDE 生成目录）
        if any_segment_startswith(nc, "cmake-build-"):
            return RuleResult(
                matched=True,
                risk_level=RiskLevel.MEDIUM,
                category=FileCategory.CACHE,
                reason="位于 CMake 构建目录（cmake-build-*），通常可重建但建议确认后清理",
                priority=self.priority,
            )
        # 目录段匹配（Path.parts 级别）
        segments = {
            ".parcel-cache", ".turbo", ".vite", ".eslintcache", ".ruff_cache",
            ".pytest_cache", ".mypy_cache", ".tox",
            "htmlcov", "coverage",
            "cmakefiles",
            # Rust/Go/Python 工具链常见缓存/产物
            "target", "go-build",
            "uv", "pypoetry",
        }
        if has_any_segment(nc, segments):
            return RuleResult(
                matched=True,
                risk_level=RiskLevel.MEDIUM,
                category=FileCategory.CACHE,
                reason="位于开发工具缓存目录（加速构建/检查），通常可重建但建议确认后清理",
                priority=self.priority,
            )
        # 更精确：.cache\uv 或 .cache\pypoetry
        if contains_sequence(nc, (".cache", "uv")) or contains_sequence(nc, (".cache", "pypoetry")):
            return RuleResult(
                matched=True,
                risk_level=RiskLevel.MEDIUM,
                category=FileCategory.CACHE,
                reason="位于 Python 工具缓存（uv/poetry），通常可重建但建议确认后清理",
                priority=self.priority,
            )
        # pipenv / pip-tools 缓存：.cache\pipenv
        if contains_sequence(nc, (".cache", "pipenv")):
            return RuleResult(
                matched=True,
                risk_level=RiskLevel.MEDIUM,
                category=FileCategory.CACHE,
                reason="位于 pipenv 缓存（.cache\\pipenv），通常可重建但建议确认后清理",
                priority=self.priority,
            )
        # poetry 更完整：AppData\Local\pypoetry\cache
        if contains_sequence(nc, ("appdata", "local", "pypoetry", "cache")):
            return RuleResult(
                matched=True,
                risk_level=RiskLevel.MEDIUM,
                category=FileCategory.CACHE,
                reason="位于 Poetry 缓存（AppData\\Local\\pypoetry\\cache），通常可重建但建议确认后清理",
                priority=self.priority,
            )
        # uv 更完整：AppData\Local\uv\cache
        if contains_sequence(nc, ("appdata", "local", "uv", "cache")):
            return RuleResult(
                matched=True,
                risk_level=RiskLevel.MEDIUM,
                category=FileCategory.CACHE,
                reason="位于 uv 缓存（AppData\\Local\\uv\\cache），通常可重建但建议确认后清理",
                priority=self.priority,
            )
        # Go module cache: ...\go\pkg\mod
        if contains_sequence(nc, ("go", "pkg", "mod")):
            return RuleResult(
                matched=True,
                risk_level=RiskLevel.MEDIUM,
                category=FileCategory.CACHE,
                reason="位于 Go module 缓存（pkg\\mod），通常可重建但建议确认后清理",
                priority=self.priority,
            )
        # 覆盖“文件级缓存”特征（即使不在目录段中）
        name_l = (fi.name or "").lower()
        if name_l in (".coverage",) or name_l.endswith(".eslintcache"):
            return RuleResult(
                matched=True,
                risk_level=RiskLevel.MEDIUM,
                category=FileCategory.CACHE,
                reason="开发工具缓存文件（coverage/eslintcache），通常可重建但建议确认后清理",
                priority=self.priority,
            )
        return RuleResult(matched=False, risk_level=None, category=None, reason="", priority=0)


class SyncDriveRule(BaseRule):
    """同步盘目录中的文件 -> 高风险（更保守）"""
    name = "SyncDrive"
    priority = 95

    def apply(self, fi: FileInfo) -> RuleResult:
        nc = os.path.normcase(fi.path)
        if has_any_segment(nc, SYNC_DRIVE_DIR_NAMES):
            return RuleResult(
                matched=True,
                risk_level=RiskLevel.HIGH,
                category=FileCategory.CONFIG,
                reason="位于同步盘目录（删除可能同步到云端），默认不建议删除",
                priority=self.priority,
            )
        return RuleResult(matched=False, risk_level=None, category=None, reason="", priority=0)

class WindowsUserDataProtectionRule(BaseRule):
    """用户 AppData 下的 Windows 核心子目录：更保守（避免误删系统/索引/体验数据）。"""
    name = "WindowsUserDataProtection"
    priority = 94

    def apply(self, fi: FileInfo) -> RuleResult:
        nc = os.path.normcase(fi.path)
        if contains_all_segments(nc, ("appdata", "local", "microsoft", "windows")):
            return RuleResult(
                matched=True,
                risk_level=RiskLevel.HIGH,
                category=FileCategory.SYSTEM,
                reason="位于 AppData\\Local\\Microsoft\\Windows（系统/索引/体验数据），默认不建议删除",
                priority=self.priority,
            )
        if contains_all_segments(nc, ("appdata", "roaming", "microsoft", "windows")):
            return RuleResult(
                matched=True,
                risk_level=RiskLevel.HIGH,
                category=FileCategory.SYSTEM,
                reason="位于 AppData\\Roaming\\Microsoft\\Windows（系统配置/外壳数据），默认不建议删除",
                priority=self.priority,
            )
        return RuleResult(matched=False, risk_level=None, category=None, reason="", priority=0)


class SensitiveConfigRule(BaseRule):
    """敏感配置/密钥路径启发式（如 .ssh/config） -> 高风险"""
    name = "SensitiveConfig"
    priority = 92

    def apply(self, fi: FileInfo) -> RuleResult:
        name_l = (fi.name or "").lower()
        nc = os.path.normcase(fi.path).lower()
        if contains_sequence(nc, (".ssh",)) and name_l in ("config", "known_hosts", "authorized_keys", "id_rsa", "id_ed25519"):
            return RuleResult(
                matched=True,
                risk_level=RiskLevel.HIGH,
                category=FileCategory.CONFIG,
                reason="位于 .ssh 目录的敏感配置/密钥文件，禁止自动删除",
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
        # 结构化匹配：目录段命中（避免 "\dist\\" 这种字符串脆弱写法）
        build_dirs = {
            "dist", "build", "out", "target", "coverage", "obj", "bin",
            ".next", ".nuxt", ".angular", ".svelte-kit", ".terraform",
            "cmake-build-debug", "cmake-build-release", "cmakefiles",
        }
        if has_any_segment(nc, build_dirs):
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
            # 安装/系统语义目录下的日志更保守（即便较旧，也不直接给“低风险”）
            nc = os.path.normcase(fi.path)
            installish = has_any_segment(nc, {"program files", "program files (x86)", "windows", "programdata"})
            if installish:
                risk = RiskLevel.MEDIUM
            else:
                # 近 24 小时仍在写入：更保守
                if days <= 1:
                    risk = RiskLevel.MEDIUM
                else:
                    risk = RiskLevel.LOW if days > 30 else RiskLevel.MEDIUM
            big_hint = ""
            try:
                if fi.size >= 200 * 1024 * 1024 and days > 30 and not installish:
                    big_hint = "；体积很大且长期未修改，清理收益高"
            except Exception:
                pass
            return RuleResult(
                matched=True,
                risk_level=risk,
                category=FileCategory.LOG,
                reason=(f"日志文件，最后修改 {days} 天前，"
                        + ("可清理" if risk == RiskLevel.LOW else "可能仍在使用，建议确认") + big_hint),
                priority=self.priority,
            )
        return RuleResult(matched=False, risk_level=None, category=None, reason="", priority=0)

class UnfinishedDownloadRule(BaseRule):
    """未完成下载（.crdownload/.part 等） -> 低风险（但仅对较旧者）"""
    name = "UnfinishedDownload"
    priority = 72

    def apply(self, fi: FileInfo) -> RuleResult:
        if fi.extension not in (".crdownload", ".part", ".partial", ".download"):
            return RuleResult(matched=False, risk_level=None, category=None, reason="", priority=0)
        days = fi.mtime_days_ago
        # 太新的可能是正在下载，不建议清理
        if days <= 7:
            return RuleResult(
                matched=True,
                risk_level=RiskLevel.MEDIUM,
                category=FileCategory.DOWNLOAD,
                reason=f"未完成下载文件（{fi.extension}），最近 {days} 天内仍修改，可能仍在下载，建议确认",
                priority=self.priority,
            )
        return RuleResult(
            matched=True,
            risk_level=RiskLevel.LOW,
            category=FileCategory.TEMP,
            reason=f"未完成下载文件（{fi.extension}），超过 {days} 天未修改，通常可清理",
            priority=self.priority,
        )


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
        location = "下载目录" if in_downloads else "非下载目录"
        # 下载目录的时间维度：越新越需要确认，越旧越“更接近可清理”
        days = fi.mtime_days_ago
        if in_downloads and days <= 7:
            hint = "近期下载，建议确认安装完成后再删除"
        elif in_downloads and days >= 90:
            hint = "下载目录中已放置较久（>90天），更可能可清理，但仍建议确认"
        else:
            hint = "较早下载，建议确认后清理"
        return RuleResult(
            matched=True,
            risk_level=RiskLevel.MEDIUM,
            category=FileCategory.INSTALLER,
            reason=f"安装包文件，位于{location}，{hint}",
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

        days = fi.mtime_days_ago
        # 旁边存在“同名解压目录”时给出提示（仍中风险，避免误删）
        try:
            base = os.path.splitext(fi.name)[0]
            parent = os.path.dirname(fi.path)
            extracted_dir = os.path.join(parent, base)
            extracted_hint = "；旁边存在同名目录，可能已解压" if os.path.isdir(extracted_dir) else ""
        except Exception:
            extracted_hint = ""
        hint = "近期下载，建议确认已解压/使用后再删除" if days <= 7 else "较早下载，建议确认已解压或不再需要后删除"
        return RuleResult(
            matched=True,
            risk_level=RiskLevel.MEDIUM,
            category=FileCategory.ARCHIVE,
            reason=f"下载目录中的压缩包，{hint}{extracted_hint}",
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
        # Windows 上 atime 可能不可靠：改为 mtime 为主、atime 为辅，并结合文件类型
        m_days = getattr(fi, "mtime_days_ago", 0)
        a_days = getattr(fi, "atime_days_ago", 0)

        if fi.extension in LOG_EXTENSIONS and m_days >= 30:
            return RuleResult(
                matched=True,
                risk_level=RiskLevel.LOW,
                category=FileCategory.LOG,
                reason=f"日志文件超过 {m_days} 天未修改，通常可清理（近期仍在写入则不建议）",
                priority=self.priority,
            )

        days = max(m_days, a_days)
        if days >= VERY_OLD_FILE_DAYS:
            return RuleResult(
                matched=True,
                risk_level=RiskLevel.MEDIUM,
                category=FileCategory.OLD_FILE,
                reason=f"超过 {days} 天未修改/访问，可能不再需要",
                priority=self.priority,
            )
        elif days >= OLD_FILE_DAYS:
            return RuleResult(
                matched=True,
                risk_level=RiskLevel.MEDIUM,
                category=FileCategory.OLD_FILE,
                reason=f"超过 {days} 天未修改/访问，建议确认",
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
    priority = 55

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
    priority = 55

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
        SyncDriveRule(),
        WindowsUserDataProtectionRule(),
        SensitiveConfigRule(),
        HighRiskExtensionRule(),
        KnownTempDirRule(),
        DevToolCacheRule(),
        MediumRiskCacheRule(),
        KnownCacheDirRule(),
        DuplicateFileRule(),
        LowRiskExtensionRule(),
        LogFileRule(),
        LogDirHeuristicRule(),
        UnfinishedDownloadRule(),
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

    def apply(self, fi: FileInfo) -> Tuple[RiskLevel, FileCategory, str, List[str]]:
        """
        对单个文件应用所有规则。

        返回: (risk_level, category, reason)
        """
        # 策略明确化：
        # - “系统关键目录 / 高风险扩展名”属于绝对高风险保护，必须优先生效且不可被覆盖
        # - 其他规则在此保护之外按优先级选取最优匹配（不再用 priority>=80 这种隐式短路）
        hits: List[str] = []

        try:
            sys_rule = SystemDirectoryRule()
            r0 = sys_rule.apply(fi)
            if r0.matched:
                hits.append(r0.reason)
                return r0.risk_level, r0.category, r0.reason, hits
        except Exception as e:
            self._log_rule_error(SystemDirectoryRule(), fi, e)

        # 同步盘/敏感配置：高风险优先且不可被覆盖
        for abs_rule in (SyncDriveRule(), WindowsUserDataProtectionRule(), SensitiveConfigRule()):
            try:
                rr = abs_rule.apply(fi)
                if rr.matched:
                    hits.append(rr.reason)
                    return rr.risk_level, rr.category, rr.reason, hits
            except Exception as e:
                self._log_rule_error(abs_rule, fi, e)

        try:
            hr_rule = HighRiskExtensionRule()
            r1 = hr_rule.apply(fi)
            if r1.matched:
                hits.append(r1.reason)
                return r1.risk_level, r1.category, r1.reason, hits
        except Exception as e:
            self._log_rule_error(HighRiskExtensionRule(), fi, e)

        best: Optional[RuleResult] = None
        for rule in self.rules:
            # 跳过已显式处理的绝对规则
            if isinstance(rule, (SystemDirectoryRule, HighRiskExtensionRule)):
                continue
            try:
                result = rule.apply(fi)
                if result.matched:
                    if result.reason:
                        hits.append(result.reason)
                    if best is None or result.priority > best.priority:
                        best = result
            except Exception as e:
                self._log_rule_error(rule, fi, e)

        if best is None:
            # 无规则匹配 -> 未知，保守标记为高风险
            return (
                RiskLevel.HIGH,
                FileCategory.UNKNOWN,
                "未能识别文件用途，保守标记为高风险，建议使用智能分析后再决定",
                hits,
            )

        return best.risk_level, best.category, best.reason, hits

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
            risk, cat, reason, hits = self.apply(fi)
            fi.risk_level  = risk.value
            fi.category    = cat.value
            fi.risk_reason = reason
            fi.rule_hits   = hits
            # 高风险文件默认不选中
            if risk == RiskLevel.HIGH:
                fi.selected = False
