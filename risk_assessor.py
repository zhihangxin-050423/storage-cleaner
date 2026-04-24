# risk_assessor.py - 风险评估模块
"""
在规则引擎分类基础上，结合文件大小、位置、访问时间等上下文，
对风险等级做最终裁决，并生成结构化的评估报告。
"""
from dataclasses import dataclass, field
from typing import List, Dict
from collections import defaultdict

from config import RiskLevel, FileCategory
from scanner import FileInfo, _fmt_size


@dataclass
class AssessmentSummary:
    """扫描结果的汇总统计，用于 UI 概览页"""
    total_files:       int   = 0
    total_size:        int   = 0

    low_count:         int   = 0
    low_size:          int   = 0
    medium_count:      int   = 0
    medium_size:       int   = 0
    high_count:        int   = 0
    high_size:         int   = 0

    # 按类别统计
    category_counts:   Dict[str, int] = field(default_factory=dict)
    category_sizes:    Dict[str, int] = field(default_factory=dict)

    duplicate_groups:  int   = 0
    duplicate_waste:   int   = 0   # 可节省空间（重复文件总大小 - 一份）

    @property
    def cleanable_low(self) -> int:
        return self.low_size

    @property
    def cleanable_medium(self) -> int:
        return self.medium_size

    @property
    def total_cleanable(self) -> int:
        return self.low_size + self.medium_size

    def total_size_str(self)     -> str: return _fmt_size(self.total_size)
    def low_size_str(self)       -> str: return _fmt_size(self.low_size)
    def medium_size_str(self)    -> str: return _fmt_size(self.medium_size)
    def high_size_str(self)      -> str: return _fmt_size(self.high_size)
    def total_cleanable_str(self)-> str: return _fmt_size(self.total_cleanable)
    def dup_waste_str(self)      -> str: return _fmt_size(self.duplicate_waste)


class RiskAssessor:
    """
    接收已经由 RuleEngine 标注的 FileInfo 列表，
    生成 AssessmentSummary 统计报告。
    """

    def summarize(self, files: List[FileInfo],
                  duplicate_groups: Dict[str, List[FileInfo]]) -> AssessmentSummary:
        summary = AssessmentSummary()
        summary.total_files = len(files)

        cat_counts: Dict[str, int] = defaultdict(int)
        cat_sizes:  Dict[str, int] = defaultdict(int)

        for fi in files:
            summary.total_size += fi.size
            cat_counts[fi.category] += 1
            cat_sizes[fi.category]  += fi.size

            if fi.risk_level == RiskLevel.LOW.value:
                summary.low_count += 1
                summary.low_size  += fi.size
            elif fi.risk_level == RiskLevel.MEDIUM.value:
                summary.medium_count += 1
                summary.medium_size  += fi.size
            else:
                summary.high_count += 1
                summary.high_size  += fi.size

        summary.category_counts = dict(cat_counts)
        summary.category_sizes  = dict(cat_sizes)

        # 重复文件浪费空间 = sum(size) - 最大size（保留一份）
        for h, dups in duplicate_groups.items():
            if len(dups) > 1:
                summary.duplicate_groups += 1
                sizes = sorted(d.size for d in dups)
                summary.duplicate_waste += sum(sizes[1:])  # 超出一份的大小

        return summary
