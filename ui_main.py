# ui_main.py - 主界面模块
"""
基于 tkinter + ttk 构建的存储清理工具界面。
包含：
  - 扫描控制栏
  - 概览 / 文件列表 / 重复文件 / 目录分析 / 操作日志 五个标签页
  - 文件详情 + AI 解释面板
  - 安全删除控制栏
  - 状态栏
"""
import os
import sys
import json
import time
import queue
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from typing import List, Dict, Optional
from pathlib import Path
from datetime import datetime

from config import (
    RiskLevel, RISK_BG, RISK_FG, RISK_TAG,
    DOWNLOADS_DIR, LOG_DIR, OPERATION_LOG_PATH,
)
from scanner import Scanner, FileInfo, ScanResult, _fmt_size
from rule_engine import RuleEngine
from risk_assessor import RiskAssessor, AssessmentSummary
from explainer import Explainer
from executor import Executor, ExecutionResult


# ──────────────────────────────────────────────────────────────────────────────
# 常量
# ──────────────────────────────────────────────────────────────────────────────

TITLE   = "StorageCleaner  —  智能存储分析与安全清理工具"
VERSION = "v1.0"

# 颜色方案
C_BG        = "#1E1E2E"   # 深色背景
C_PANEL     = "#2A2A3E"   # 面板背景
C_ACCENT    = "#7C5CBF"   # 主色调（紫色）
C_ACCENT2   = "#5B8BF5"   # 次色调（蓝色）
C_TEXT      = "#CDD6F4"   # 主文字
C_SUBTEXT   = "#7F849C"   # 次要文字
C_BORDER    = "#45475A"   # 边框
C_LOW       = "#A6E3A1"   # 低风险绿
C_MEDIUM    = "#FAB387"   # 中风险橙
C_HIGH      = "#F38BA8"   # 高风险红
C_LOW_BG    = "#1E3A2B"
C_MEDIUM_BG = "#3A2600"
C_HIGH_BG   = "#3A1020"
C_BTN       = "#313244"
C_BTN_HOV   = "#45475A"

FONT_H1    = ("Segoe UI", 14, "bold")
FONT_H2    = ("Segoe UI", 11, "bold")
FONT_BODY  = ("Segoe UI", 10)
FONT_SMALL = ("Segoe UI", 9)
FONT_MONO  = ("Consolas", 9)

# 设置窗口字体（更大一些，避免在高 DPI 下过小）
FONT_SETTINGS_LABEL = ("Segoe UI", 12)
FONT_SETTINGS_ENTRY = ("Segoe UI", 12)
FONT_SETTINGS_HINT  = ("Segoe UI", 10)

# DeepSeek 模型固定选项（按需求：提供下拉选择）
DEEPSEEK_MODELS = ["deepseek-v4-flash", "deepseek-v4-pro", "deepseek-chat", "deepseek-reasoner"]

# AI 建议标签颜色
AI_SUGGESTION_STYLE = {
    "safe_to_delete": {"fg": "#A6E3A1", "bg": "#1E3A2B", "text": "✅ 可以删除"},
    "keep": {"fg": "#F38BA8", "bg": "#3A1020", "text": "🔒 建议保留"},
    "caution": {"fg": "#FAB387", "bg": "#3A2600", "text": "⚠️ 谨慎确认"},
}


# ──────────────────────────────────────────────────────────────────────────────
# 帮助函数
# ──────────────────────────────────────────────────────────────────────────────

def _risk_color(risk_value: str):
    if risk_value == RiskLevel.LOW.value:    return C_LOW,    C_LOW_BG
    if risk_value == RiskLevel.MEDIUM.value: return C_MEDIUM, C_MEDIUM_BG
    if risk_value == RiskLevel.HIGH.value:   return C_HIGH,   C_HIGH_BG
    return C_TEXT, C_PANEL


def _risk_tag(risk_value: str) -> str:
    if risk_value == RiskLevel.LOW.value:    return "low"
    if risk_value == RiskLevel.MEDIUM.value: return "medium"
    if risk_value == RiskLevel.HIGH.value:   return "high"
    return "unknown"


def _days_str(days: int) -> str:
    if days < 1:    return "今天"
    if days < 7:    return f"{days} 天前"
    if days < 30:   return f"{days//7} 周前"
    if days < 365:  return f"{days//30} 个月前"
    return f"{days//365} 年前"


def _make_btn(parent, text, command, **kw):
    fg   = kw.pop("fg", C_TEXT)
    bg   = kw.pop("bg", C_BTN)
    font = kw.pop("font", FONT_BODY)
    btn = tk.Button(parent, text=text, command=command,
                    fg=fg, bg=bg, font=font,
                    relief="flat", bd=0, padx=12, pady=6,
                    activebackground=C_BTN_HOV, activeforeground=C_TEXT,
                    cursor="hand2", **kw)
    btn.bind("<Enter>", lambda e: btn.configure(bg=C_BTN_HOV))
    btn.bind("<Leave>", lambda e: btn.configure(bg=bg))
    return btn


# ──────────────────────────────────────────────────────────────────────────────
# 主应用
# ──────────────────────────────────────────────────────────────────────────────

class StorageCleanerApp:

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(TITLE)
        self.root.geometry("1280x820")
        self.root.minsize(960, 640)
        self.root.configure(bg=C_BG)

        # 图标（忽略错误）
        try:
            self.root.iconbitmap(default="")
        except Exception:
            pass

        # 核心组件
        self.scanner     = Scanner(progress_callback=self._on_scan_progress)
        self.rule_engine = RuleEngine()
        self.risk_assessor = RiskAssessor()
        self.explainer   = Explainer()
        self.executor    = Executor(use_trash=True)

        # 状态变量
        self.scan_result:  Optional[ScanResult]       = None
        self.summary:      Optional[AssessmentSummary] = None
        self.all_files:    List[FileInfo]              = []
        self._q:           queue.Queue                 = queue.Queue()
        self._scan_thread: Optional[threading.Thread]  = None
        self._scanning     = False
        self._selected_file: Optional[FileInfo]        = None
        self._scan_total_est: int = 0
        self._scan_phase: str = ""  # "counting" | "scanning" | "hashing"

        # 筛选状态
        self._filter_risk    = tk.StringVar(value="全部")
        self._filter_cat     = tk.StringVar(value="全部")
        self._filter_min_mb  = tk.StringVar(value="0")
        self._sort_col       = "size"
        self._sort_asc       = False

        self._build_ui()
        self._apply_style()
        self._poll_queue()

    # ──────────────────────────────────────────────────────────────────────────
    # UI 构建
    # ──────────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        # ── 顶部控制栏
        self._build_topbar()
        # ── 主体区域（左侧过滤 + 右侧内容）
        body = tk.Frame(self.root, bg=C_BG)
        body.pack(fill="both", expand=True, padx=8, pady=(0, 4))
        # ── Notebook 标签页
        self._build_notebook(body)
        # ── 底部详情 + 操作区
        self._build_bottom()
        # ── 状态栏
        self._build_statusbar()

    def _build_topbar(self):
        bar = tk.Frame(self.root, bg=C_PANEL, height=56)
        bar.pack(fill="x", padx=0, pady=0)
        bar.pack_propagate(False)

        # Logo / 标题
        tk.Label(bar, text="💾 StorageCleaner", font=("Segoe UI", 13, "bold"),
                 bg=C_PANEL, fg=C_ACCENT).pack(side="left", padx=16)

        # 扫描路径
        tk.Label(bar, text="扫描路径:", font=FONT_BODY,
                 bg=C_PANEL, fg=C_SUBTEXT).pack(side="left", padx=(8, 4))
        self._path_var = tk.StringVar(value=str(Path.home()))
        path_entry = tk.Entry(bar, textvariable=self._path_var,
                              bg=C_BTN, fg=C_TEXT, font=FONT_BODY,
                              insertbackground=C_TEXT, relief="flat",
                              width=42, bd=4)
        path_entry.pack(side="left", ipady=4)

        _make_btn(bar, "📂 浏览", self._browse_path,
                  bg=C_BTN).pack(side="left", padx=6)

        self._scan_btn = _make_btn(bar, "▶ 开始扫描", self._start_scan,
                                   bg=C_ACCENT, fg="white", font=FONT_H2)
        self._scan_btn.pack(side="left", padx=6)

        self._cancel_btn = _make_btn(bar, "⏹ 取消", self._cancel_scan,
                                     bg="#555", fg=C_SUBTEXT)
        self._cancel_btn.pack(side="left", padx=2)
        self._cancel_btn.configure(state="disabled")

        # 设置按钮
        _make_btn(bar, "⚙ 设置", self._open_settings,
                  bg=C_BTN).pack(side="right", padx=12)

        # 进度条（默认隐藏）
        self._progress = ttk.Progressbar(bar, mode="indeterminate", length=220)
        self._progress.pack(side="right", padx=8)
        self._progress.pack_forget()

    def _build_notebook(self, parent):
        style = ttk.Style()
        style.configure("Custom.TNotebook", background=C_BG, borderwidth=0)
        style.configure("Custom.TNotebook.Tab",
                        background=C_PANEL, foreground=C_SUBTEXT,
                        padding=[14, 6], font=FONT_BODY)
        style.map("Custom.TNotebook.Tab",
                  background=[("selected", C_BG)],
                  foreground=[("selected", C_ACCENT)])

        self._nb = ttk.Notebook(parent, style="Custom.TNotebook")
        self._nb.pack(fill="both", expand=True, pady=(6, 0))

        # 标签页
        self._tab_overview  = tk.Frame(self._nb, bg=C_BG)
        self._tab_files     = tk.Frame(self._nb, bg=C_BG)
        self._tab_dupes     = tk.Frame(self._nb, bg=C_BG)
        self._tab_dirs      = tk.Frame(self._nb, bg=C_BG)
        self._tab_log       = tk.Frame(self._nb, bg=C_BG)

        self._nb.add(self._tab_overview, text="📊 概览")
        self._nb.add(self._tab_files,    text="📄 文件列表")
        self._nb.add(self._tab_dupes,    text="🔗 重复文件")
        self._nb.add(self._tab_dirs,     text="📁 目录分析")
        self._nb.add(self._tab_log,      text="📋 操作日志")

        self._build_tab_overview()
        self._build_tab_files()
        self._build_tab_dupes()
        self._build_tab_dirs()
        self._build_tab_log()

    # ── 概览标签页
    def _build_tab_overview(self):
        p = self._tab_overview
        tk.Label(p, text="请选择目录后点击「开始扫描」",
                 font=FONT_H1, bg=C_BG, fg=C_SUBTEXT).pack(expand=True)
        self._overview_placeholder = p.winfo_children()[-1]

        # 概览内容（扫描后显示）
        self._overview_content = tk.Frame(p, bg=C_BG)
        self._overview_content.pack_forget()
        self._build_overview_content()

    def _build_overview_content(self):
        f = self._overview_content

        # 顶部大数字
        top = tk.Frame(f, bg=C_BG)
        top.pack(fill="x", padx=16, pady=12)

        def _stat_card(parent, label, value_var, color, width=200):
            card = tk.Frame(parent, bg=C_PANEL, bd=0, relief="flat",
                            width=width, height=100)
            card.pack(side="left", padx=6, pady=4, fill="y")
            card.pack_propagate(False)
            tk.Label(card, textvariable=value_var, font=("Segoe UI", 22, "bold"),
                     bg=C_PANEL, fg=color).pack(pady=(12, 0))
            tk.Label(card, text=label, font=FONT_SMALL,
                     bg=C_PANEL, fg=C_SUBTEXT).pack()
            return card

        self._ov_total    = tk.StringVar(value="—")
        self._ov_low      = tk.StringVar(value="—")
        self._ov_medium   = tk.StringVar(value="—")
        self._ov_high     = tk.StringVar(value="—")
        self._ov_clean    = tk.StringVar(value="—")
        self._ov_files    = tk.StringVar(value="—")

        _stat_card(top, "总占用空间", self._ov_total,  C_ACCENT2)
        _stat_card(top, "可清理（低风险）", self._ov_low, C_LOW)
        _stat_card(top, "建议确认（中风险）", self._ov_medium, C_MEDIUM)
        _stat_card(top, "不建议删除（高风险）", self._ov_high, C_HIGH)
        _stat_card(top, "合计可清理", self._ov_clean, C_ACCENT2)
        _stat_card(top, "文件总数", self._ov_files, C_TEXT)

        # 分类统计
        mid = tk.Frame(f, bg=C_BG)
        mid.pack(fill="both", expand=True, padx=16, pady=4)

        tk.Label(mid, text="分类统计", font=FONT_H2,
                 bg=C_BG, fg=C_TEXT).pack(anchor="w", pady=(4, 6))

        self._cat_tree = ttk.Treeview(
            mid,
            columns=("category", "count", "size", "risk"),
            show="headings", height=12,
        )
        self._cat_tree.heading("category", text="类别")
        self._cat_tree.heading("count",    text="文件数")
        self._cat_tree.heading("size",     text="占用空间")
        self._cat_tree.heading("risk",     text="典型风险")
        self._cat_tree.column("category", width=200)
        self._cat_tree.column("count",    width=80,  anchor="center")
        self._cat_tree.column("size",     width=120, anchor="center")
        self._cat_tree.column("risk",     width=100, anchor="center")
        self._cat_tree.pack(fill="both", expand=True)

    # ── 文件列表标签页
    def _build_tab_files(self):
        p = self._tab_files

        # 使用 grid 统一布局，避免 pack/grid 混用
        p.grid_rowconfigure(1, weight=1)
        p.grid_columnconfigure(0, weight=1)

        # 筛选栏
        filter_bar = tk.Frame(p, bg=C_PANEL, height=38)
        filter_bar.grid(row=0, column=0, columnspan=2, sticky="ew")
        filter_bar.grid_propagate(False)

        tk.Label(filter_bar, text="风险筛选:", font=FONT_SMALL,
                 bg=C_PANEL, fg=C_SUBTEXT).pack(side="left", padx=8)
        for opt in ["全部", "低风险", "中风险", "高风险"]:
            rb = tk.Radiobutton(filter_bar, text=opt,
                                variable=self._filter_risk, value=opt,
                                command=self._refresh_file_list,
                                bg=C_PANEL, fg=C_TEXT, font=FONT_SMALL,
                                selectcolor=C_ACCENT, activebackground=C_PANEL,
                                relief="flat", bd=0)
            rb.pack(side="left", padx=4)

        tk.Label(filter_bar, text="  最小大小(MB):", font=FONT_SMALL,
                 bg=C_PANEL, fg=C_SUBTEXT).pack(side="left", padx=(12, 2))
        min_mb_entry = tk.Entry(filter_bar, textvariable=self._filter_min_mb,
                                bg=C_BTN, fg=C_TEXT, font=FONT_SMALL,
                                width=6, relief="flat", bd=3)
        min_mb_entry.pack(side="left")
        min_mb_entry.bind("<Return>", lambda e: self._refresh_file_list())

        _make_btn(filter_bar, "筛选", self._refresh_file_list,
                  bg=C_BTN, font=FONT_SMALL).pack(side="left", padx=6)

        # 批量操作
        _make_btn(filter_bar, "✅ 全选低风险", self._select_all_low,
                  bg=C_BTN, font=FONT_SMALL).pack(side="right", padx=4)
        _make_btn(filter_bar, "☑ 全选", lambda: self._toggle_all(True),
                  bg=C_BTN, font=FONT_SMALL).pack(side="right", padx=4)
        _make_btn(filter_bar, "☐ 全不选", lambda: self._toggle_all(False),
                  bg=C_BTN, font=FONT_SMALL).pack(side="right", padx=4)

        # 文件列表 Treeview
        cols = ("sel", "name", "size", "risk", "category", "atime", "path")
        self._file_tree = ttk.Treeview(p, columns=cols, show="headings",
                                        selectmode="browse")
        hdrs = [("sel", "☑", 32), ("name", "文件名", 220),
                ("size", "大小", 90), ("risk", "风险", 80),
                ("category", "类别", 110), ("atime", "最后访问", 110),
                ("path", "路径", 400)]
        for col, hdr, w in hdrs:
            self._file_tree.heading(col, text=hdr,
                                    command=lambda c=col: self._sort_file_list(c))
            self._file_tree.column(col, width=w, minwidth=30,
                                   anchor="center" if col in ("sel","size","risk","atime") else "w")

        vsb = ttk.Scrollbar(p, orient="vertical",   command=self._file_tree.yview)
        hsb = ttk.Scrollbar(p, orient="horizontal",  command=self._file_tree.xview)
        self._file_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self._file_tree.grid(row=1, column=0, sticky="nsew")
        vsb.grid(row=1, column=1, sticky="ns")
        hsb.grid(row=2, column=0, sticky="ew")

        # 事件
        self._file_tree.bind("<<TreeviewSelect>>", self._on_file_select)
        self._file_tree.bind("<Button-1>",          self._on_file_click)

        # 行颜色标签
        self._file_tree.tag_configure("low",    background=C_LOW_BG,    foreground=C_LOW)
        self._file_tree.tag_configure("medium", background=C_MEDIUM_BG, foreground=C_MEDIUM)
        self._file_tree.tag_configure("high",   background=C_HIGH_BG,   foreground=C_HIGH)
        self._file_tree.tag_configure("unknown",background=C_PANEL,     foreground=C_SUBTEXT)

    # ── 重复文件标签页
    def _build_tab_dupes(self):
        p = self._tab_dupes
        tk.Label(p, text="重复文件检测结果", font=FONT_H2,
                 bg=C_BG, fg=C_TEXT).pack(anchor="w", padx=12, pady=6)

        cols = ("group", "name", "size", "path", "atime")
        self._dupe_tree = ttk.Treeview(p, columns=cols, show="headings")
        self._dupe_tree.heading("group", text="重复组")
        self._dupe_tree.heading("name",  text="文件名")
        self._dupe_tree.heading("size",  text="大小")
        self._dupe_tree.heading("path",  text="路径")
        self._dupe_tree.heading("atime", text="最后访问")
        self._dupe_tree.column("group", width=60,  anchor="center")
        self._dupe_tree.column("name",  width=200)
        self._dupe_tree.column("size",  width=90,  anchor="center")
        self._dupe_tree.column("path",  width=500)
        self._dupe_tree.column("atime", width=110, anchor="center")

        vsb2 = ttk.Scrollbar(p, orient="vertical", command=self._dupe_tree.yview)
        self._dupe_tree.configure(yscrollcommand=vsb2.set)
        self._dupe_tree.pack(side="left", fill="both", expand=True, padx=(12, 0), pady=4)
        vsb2.pack(side="right", fill="y", pady=4, padx=(0, 4))

        self._dupe_tree.tag_configure("original", foreground=C_LOW)
        self._dupe_tree.tag_configure("dupe",     foreground=C_MEDIUM)

    # ── 目录分析标签页
    def _build_tab_dirs(self):
        p = self._tab_dirs
        tk.Label(p, text="目录空间占用 TOP 50", font=FONT_H2,
                 bg=C_BG, fg=C_TEXT).pack(anchor="w", padx=12, pady=6)

        cols = ("dir", "size", "files", "pct")
        self._dir_tree = ttk.Treeview(p, columns=cols, show="headings")
        self._dir_tree.heading("dir",   text="目录路径")
        self._dir_tree.heading("size",  text="占用大小")
        self._dir_tree.heading("files", text="文件数")
        self._dir_tree.heading("pct",   text="占总扫描%")
        self._dir_tree.column("dir",   width=600)
        self._dir_tree.column("size",  width=120, anchor="center")
        self._dir_tree.column("files", width=80,  anchor="center")
        self._dir_tree.column("pct",   width=100, anchor="center")

        vsb3 = ttk.Scrollbar(p, orient="vertical", command=self._dir_tree.yview)
        self._dir_tree.configure(yscrollcommand=vsb3.set)
        self._dir_tree.pack(side="left", fill="both", expand=True, padx=(12, 0), pady=4)
        vsb3.pack(side="right", fill="y", pady=4, padx=(0, 4))

    # ── 操作日志标签页
    def _build_tab_log(self):
        p = self._tab_log
        hdr = tk.Frame(p, bg=C_BG)
        hdr.pack(fill="x", padx=12, pady=4)
        tk.Label(hdr, text="操作日志（最近 200 条）", font=FONT_H2,
                 bg=C_BG, fg=C_TEXT).pack(side="left")
        _make_btn(hdr, "🔄 刷新", self._refresh_log, bg=C_BTN,
                  font=FONT_SMALL).pack(side="right")
        _make_btn(hdr, "🗑 清除日志", self._clear_log, bg=C_BTN,
                  font=FONT_SMALL).pack(side="right", padx=4)

        cols = ("time", "action", "name", "size", "risk", "result", "path")
        self._log_tree = ttk.Treeview(p, columns=cols, show="headings", height=20)
        heads = [("time","时间",130), ("action","操作",70), ("name","文件名",180),
                 ("size","大小",80), ("risk","风险",70), ("result","结果",60),
                 ("path","路径",450)]
        for col, hdr_txt, w in heads:
            self._log_tree.heading(col, text=hdr_txt)
            self._log_tree.column(col, width=w, anchor="center" if col in ("action","size","risk","result") else "w")

        vsb4 = ttk.Scrollbar(p, orient="vertical", command=self._log_tree.yview)
        self._log_tree.configure(yscrollcommand=vsb4.set)
        self._log_tree.pack(side="left", fill="both", expand=True, padx=(12, 0), pady=4)
        vsb4.pack(side="right", fill="y", pady=4, padx=(0, 4))

        self._log_tree.tag_configure("success", foreground=C_LOW)
        self._log_tree.tag_configure("error",   foreground=C_HIGH)
        self._log_tree.tag_configure("skip",    foreground=C_SUBTEXT)

    # ── 底部详情 + 操作区
    def _build_bottom(self):
        bottom = tk.Frame(self.root, bg=C_PANEL, height=220)
        bottom.pack(fill="x", padx=8, pady=(0, 4))
        bottom.pack_propagate(False)

        # 左：文件详情
        detail_frame = tk.Frame(bottom, bg=C_PANEL, width=560)
        detail_frame.pack(side="left", fill="y", padx=10, pady=8)
        detail_frame.pack_propagate(False)

        tk.Label(detail_frame, text="文件详情", font=FONT_H2,
                 bg=C_PANEL, fg=C_TEXT).pack(anchor="w")

        # AI 建议标签（独立展示，不混在详情文本里）
        self._ai_tag = tk.Label(
            detail_frame,
            text="AI 建议：—",
            font=FONT_SMALL,
            bg=C_BG,
            fg=C_SUBTEXT,
            padx=10,
            pady=6,
            anchor="w",
        )
        self._ai_tag.pack(fill="x", pady=(6, 4))

        self._detail_text = tk.Text(detail_frame, bg=C_BG, fg=C_TEXT,
                                     font=FONT_SMALL, relief="flat",
                                     height=9, width=62, state="disabled",
                                     wrap="word", bd=4)
        self._detail_text.pack(fill="both", expand=True, pady=4)

        # 中：AI 解释区
        ai_frame = tk.Frame(bottom, bg=C_PANEL)
        ai_frame.pack(side="left", fill="both", expand=True, padx=4, pady=8)

        ai_hdr = tk.Frame(ai_frame, bg=C_PANEL)
        ai_hdr.pack(fill="x")
        tk.Label(ai_hdr, text="🤖 智能分析", font=FONT_H2,
                 bg=C_PANEL, fg=C_ACCENT).pack(side="left")
        self._ai_btn = _make_btn(ai_hdr, "获取智能分析报告", self._get_ai_explanation,
                                  bg=C_ACCENT, fg="white", font=FONT_SMALL)
        self._ai_btn.pack(side="right")
        _make_btn(ai_hdr, "批量分析未知文件", self._batch_ai_unknown,
                  bg=C_BTN, font=FONT_SMALL).pack(side="right", padx=6)

        self._ai_text = tk.Text(ai_frame, bg=C_BG, fg=C_TEXT,
                                 font=FONT_SMALL, relief="flat",
                                 height=9, state="disabled",
                                 wrap="word", bd=4)
        self._ai_text.pack(fill="both", expand=True, pady=4)

        # 右：操作按钮
        action_frame = tk.Frame(bottom, bg=C_PANEL, width=200)
        action_frame.pack(side="right", fill="y", padx=10, pady=8)
        action_frame.pack_propagate(False)

        tk.Label(action_frame, text="执行操作", font=FONT_H2,
                 bg=C_PANEL, fg=C_TEXT).pack(anchor="w")

        self._trash_btn = _make_btn(action_frame, "♻ 移至回收站（推荐）",
                                     self._do_trash,
                                     bg=C_ACCENT, fg="white",
                                     font=FONT_SMALL)
        self._trash_btn.pack(fill="x", pady=3)

        self._delete_btn = _make_btn(action_frame, "⚠ 永久删除（不可恢复）",
                                      self._do_permanent_delete,
                                      bg="#8B1A1A", fg="white",
                                      font=FONT_SMALL)
        self._delete_btn.pack(fill="x", pady=3)

        self._symlink_btn = _make_btn(action_frame, "🔗 创建软链接",
                                      self._create_symlink,
                                      bg=C_BTN, font=FONT_SMALL)
        self._symlink_btn.pack(fill="x", pady=3)

        _make_btn(action_frame, "📤 导出报告 (JSON)",
                  self._export_report, bg=C_BTN, font=FONT_SMALL).pack(fill="x", pady=3)

        _make_btn(action_frame, "📋 复制选中路径",
                  self._copy_paths, bg=C_BTN, font=FONT_SMALL).pack(fill="x", pady=3)

        # 选中统计标签
        self._sel_label = tk.Label(action_frame, text="已选: 0 个文件",
                                    font=FONT_SMALL, bg=C_PANEL, fg=C_SUBTEXT)
        self._sel_label.pack(anchor="w", pady=(8, 0))
        self._sel_size_label = tk.Label(action_frame, text="选中大小: —",
                                         font=FONT_SMALL, bg=C_PANEL, fg=C_SUBTEXT)
        self._sel_size_label.pack(anchor="w")

    def _build_statusbar(self):
        bar = tk.Frame(self.root, bg=C_PANEL, height=26)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)

        self._status_var = tk.StringVar(value="就绪 — 请选择目录后开始扫描")
        tk.Label(bar, textvariable=self._status_var, font=FONT_SMALL,
                 bg=C_PANEL, fg=C_SUBTEXT, anchor="w").pack(side="left", padx=10, fill="y")

        self._file_count_var = tk.StringVar(value="")
        tk.Label(bar, textvariable=self._file_count_var, font=FONT_SMALL,
                 bg=C_PANEL, fg=C_ACCENT, anchor="e").pack(side="right", padx=10, fill="y")

    # ──────────────────────────────────────────────────────────────────────────
    # 样式
    # ──────────────────────────────────────────────────────────────────────────

    def _apply_style(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")

        tv_cfg = dict(background=C_PANEL, foreground=C_TEXT,
                      fieldbackground=C_PANEL, rowheight=24)
        style.configure("Treeview", **tv_cfg, font=FONT_SMALL)
        style.configure("Treeview.Heading",
                        background=C_BTN, foreground=C_TEXT,
                        font=FONT_SMALL, relief="flat")
        style.map("Treeview",
                  background=[("selected", C_ACCENT)],
                  foreground=[("selected", "white")])
        style.map("Treeview.Heading",
                  background=[("active", C_BTN_HOV)])

        style.configure("TScrollbar", background=C_PANEL,
                         troughcolor=C_BG, arrowcolor=C_SUBTEXT)
        style.configure("TProgressbar", background=C_ACCENT)

    # ──────────────────────────────────────────────────────────────────────────
    # 扫描控制
    # ──────────────────────────────────────────────────────────────────────────

    def _browse_path(self):
        path = filedialog.askdirectory(title="选择要扫描的目录",
                                       initialdir=self._path_var.get())
        if path:
            self._path_var.set(path)

    def _start_scan(self):
        path = self._path_var.get().strip()
        if not os.path.isdir(path):
            messagebox.showerror("错误", f"目录不存在：{path}")
            return
        if self._scanning:
            return

        self._scanning = True
        self._scan_btn.configure(state="disabled")
        self._cancel_btn.configure(state="normal")
        self._status_var.set("正在预统计文件数量...")
        self._progress.pack(side="right", padx=8)
        self._progress.configure(mode="indeterminate", maximum=100, value=0)
        self._progress.start(10)
        self._scan_total_est = 0
        self._scan_phase = "counting"

        # 清空旧数据
        self._clear_display()

        self._scan_thread = threading.Thread(
            target=self._scan_worker, args=(path,), daemon=True
        )
        self._scan_thread.start()

    def _cancel_scan(self):
        if self._scanning:
            self.scanner.cancel()
            self._status_var.set("正在取消...")

    def _scan_worker(self, path: str):
        """后台扫描线程"""
        try:
            # 第 0 步：预统计文件数量，用于确定型进度条
            total = self.scanner.estimate_total_files(path, skip_system=True)
            self._q.put(("scan_total", total))
            if self.scanner._cancel_flag.is_set():
                self._q.put(("scan_error", "已取消"))
                return
            result = self.scanner.scan(path, skip_system=True, compute_hashes=True)
            # 应用规则引擎
            self.rule_engine.apply_all(result.files)
            # 生成摘要
            summary = self.risk_assessor.summarize(result.files, result.duplicate_groups)
            self._q.put(("scan_done", result, summary))
        except Exception as e:
            self._q.put(("scan_error", str(e)))

    def _on_scan_progress(self, count: int, total_size: int, current_path: str):
        """进度回调（后台线程调用）"""
        self._q.put(("progress", count, total_size, current_path))

    def _poll_queue(self):
        """主线程轮询队列"""
        try:
            while True:
                msg = self._q.get_nowait()
                self._handle_message(msg)
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)

    def _handle_message(self, msg):
        mtype = msg[0]
        if mtype == "progress":
            _, count, size, path = msg
            short = path[-60:] if len(path) > 60 else path
            # 扫描阶段：更新确定型进度条
            if self._scan_phase == "scanning" and self._scan_total_est > 0:
                self._progress.configure(mode="determinate", maximum=self._scan_total_est)
                self._progress.stop()
                self._progress.configure(value=min(count, self._scan_total_est))
                pct = int(min(count, self._scan_total_est) / max(self._scan_total_est, 1) * 100)
                self._status_var.set(f"扫描中: {count}/{self._scan_total_est} ({pct}%) | {_fmt_size(size)} | {short}")
            else:
                self._status_var.set(f"扫描中: {count} 个文件 | {_fmt_size(size)} | {short}")
            self._file_count_var.set(f"{count} 文件")

            # 哈希阶段提示：切回转圈（无法准确量化）
            if isinstance(path, str) and path.startswith("哈希检测中:"):
                if self._scan_phase != "hashing":
                    self._scan_phase = "hashing"
                    self._progress.configure(mode="indeterminate")
                    self._progress.start(10)
                self._status_var.set(path)

        elif mtype == "scan_total":
            _, total = msg
            self._scan_total_est = int(total or 0)
            self._scan_phase = "scanning"
            # 切换到确定型进度条
            if self._scan_total_est > 0:
                self._progress.stop()
                self._progress.configure(mode="determinate", maximum=self._scan_total_est, value=0)
                self._status_var.set(f"开始扫描（预计 {self._scan_total_est} 个文件）...")
            else:
                # 无法统计时保持转圈
                self._progress.configure(mode="indeterminate")
                self._progress.start(10)

        elif mtype == "scan_done":
            _, result, summary = msg
            self.scan_result = result
            self.summary     = summary
            self.all_files   = result.files
            self._scanning   = False
            self._scan_btn.configure(state="normal")
            self._cancel_btn.configure(state="disabled")
            self._progress.stop()
            self._progress.pack_forget()
            self._scan_phase = ""
            self._on_scan_complete(result, summary)

        elif mtype == "scan_error":
            _, err = msg
            self._scanning = False
            self._scan_btn.configure(state="normal")
            self._cancel_btn.configure(state="disabled")
            self._progress.stop()
            self._progress.pack_forget()
            self._scan_phase = ""
            self._status_var.set(f"扫描出错: {err}")
            messagebox.showerror("扫描错误", err)

    # ──────────────────────────────────────────────────────────────────────────
    # 扫描完成后更新 UI
    # ──────────────────────────────────────────────────────────────────────────

    def _on_scan_complete(self, result: ScanResult, summary: AssessmentSummary):
        t = result.scan_duration
        self._status_var.set(
            f"扫描完成 | 耗时 {t:.1f}s | {summary.total_files} 个文件 | "
            f"总大小 {summary.total_size_str()} | 错误 {len(result.error_paths)} 项"
        )
        self._file_count_var.set(
            f"低:{summary.low_count}  中:{summary.medium_count}  高:{summary.high_count}"
        )
        self._update_overview(summary)
        self._refresh_file_list()
        self._update_dupe_tab(result)
        self._update_dir_tab(result, summary)
        self._refresh_log()
        self._nb.select(0)  # 切到概览

    def _update_overview(self, s: AssessmentSummary):
        # 显示概览内容区
        self._overview_placeholder.pack_forget()
        self._overview_content.pack(fill="both", expand=True)

        self._ov_total.set(s.total_size_str())
        self._ov_low.set(s.low_size_str())
        self._ov_medium.set(s.medium_size_str())
        self._ov_high.set(s.high_size_str())
        self._ov_clean.set(s.total_cleanable_str())
        self._ov_files.set(str(s.total_files))

        # 分类表
        for row in self._cat_tree.get_children():
            self._cat_tree.delete(row)

        cat_risk_map = {
            "临时文件": "低", "缓存文件": "低", "日志文件": "低~中",
            "重复文件": "中", "大文件": "中", "长期未访问": "中",
            "安装包": "中", "应用残留": "中", "压缩包": "中",
            "系统文件": "高", "配置文件": "高", "媒体文件": "高",
            "文档文件": "高", "未知文件": "高",
        }
        rows = sorted(s.category_sizes.items(), key=lambda x: x[1], reverse=True)
        for cat, size in rows:
            count = s.category_counts.get(cat, 0)
            risk  = cat_risk_map.get(cat, "?")
            self._cat_tree.insert("", "end",
                                   values=(cat, count, _fmt_size(size), risk))

    def _refresh_file_list(self):
        """重新填充文件列表（应用筛选/排序）"""
        for row in self._file_tree.get_children():
            self._file_tree.delete(row)

        if not self.all_files:
            return

        # 筛选
        risk_filter = self._filter_risk.get()
        try:
            min_mb = float(self._filter_min_mb.get() or "0") * 1024 * 1024
        except ValueError:
            min_mb = 0

        files = [fi for fi in self.all_files
                 if (risk_filter == "全部" or fi.risk_level == risk_filter)
                 and fi.size >= min_mb]

        # 排序
        reverse = not self._sort_asc
        if self._sort_col == "size":
            files.sort(key=lambda f: f.size, reverse=reverse)
        elif self._sort_col == "atime":
            files.sort(key=lambda f: f.atime, reverse=reverse)
        elif self._sort_col == "risk":
            order = {RiskLevel.LOW.value: 0, RiskLevel.MEDIUM.value: 1, RiskLevel.HIGH.value: 2}
            files.sort(key=lambda f: order.get(f.risk_level, 3), reverse=reverse)
        elif self._sort_col == "name":
            files.sort(key=lambda f: f.name.lower(), reverse=reverse)
        elif self._sort_col == "category":
            files.sort(key=lambda f: f.category, reverse=reverse)
        else:
            files.sort(key=lambda f: f.size, reverse=True)

        sel_count = 0
        sel_size  = 0
        for fi in files:
            ck = "☑" if fi.selected else "☐"
            tag = _risk_tag(fi.risk_level)
            self._file_tree.insert(
                "", "end", iid=fi.path, tags=(tag,),
                values=(ck, fi.name, fi.size_str, fi.risk_level,
                        fi.category, _days_str(fi.atime_days_ago), fi.path)
            )
            if fi.selected:
                sel_count += 1
                sel_size  += fi.size

        self._sel_label.configure(text=f"已选: {sel_count} 个文件")
        self._sel_size_label.configure(text=f"选中大小: {_fmt_size(sel_size)}")

    def _update_dupe_tab(self, result: ScanResult):
        for row in self._dupe_tree.get_children():
            self._dupe_tree.delete(row)

        for grp_idx, (h, dups) in enumerate(result.duplicate_groups.items(), 1):
            for i, fi in enumerate(dups):
                tag   = "original" if i == 0 else "dupe"
                label = f"#{grp_idx}" + (" [原]" if i == 0 else f" [副{i}]")
                self._dupe_tree.insert("", "end", tags=(tag,),
                    values=(label, fi.name, fi.size_str,
                            fi.path, _days_str(fi.atime_days_ago)))

    def _update_dir_tab(self, result: ScanResult, summary: AssessmentSummary):
        for row in self._dir_tree.get_children():
            self._dir_tree.delete(row)

        # 目录大小 -> 文件数
        dir_file_counts: Dict[str, int] = {}
        for fi in result.files:
            d = os.path.dirname(fi.path)
            dir_file_counts[d] = dir_file_counts.get(d, 0) + 1

        sorted_dirs = sorted(result.dir_sizes.items(),
                              key=lambda x: x[1], reverse=True)[:50]
        total = summary.total_size or 1
        for dirpath, size in sorted_dirs:
            pct = f"{size/total*100:.1f}%"
            cnt = dir_file_counts.get(dirpath, 0)
            self._dir_tree.insert("", "end",
                                   values=(dirpath, _fmt_size(size), cnt, pct))

    def _refresh_log(self):
        for row in self._log_tree.get_children():
            self._log_tree.delete(row)

        records = self.executor.get_operation_log()[-200:]
        records.reverse()
        for rec in records:
            tag = "success" if rec.get("success") else (
                  "skip" if rec.get("action") == "skip" else "error")
            action_cn = {"trash": "回收站", "delete": "永久删除", "symlink": "软链接",
                         "skip": "跳过", "error": "失败"}.get(rec.get("action",""), "?")
            result_str = "✓" if rec.get("success") else "✗"
            self._log_tree.insert("", "end", tags=(tag,),
                values=(rec.get("timestamp", ""),
                        action_cn,
                        rec.get("file_name", ""),
                        _fmt_size(rec.get("file_size", 0)),
                        rec.get("risk_level", ""),
                        result_str,
                        rec.get("file_path", "")))

    # ──────────────────────────────────────────────────────────────────────────
    # 文件列表交互
    # ──────────────────────────────────────────────────────────────────────────

    def _on_file_click(self, event):
        """点击第一列（☑/☐）切换选中状态"""
        region = self._file_tree.identify_region(event.x, event.y)
        col    = self._file_tree.identify_column(event.x)
        iid    = self._file_tree.identify_row(event.y)
        if region == "cell" and col == "#1" and iid:
            self._toggle_file(iid)

    def _toggle_file(self, path: str):
        fi = self._get_fi_by_path(path)
        if fi is None:
            return
        if fi.risk_level == RiskLevel.HIGH.value:
            if not messagebox.askyesno("高风险确认",
                    f"文件 '{fi.name}' 被标记为高风险，确定要选中并删除吗？\n"
                    f"风险原因：{fi.risk_reason}\n\n此操作不建议执行！"):
                return
        fi.selected = not fi.selected
        # 更新显示
        ck = "☑" if fi.selected else "☐"
        vals = list(self._file_tree.item(path, "values"))
        vals[0] = ck
        self._file_tree.item(path, values=vals)
        self._update_sel_stats()

    def _on_file_select(self, event):
        sel = self._file_tree.selection()
        if sel:
            fi = self._get_fi_by_path(sel[0])
            if fi:
                self._selected_file = fi
                self._show_file_detail(fi)

    def _show_file_detail(self, fi: FileInfo):
        text = (
            f"文件名：{fi.name}\n"
            f"完整路径：{fi.path}\n"
            f"大小：{fi.size_str}  ({fi.size:,} 字节)\n"
            f"扩展名：{fi.extension or '(无)'}\n"
            f"风险等级：{fi.risk_level}\n"
            f"文件类别：{fi.category}\n"
            f"规则判断：{fi.risk_reason}\n"
            f"创建时间：{datetime.fromtimestamp(fi.ctime).strftime('%Y-%m-%d %H:%M')}\n"
            f"修改时间：{datetime.fromtimestamp(fi.mtime).strftime('%Y-%m-%d %H:%M')}\n"
            f"访问时间：{datetime.fromtimestamp(fi.atime).strftime('%Y-%m-%d %H:%M')} "
            f"({_days_str(fi.atime_days_ago)})\n"
        )
        # 更新 AI 标签
        sug = (getattr(fi, "ai_suggestion", "") or "").strip()
        conf = float(getattr(fi, "ai_confidence", 0.0) or 0.0)
        if sug in AI_SUGGESTION_STYLE:
            st = AI_SUGGESTION_STYLE[sug]
            self._ai_tag.configure(
                text=f"AI 建议：{st['text']}  置信度：{int(conf*100)}%",
                fg=st["fg"],
                bg=st["bg"],
            )
        else:
            self._ai_tag.configure(text="AI 建议：—", fg=C_SUBTEXT, bg=C_BG)
        if fi.is_duplicate and fi.duplicate_of:
            text += f"重复源文件：{fi.duplicate_of}\n"
        if fi.hash_md5:
            text += f"MD5：{fi.hash_md5}\n"

        self._detail_text.configure(state="normal")
        self._detail_text.delete("1.0", "end")
        self._detail_text.insert("1.0", text)
        self._detail_text.configure(state="disabled")

        # 如已有 AI 解释，直接显示
        if fi.ai_explanation:
            self._set_ai_text(fi.ai_explanation)
        else:
            self._set_ai_text("（点击「获取 AI 分析」按钮以生成解释）")

    def _get_fi_by_path(self, path: str) -> Optional[FileInfo]:
        for fi in self.all_files:
            if fi.path == path:
                return fi
        return None

    def _update_sel_stats(self):
        sel_count = sum(1 for fi in self.all_files if fi.selected)
        sel_size  = sum(fi.size for fi in self.all_files if fi.selected)
        self._sel_label.configure(text=f"已选: {sel_count} 个文件")
        self._sel_size_label.configure(text=f"选中大小: {_fmt_size(sel_size)}")

    def _toggle_all(self, state: bool):
        for fi in self.all_files:
            if fi.risk_level != RiskLevel.HIGH.value:
                fi.selected = state
            elif state is False:
                fi.selected = False
        self._refresh_file_list()

    def _select_all_low(self):
        for fi in self.all_files:
            fi.selected = (fi.risk_level == RiskLevel.LOW.value)
        self._refresh_file_list()

    def _sort_file_list(self, col: str):
        if self._sort_col == col:
            self._sort_asc = not self._sort_asc
        else:
            self._sort_col = col
            self._sort_asc = False
        self._refresh_file_list()

    # ──────────────────────────────────────────────────────────────────────────
    # AI 解释
    # ──────────────────────────────────────────────────────────────────────────

    def _get_ai_explanation(self):
        if not self._selected_file:
            messagebox.showinfo("提示", "请先在文件列表中选择一个文件")
            return
        fi = self._selected_file
        if not self.explainer.api_key:
            if not self._prompt_api_key():
                return
        self._set_ai_text("正在调用 AI 分析中，请稍候...")
        self._ai_btn.configure(state="disabled")

        def worker():
            result = self.explainer.explain_file(fi)
            self._q.put(("ai_done", fi, result))

        threading.Thread(target=worker, daemon=True).start()

    def _batch_ai_unknown(self):
        unknown = [fi for fi in self.all_files
                   if fi.category in ("未知文件",) and not fi.ai_explanation]
        if not unknown:
            messagebox.showinfo("提示", "没有需要 AI 分析的未知文件")
            return
        if not self.explainer.api_key:
            if not self._prompt_api_key():
                return

        n = len(unknown)
        if not messagebox.askyesno("确认", f"将对 {n} 个未知文件进行 AI 分析，是否继续？"):
            return

        self._set_ai_text(f"正在分析 {n} 个未知文件，请稍候...")

        def worker():
            def progress(done, total):
                self._q.put(("batch_ai_progress", done, total))

            results = self.explainer.explain_batch(unknown, progress_callback=progress)
            for fi in unknown:
                if fi.path in results:
                    fi.ai_explanation = results[fi.path]
            self._q.put(("batch_ai_done", len(results)))

        threading.Thread(target=worker, daemon=True).start()

    def _set_ai_text(self, text: str):
        self._ai_text.configure(state="normal")
        self._ai_text.delete("1.0", "end")
        self._ai_text.insert("1.0", text)
        self._ai_text.configure(state="disabled")

    # ──────────────────────────────────────────────────────────────────────────
    # 删除操作
    # ──────────────────────────────────────────────────────────────────────────

    def _get_selected_files(self) -> List[FileInfo]:
        return [fi for fi in self.all_files if fi.selected]

    def _do_trash(self):
        files = self._get_selected_files()
        if not files:
            messagebox.showinfo("提示", "没有选中任何文件")
            return

        # 检查高风险文件
        high_risk = [fi for fi in files if fi.risk_level == RiskLevel.HIGH.value]
        if high_risk:
            if not messagebox.askyesno("高风险警告",
                    f"选中文件中包含 {len(high_risk)} 个高风险文件！\n"
                    f"高风险文件将被跳过，仅处理低/中风险文件。\n\n确认继续？"):
                return

        n = len(files)
        total_size = sum(fi.size for fi in files)
        if not messagebox.askyesno("确认",
                f"即将将 {n} 个文件（{_fmt_size(total_size)}）移至回收站\n"
                f"（高风险文件将自动跳过；回收站失败将不会执行永久删除）\n\n确认执行？"):
            return

        self.executor.use_trash = True
        self.executor.allow_high_risk = False
        self._run_executor(files)

    def _do_permanent_delete(self):
        files = self._get_selected_files()
        if not files:
            messagebox.showinfo("提示", "没有选中任何文件")
            return

        high_count = sum(1 for fi in files if fi.risk_level == RiskLevel.HIGH.value)
        warning = f"⚠ 永久删除操作不可恢复！\n\n"
        warning += f"将删除 {len(files)} 个文件，共 {_fmt_size(sum(fi.size for fi in files))}\n"
        if high_count > 0:
            warning += f"\n包含 {high_count} 个高风险文件（将自动跳过）\n"
        warning += "\n请再次确认：确定要永久删除这些文件吗？"

        if not messagebox.askyesno("⚠ 永久删除确认", warning, icon="warning"):
            return
        # 二次确认
        confirm_text = simpledialog.askstring("二次确认",
            "请输入 DELETE 以确认永久删除（此操作不可恢复）:")
        if confirm_text != "DELETE":
            messagebox.showinfo("取消", "输入不匹配，操作已取消")
            return

        self.executor.use_trash = False
        self.executor.allow_high_risk = False
        self._run_executor(files)

    def _create_symlink(self):
        """为当前选中的单个文件创建软链接（不会删除源文件）"""
        fi = self._selected_file
        if not fi:
            messagebox.showinfo("提示", "请先在文件列表中选择一个文件")
            return

        ok, reason = self.executor.is_symlink_candidate(fi)
        if not ok:
            messagebox.showwarning("不可创建软链接", reason)
            return

        # 让用户选择软链接保存路径（默认同目录、同名 .lnk? 这里是符号链接，不是快捷方式）
        default_name = fi.name
        initial_dir = os.path.dirname(fi.path)
        link_path = filedialog.asksaveasfilename(
            title="选择软链接保存路径（将创建符号链接）",
            initialdir=initial_dir,
            initialfile=default_name,
            defaultextension="",
            filetypes=[("All", "*.*")],
        )
        if not link_path:
            return

        if os.path.abspath(link_path) == os.path.abspath(fi.path):
            messagebox.showerror("错误", "链接路径不能与源文件相同")
            return

        rec = self.executor.create_symlink(fi, link_path)
        self._refresh_log()
        if rec.success:
            messagebox.showinfo("成功", rec.error_msg or "软链接创建成功")
        else:
            messagebox.showerror("失败", rec.error_msg or "软链接创建失败")

    def _run_executor(self, files: List[FileInfo]):
        self._trash_btn.configure(state="disabled")
        self._delete_btn.configure(state="disabled")
        self._status_var.set("正在执行删除操作...")

        def worker():
            result = self.executor.execute(files)
            self._q.put(("exec_done", result, files))

        threading.Thread(target=worker, daemon=True).start()

    # ──────────────────────────────────────────────────────────────────────────
    # 消息处理（补充）
    # ──────────────────────────────────────────────────────────────────────────

    def _handle_message(self, msg):
        mtype = msg[0]
        if mtype == "progress":
            _, count, size, path = msg
            short = path[-60:] if len(path) > 60 else path
            self._status_var.set(f"扫描中: {count} 个文件 | {_fmt_size(size)} | {short}")
            self._file_count_var.set(f"{count} 文件")

        elif mtype == "scan_done":
            _, result, summary = msg
            self.scan_result = result
            self.summary     = summary
            self.all_files   = result.files
            self._scanning   = False
            self._scan_btn.configure(state="normal")
            self._cancel_btn.configure(state="disabled")
            self._progress.stop()
            self._progress.pack_forget()
            self._on_scan_complete(result, summary)

        elif mtype == "scan_error":
            _, err = msg
            self._scanning = False
            self._scan_btn.configure(state="normal")
            self._cancel_btn.configure(state="disabled")
            self._progress.stop()
            self._progress.pack_forget()
            self._status_var.set(f"扫描出错: {err}")
            messagebox.showerror("扫描错误", err)

        elif mtype == "ai_done":
            _, fi, explanation = msg
            fi.ai_explanation = explanation
            self._set_ai_text(explanation)
            # 同步刷新详情区 AI 标签
            if self._selected_file and self._selected_file.path == fi.path:
                self._show_file_detail(fi)
            self._ai_btn.configure(state="normal")

        elif mtype == "batch_ai_done":
            _, count = msg
            self._set_ai_text(f"AI 分析完成，共分析 {count} 个文件。\n请选中文件查看各自解释。")

        elif mtype == "batch_ai_progress":
            _, done, total = msg
            self._set_ai_text(f"批量 AI 分析中：{done}/{total} ...")

        elif mtype == "exec_done":
            _, result, processed_files = msg
            self._trash_btn.configure(state="normal")
            self._delete_btn.configure(state="normal")
            self._status_var.set(f"执行完成 | {result.summary}")

            # 从列表中移除成功处理的文件
            success_set = set(result.success_paths)
            self.all_files = [fi for fi in self.all_files
                              if fi.path not in success_set]
            self._refresh_file_list()
            self._refresh_log()

            msg_text = (f"操作完成！\n\n"
                        f"成功: {len(result.success_paths)} 个\n"
                        f"跳过: {len(result.skipped_paths)} 个\n"
                        f"失败: {len(result.failed_paths)} 个\n"
                        f"释放空间: {result.freed_str}")
            if result.failed_paths:
                msg_text += f"\n\n失败文件:\n" + "\n".join(result.failed_paths[:5])
            messagebox.showinfo("执行结果", msg_text)

    # ──────────────────────────────────────────────────────────────────────────
    # 其他功能
    # ──────────────────────────────────────────────────────────────────────────

    def _export_report(self):
        if not self.all_files:
            messagebox.showinfo("提示", "没有扫描数据可导出")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("All", "*.*")],
            initialfile="storage_report.json",
        )
        if not path:
            return
        try:
            data = {
                "scan_time": datetime.now().isoformat(),
                "scan_path": self._path_var.get(),
                "total_files": len(self.all_files),
                "total_size": self.summary.total_size if self.summary else 0,
                "files": [
                    {
                        "path": fi.path, "name": fi.name,
                        "size": fi.size, "size_str": fi.size_str,
                        "risk_level": fi.risk_level,
                        "category": fi.category,
                        "risk_reason": fi.risk_reason,
                        "ai_explanation": fi.ai_explanation,
                        "atime_days_ago": fi.atime_days_ago,
                        "is_duplicate": fi.is_duplicate,
                        "duplicate_of": fi.duplicate_of,
                    }
                    for fi in self.all_files
                ]
            }
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            messagebox.showinfo("导出成功", f"报告已保存至：{path}")
        except Exception as e:
            messagebox.showerror("导出失败", str(e))

    def _copy_paths(self):
        files = self._get_selected_files()
        if not files:
            messagebox.showinfo("提示", "没有选中任何文件")
            return
        paths = "\n".join(fi.path for fi in files)
        self.root.clipboard_clear()
        self.root.clipboard_append(paths)
        messagebox.showinfo("已复制", f"已复制 {len(files)} 个文件路径到剪贴板")

    def _prompt_api_key(self) -> bool:
        key = simpledialog.askstring(
            "API Key 设置",
            "请输入当前模型服务商的 API Key：\n"
            "（也可在 设置 中配置，或设置对应环境变量，例如 OPENAI_API_KEY / DEEPSEEK_API_KEY / GEMINI_API_KEY / ANTHROPIC_API_KEY）",
            show="*"
        )
        if key and key.strip():
            self.explainer.configure(api_key=key.strip())
            return True
        return False

    def _open_settings(self):
        SettingsDialog(self.root, self.explainer, self.executor)

    def _clear_display(self):
        for row in self._file_tree.get_children():
            self._file_tree.delete(row)
        for row in self._dupe_tree.get_children():
            self._dupe_tree.delete(row)
        for row in self._dir_tree.get_children():
            self._dir_tree.delete(row)
        self._detail_text.configure(state="normal")
        self._detail_text.delete("1.0", "end")
        self._detail_text.configure(state="disabled")
        self._set_ai_text("")

    def _refresh_log(self):
        for row in self._log_tree.get_children():
            self._log_tree.delete(row)
        records = self.executor.get_operation_log()[-200:]
        records.reverse()
        for rec in records:
            tag = "success" if rec.get("success") else (
                  "skip" if rec.get("action") == "skip" else "error")
            action_cn = {"trash": "回收站", "delete": "永久删除", "symlink": "软链接",
                         "skip": "跳过", "error": "失败"}.get(rec.get("action",""), "?")
            result_str = "✓" if rec.get("success") else "✗"
            self._log_tree.insert("", "end", tags=(tag,),
                values=(rec.get("timestamp", ""), action_cn,
                        rec.get("file_name", ""),
                        _fmt_size(rec.get("file_size", 0)),
                        rec.get("risk_level", ""),
                        result_str,
                        rec.get("file_path", "")))

    def _clear_log(self):
        if messagebox.askyesno("确认", "确定要清除所有操作日志吗？"):
            self.executor.clear_log()
            self._refresh_log()


# ──────────────────────────────────────────────────────────────────────────────
# 设置对话框
# ──────────────────────────────────────────────────────────────────────────────

class SettingsDialog(tk.Toplevel):

    def __init__(self, parent, explainer: Explainer, executor: Executor):
        super().__init__(parent)
        self.explainer = explainer
        self.executor  = executor
        self.title("设置")
        # 默认尺寸；允许用户最大化/拉伸，内容区支持滚动避免遮挡
        self.geometry("720x760")
        self.configure(bg=C_BG)
        self.resizable(True, True)
        self.grab_set()

        # Windows：允许最大化（可选）
        try:
            self.state("normal")
        except Exception:
            pass

        self._build()

    def _build(self):
        p = self

        # 顶部标题
        tk.Label(p, text="⚙ 设置", font=FONT_H1, bg=C_BG, fg=C_TEXT).pack(pady=(12, 8))

        # 可滚动内容区（避免小屏/高 DPI 遮挡）
        outer = tk.Frame(p, bg=C_BG)
        outer.pack(fill="both", expand=True, padx=12, pady=(0, 10))

        canvas = tk.Canvas(outer, bg=C_BG, highlightthickness=0)
        vsb = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        content = tk.Frame(canvas, bg=C_BG)
        content_id = canvas.create_window((0, 0), window=content, anchor="nw")

        def _on_configure(_evt=None):
            canvas.configure(scrollregion=canvas.bbox("all"))
            # 让内部 frame 宽度跟随 canvas
            try:
                canvas.itemconfigure(content_id, width=canvas.winfo_width())
            except Exception:
                pass

        content.bind("<Configure>", _on_configure)
        canvas.bind("<Configure>", _on_configure)

        # 鼠标滚轮滚动
        def _on_mousewheel(evt):
            try:
                # Windows: delta 是 120 的倍数
                canvas.yview_scroll(int(-1 * (evt.delta / 120)), "units")
            except Exception:
                pass
        canvas.bind_all("<MouseWheel>", _on_mousewheel)

        # LLM 配置
        frame1 = tk.LabelFrame(content, text="大模型（LLM）配置", bg=C_BG,
                                fg=C_TEXT, font=FONT_BODY)
        frame1.pack(fill="x", padx=8, pady=8)

        # Provider
        from config import LLMProvider, DEFAULT_LLM_MODELS, DEFAULT_OPENAI_BASE_URL, DEFAULT_DEEPSEEK_BASE_URL
        self._provider_var = tk.StringVar(value=self.explainer.provider.value)
        tk.Label(frame1, text="服务商:", bg=C_BG, fg=C_SUBTEXT, font=FONT_SETTINGS_LABEL).pack(anchor="w", padx=8, pady=(6, 0))
        provider_opts = [p.value for p in LLMProvider]
        provider_box = ttk.Combobox(frame1, values=provider_opts, textvariable=self._provider_var,
                                    state="readonly", height=5)
        provider_box.pack(padx=8, pady=(2, 6), fill="x")

        # Model
        self._model_var = tk.StringVar(value=self.explainer.model)
        tk.Label(frame1, text="模型名:", bg=C_BG, fg=C_SUBTEXT, font=FONT_SETTINGS_LABEL).pack(anchor="w", padx=8)
        self._model_box = ttk.Combobox(frame1, textvariable=self._model_var, state="normal", height=6)
        self._model_box.pack(padx=8, pady=(2, 6), fill="x")

        # Base URL（仅 OpenAI/DeepSeek 有意义，Claude/Gemini 可留空）
        self._base_url_var = tk.StringVar(value=getattr(self.explainer, "base_url", "") or "")
        tk.Label(frame1, text="Base URL（可选）:", bg=C_BG, fg=C_SUBTEXT, font=FONT_SETTINGS_LABEL).pack(anchor="w", padx=8)
        base_entry = tk.Entry(frame1, textvariable=self._base_url_var,
                              bg=C_BTN, fg=C_TEXT, font=FONT_SETTINGS_ENTRY, relief="flat",
                              width=50, bd=4)
        base_entry.pack(padx=8, pady=(2, 6), fill="x")
        tk.Label(
            frame1,
            text="提示：ChatGPT 默认 https://api.openai.com；DeepSeek(OpenAI兼容) 默认 https://api.deepseek.com；DeepSeek(Anthropic兼容) 可填 https://api.deepseek.com/anthropic。",
            bg=C_BG, fg=C_SUBTEXT, font=FONT_SETTINGS_HINT, wraplength=660, justify="left"
        ).pack(anchor="w", padx=8, pady=(0, 8))

        # Extra params（JSON，可选，用于 OpenAI/DeepSeek 扩展字段透传）
        self._extra_var = tk.StringVar(value=json.dumps(getattr(self.explainer, "extra_params", {}) or {}, ensure_ascii=False))
        tk.Label(frame1, text="额外参数（JSON，可选）:", bg=C_BG, fg=C_SUBTEXT, font=FONT_SETTINGS_LABEL).pack(anchor="w", padx=8)
        extra_entry = tk.Entry(frame1, textvariable=self._extra_var,
                               bg=C_BTN, fg=C_TEXT, font=FONT_SETTINGS_ENTRY, relief="flat",
                               width=50, bd=4)
        extra_entry.pack(padx=8, pady=(2, 6), fill="x")
        tk.Label(
            frame1,
            text="示例：{\"reasoning_effort\":\"high\",\"extra_body\":{\"thinking\":{\"type\":\"enabled\"}}}",
            bg=C_BG, fg=C_SUBTEXT, font=FONT_SETTINGS_HINT, wraplength=660, justify="left"
        ).pack(anchor="w", padx=8, pady=(0, 8))

        # API Key
        self._api_var = tk.StringVar(value=self.explainer.api_key)
        tk.Label(frame1, text="API Key:", bg=C_BG, fg=C_SUBTEXT, font=FONT_SETTINGS_LABEL).pack(anchor="w", padx=8)
        entry = tk.Entry(frame1, textvariable=self._api_var, show="*",
                         bg=C_BTN, fg=C_TEXT, font=FONT_SETTINGS_ENTRY, relief="flat",
                         width=50, bd=4)
        entry.pack(padx=8, pady=(2, 6), fill="x")
        tk.Label(
            frame1,
            text="（也可设置环境变量：OPENAI_API_KEY / DEEPSEEK_API_KEY / GEMINI_API_KEY / ANTHROPIC_API_KEY）",
            bg=C_BG, fg=C_SUBTEXT, font=FONT_SETTINGS_HINT, wraplength=660, justify="left"
        ).pack(anchor="w", padx=8, pady=(0, 8))

        def _sync_defaults(*_):
            # 切换 provider 时自动填充常用默认值（不覆盖用户手动输入过的非空值）
            try:
                selected = self._provider_var.get()
                prov = next(p for p in LLMProvider if p.value == selected)
            except Exception:
                return
            if not self._model_var.get().strip():
                self._model_var.set(DEFAULT_LLM_MODELS.get(prov, ""))
            if not self._base_url_var.get().strip():
                if prov == LLMProvider.OPENAI:
                    self._base_url_var.set(DEFAULT_OPENAI_BASE_URL)
                elif prov == LLMProvider.DEEPSEEK:
                    self._base_url_var.set(DEFAULT_DEEPSEEK_BASE_URL)

            # DeepSeek：模型名限定为 4 个固定选项，提供下拉选择
            if prov == LLMProvider.DEEPSEEK:
                self._model_box.configure(values=DEEPSEEK_MODELS, state="readonly")
                if self._model_var.get().strip() not in DEEPSEEK_MODELS:
                    self._model_var.set("deepseek-v4-flash")
            else:
                self._model_box.configure(values=[], state="normal")

        provider_box.bind("<<ComboboxSelected>>", _sync_defaults)
        _sync_defaults()

        # 删除模式
        frame2 = tk.LabelFrame(content, text="删除模式", bg=C_BG,
                                fg=C_TEXT, font=FONT_BODY)
        frame2.pack(fill="x", padx=8, pady=8)

        self._trash_var = tk.BooleanVar(value=self.executor.use_trash)
        tk.Checkbutton(frame2, text="默认使用回收站（推荐，可恢复）",
                       variable=self._trash_var,
                       bg=C_BG, fg=C_TEXT, selectcolor=C_ACCENT,
                       activebackground=C_BG, font=FONT_SETTINGS_LABEL).pack(anchor="w", padx=8, pady=6)

        # 日志
        frame3 = tk.LabelFrame(content, text="操作日志", bg=C_BG,
                                fg=C_TEXT, font=FONT_BODY)
        frame3.pack(fill="x", padx=8, pady=8)
        tk.Label(
            frame3,
            text=f"日志保存路径：{OPERATION_LOG_PATH}",
            bg=C_BG, fg=C_SUBTEXT, font=FONT_SETTINGS_HINT, wraplength=660, justify="left"
        ).pack(anchor="w", padx=8, pady=6)

        # 按钮
        btns = tk.Frame(content, bg=C_BG)
        btns.pack(pady=12)
        _make_btn(btns, "保存", self._save, bg=C_ACCENT, fg="white").pack(side="left", padx=8)
        _make_btn(btns, "取消", self.destroy, bg=C_BTN).pack(side="left", padx=8)

    def _save(self):
        from config import LLMProvider
        # provider
        ptxt = self._provider_var.get()
        provider = next((p for p in LLMProvider if p.value == ptxt), LLMProvider.ANTHROPIC)
        key = self._api_var.get().strip()
        model = self._model_var.get().strip()
        base_url = self._base_url_var.get().strip()
        # extra params JSON
        extra_raw = (self._extra_var.get() or "").strip()
        extra = {}
        if extra_raw:
            try:
                extra = json.loads(extra_raw)
                if not isinstance(extra, dict):
                    extra = {}
            except Exception:
                messagebox.showerror("设置错误", "额外参数必须是 JSON 对象，例如 {\"temperature\":0.2}")
                return

        self.explainer.configure(provider=provider, api_key=key, model=model, base_url=base_url, extra_params=extra)
        self.executor.use_trash = self._trash_var.get()
        self.destroy()
