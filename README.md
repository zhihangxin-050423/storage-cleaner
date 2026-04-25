# StorageCleaner - 智能存储空间分析与安全清理工具

StorageCleaner 是一个面向 Windows 的本地存储空间分析与安全清理工具。它的设计目标不是“自动帮你删东西”，而是：

**先扫描、再分类、再解释，最后由用户明确确认清理。**

项目当前提供 Tkinter 桌面界面、规则风险分级、重复文件检测、AI 辅助解释、回收站/永久删除、软链接创建、操作日志与 JSON 报告导出等功能。

---

## 目录结构

```text
storage_cleaner/
├── main.py          # 程序入口，依赖检查，启动 Tkinter UI
├── config.py        # 全局配置：Windows 路径、风险类别、阈值、LLM 默认值、日志路径
├── scanner.py       # 文件扫描：递归遍历、元数据收集、目录统计、MD5 查重
├── rule_engine.py   # 规则引擎：基于路径/扩展名/时间/大小等做风险分类
├── risk_assessor.py # 汇总统计：风险大小、分类统计、重复文件浪费空间
├── api_client.py    # 统一 HTTP 客户端：错误分类、重试、request_id、SSE 简化解析
├── explainer.py     # AI 解释模块：多 Provider、批量分析、缓存、JSON 容错恢复
├── executor.py      # 安全执行：回收站/永久删除/软链接 + 操作日志
├── ui_main.py       # 主界面：扫描、筛选、分析、执行、设置
└── requirements.txt # 第三方依赖
```

| 模块 | 主要职责 | 是否直接删除文件 |
|------|----------|------------------|
| `scanner.py` | 扫描文件系统，收集文件元数据，检测重复文件 | 否 |
| `rule_engine.py` | 按可解释规则分类文件并给出风险等级 | 否 |
| `risk_assessor.py` | 生成总大小、风险大小、分类统计、重复浪费空间 | 否 |
| `api_client.py` | 封装 LLM HTTP 请求、错误分类、重试与 request_id | 否 |
| `explainer.py` | 调用 LLM 生成文件用途解释和删除建议 | 否 |
| `executor.py` | 执行回收站删除、永久删除、软链接创建并写日志 | 是 |
| `ui_main.py` | 展示扫描结果并接收用户操作 | 间接触发 |

---

## 环境要求

- Windows 10 / 11
- Python 3.10+
- Python 发行版需包含 `tkinter`

安装依赖：

```bash
pip install -r requirements.txt
```

当前第三方依赖：

| 依赖 | 用途 | 说明 |
|------|------|------|
| `send2trash` | 将文件移入系统回收站 | 推荐安装；回收站失败时不会静默改为永久删除 |
| `anthropic` | Claude 官方 SDK | 可选运行时依赖；未安装时 Anthropic 也可走内置 HTTP 调用 |

OpenAI、DeepSeek、Gemini 当前使用内置 HTTP 调用，不需要安装对应 SDK。

---

## 运行方式

在项目目录下运行：

```bash
python main.py
```


---

## 核心功能

### 1. 文件扫描

- 递归扫描用户选择的目录。
- 默认跳过系统关键目录，例如 `C:\Windows`、`Program Files`、部分 `ProgramData\Microsoft/Windows`。
- 收集文件名、路径、大小、创建时间、修改时间、访问时间、扩展名。
- 跳过符号链接，避免循环遍历。
- 预统计文件数量，用于 UI 进度显示。
- 统计目录空间占用，目录分析页展示 Top 50。
- 支持取消扫描。

### 2. 重复文件检测

重复检测采用两阶段策略：

1. 先按文件大小分组，大小不同直接排除。
2. 小文件计算全量 MD5。
3. 大于 `PARTIAL_HASH_THRESHOLD` 的文件先使用首尾片段 + 文件大小做筛选哈希。
4. 大文件候选重复组再计算全量 MD5 二次确认。

重复组中保留第一份为原始文件，其余副本标记为“重复文件 / 中风险”。

### 3. 风险分级

| 风险等级 | 典型文件 | 默认选择状态 | 清理策略 |
|----------|----------|--------------|----------|
| 低风险 | 临时文件、缓存文件、较旧日志、已知缓存目录 | 默认选中 | 可以优先清理 |
| 中风险 | 重复副本、大文件、安装包、压缩包、备份、构建产物、长期未访问文件 | 默认选中 | 建议人工确认 |
| 高风险 | 系统目录文件、配置/脚本/证书/数据库、文档、照片、视频、未知文件 | 默认不选中 | 默认跳过，不自动删除 |

未知文件会被保守标记为高风险，建议先查看详情或使用智能分析。

### 4. 规则引擎

当前规则引擎包含 18 类规则，全部基于本地可解释条件，不依赖大语言模型。

| 规则 | 典型条件 | 风险/类别 |
|------|----------|-----------|
| `SystemDirectoryRule` | 系统关键目录 | 高风险 / 系统文件 |
| `KnownTempDirRule` | `%TEMP%`、`AppData\Local\Temp` 等 | 低风险 / 临时文件 |
| `KnownCacheDirRule` | Chrome、Edge、VS Code、npm、pip、JetBrains 等缓存路径 | 低风险 / 缓存文件 |
| `MediumRiskCacheRule` | `.gradle`、`.m2`、`.cargo`、`.nuget`、`conda\pkgs` 等 | 中风险 / 缓存文件 |
| `BuildArtifactRule` | `dist`、`build`、`target`、`.next`、`coverage` 等 | 中风险 / 缓存文件 |
| `DuplicateFileRule` | MD5 确认相同的重复副本 | 中风险 / 重复文件 |
| `LowRiskExtensionRule` | `.tmp`、`.cache`、`.dmp`、`.crdownload` 等 | 低风险 / 临时文件 |
| `LogFileRule` / `LogDirHeuristicRule` | 日志扩展名或 `log/logs` 目录 | 低/中风险 / 日志文件 |
| `InstallerRule` | `.exe`、`.msi`、`.iso` 等安装包 | 中风险 / 安装包 |
| `ArchiveInDownloadsRule` | 下载目录中的压缩包 | 中风险 / 压缩包 |
| `MediumRiskExtensionRule` | `.bak`、`.old`、`.backup` 等 | 中风险 / 临时/备份文件 |
| `AppResidualRule` | Recent、缩略图缓存、Cookie 等应用残留路径 | 中风险 / 应用残留 |
| `LargeFileRule` | 大于 `LARGE_FILE_THRESHOLD` | 中风险 / 大文件 |
| `OldFileRule` | 超过 365/730 天未访问 | 中风险 / 长期未访问 |
| `HighRiskExtensionRule` | `.dll`、`.sys`、`.reg`、`.db`、`.key` 等 | 高风险 / 配置或系统关键文件 |
| `MediaFileRule` | 图片、音频、视频 | 高风险 / 媒体文件 |
| `DocumentFileRule` | PDF、Office、Markdown、CSV 等 | 高风险 / 文档文件 |

---

## 智能解释模块

智能解释只用于“帮助用户理解文件用途和删除影响”，不会替代规则引擎，也不会直接执行删除。

支持的 Provider：

- Claude (Anthropic)
- ChatGPT (OpenAI)
- DeepSeek (OpenAI 兼容接口，也支持 Anthropic 兼容 Base URL)
- Gemini (Google)

能力：

- 单文件解释：输出来源、功能、删除影响、建议、置信度。
- 批量分析未知文件：按风险和文件类型智能分批。
- 本地缓存：相似文件解释缓存 30 天，最多 5000 条，缓存文件为 `logs/explain_cache_v2.json`。
- JSON 容错：支持代码块包裹、前后缀、部分 JSON 提取。
- 截断恢复：单文件和批量分析遇到疑似截断 JSON 时，会尝试一次“JSON 修复”请求。
- 上下文超限恢复：批量分析遇到上下文超限时，会自动二分拆批重试。
- 动态并发降级：批量调用遇到 429/529 时会降低并发并短暂退避。
- 请求诊断：记录 `last_request_id`、`last_error_kind`、`last_call_meta`，方便排查 API 问题。

### API Key 配置

方式 1：环境变量。

```bash
set ANTHROPIC_API_KEY=sk-ant-xxxx
set OPENAI_API_KEY=sk-xxxx
set DEEPSEEK_API_KEY=sk-xxxx
set GEMINI_API_KEY=xxxx
set GOOGLE_API_KEY=xxxx
```

方式 2：界面右上角“设置”中配置 Provider、Model、Base URL、API Key 和额外参数。

### DeepSeek Base URL

当 Provider 选择 DeepSeek：

- Base URL 留空或填写 `https://api.deepseek.com`：使用 OpenAI 兼容接口，调用 `/v1/chat/completions`。
- Base URL 填写 `https://api.deepseek.com/anthropic`：使用 Anthropic Messages 兼容接口，调用 `/v1/messages`。

DeepSeek 模型下拉当前提供：

- `deepseek-v4-flash`
- `deepseek-v4-pro`
- `deepseek-chat`
- `deepseek-reasoner`

### 可选环境变量

| 环境变量 | 用途 |
|----------|------|
| `API_TIMEOUT_MS` | 覆盖单次 API 请求超时时间，单位毫秒 |
| `LLM_STREAM` / `OPENAI_STREAM` | 为 OpenAI/DeepSeek 兼容接口启用简化 SSE 流式读取 |
| `LLM_STREAM_IDLE_TIMEOUT_MS` | 流式读取空闲超时，单位毫秒 |
| `CLAUDE_STREAM_IDLE_TIMEOUT_MS` | 兼容 Claude Code 风格的流式空闲超时变量 |
| `OPENAI_ENABLE_THINKING` | 控制 OpenAI/DeepSeek 兼容接口是否注入 thinking 参数 |

---

## 安全删除与软链接

### 删除流程

1. 用户在文件列表中勾选文件。
2. 点击“移至回收站（推荐）”或“永久删除（不可恢复）”。
3. UI 弹窗二次确认。
4. `Executor` 检查文件风险和存在性。
5. 高风险文件默认跳过。
6. 执行成功后从当前列表移除已处理文件。
7. 写入 JSON 操作日志。

安全策略：

- 默认使用回收站，保留恢复可能。
- 回收站失败时只报错，不会自动降级为永久删除。
- 永久删除需要输入 `DELETE`。
- `allow_high_risk` 默认关闭，高风险文件即使被勾选也会跳过。
- 批量执行中单个文件失败不会中断其他文件。

### 软链接功能

在文件列表中选中一个文件后，可以点击“创建软链接”创建 Windows 符号链接。

限制：

- 只支持普通文件，不支持目录或特殊项。
- 源文件不存在、源文件本身已是链接时会拒绝。
- 高风险文件、系统关键目录文件、高风险扩展名文件会拒绝。
- `pagefile.sys`、`hiberfil.sys`、`swapfile.sys` 等系统文件会拒绝。

Windows 创建符号链接可能需要开启“开发者模式”或以管理员权限运行。

---

## 日志与报告

默认日志位于项目根目录下。

常见文件：

| 路径 | 内容 |
|------|------|
| `logs/operation/operation_log.json` | 删除、跳过、失败、软链接等操作记录 |
| `logs/explain_cache_v2.json` | AI 解释缓存 |
| `logs/rule_engine_errors.log` | 规则执行异常日志 |

操作日志目录可以在设置窗口中修改。界面“操作日志”标签页默认展示最近 200 条记录。

扫描结果可以通过“导出报告 (JSON)”保存，报告包含：

- 扫描时间和扫描路径
- 文件总数和总大小
- 文件路径、大小、风险等级、类别、规则原因
- AI 解释结果
- 重复文件信息
- 最后访问时间等元数据

---

## 界面说明

### 顶部区域

- 扫描路径输入框
- “浏览”按钮
- “开始扫描”按钮
- “取消”按钮
- “设置”按钮
- 扫描进度条和状态提示

### 标签页

| 标签页 | 内容 |
|--------|------|
| 概览 | 总占用空间、低/中/高风险大小、可清理空间、文件总数、分类统计 |
| 文件列表 | 文件名、大小、风险、类别、最后访问、路径；支持勾选、筛选、排序 |
| 重复文件 | 按重复组展示原始文件和重复副本 |
| 目录分析 | 目录空间占用 Top 50 |
| 操作日志 | 最近操作记录，可刷新或清除 |

### 文件列表操作

- 点击勾选列切换单个文件选择状态。
- “全选低风险”一键选择低风险文件。
- “全选 / 全不选”批量切换。
- 按风险等级筛选。
- 按最小大小 MB 筛选。
- 点击表头排序。

### 底部操作区

- “获取智能分析报告”：对当前选中文件调用 AI。
- “批量分析未知文件”：对尚未分析的未知文件批量调用 AI。
- “移至回收站（推荐）”：安全清理，可恢复。
- “永久删除（不可恢复）”：不可恢复，需要输入 `DELETE`。
- “创建软链接”：为当前选中文件创建 Windows 符号链接。
- “导出报告 (JSON)”：导出扫描结果。
- “复制选中路径”：复制已勾选文件路径到剪贴板。

---

## 主要配置项

可在 `config.py` 中调整：

```python
LARGE_FILE_THRESHOLD   = 500 * 1024 * 1024  # 大文件阈值，默认 500 MB
MEDIUM_LARGE_THRESHOLD = 100 * 1024 * 1024  # 中等大文件阈值，默认 100 MB
PARTIAL_HASH_THRESHOLD = 100 * 1024 * 1024  # 大文件部分哈希阈值
PARTIAL_HASH_READ_SIZE = 64 * 1024          # 部分哈希读取大小
OLD_FILE_DAYS          = 365                # 长期未访问阈值
VERY_OLD_FILE_DAYS     = 730                # 更长期未访问阈值
LLM_PROVIDER           = LLMProvider.ANTHROPIC
LLM_MAX_TOKENS         = 600
LOG_BASE_DIR           = PROJECT_ROOT / "logs"
```

默认模型配置在 `DEFAULT_LLM_MODELS` 中，可通过设置窗口覆盖。

---

## 使用建议

1. 首次使用建议从 `Downloads`、`AppData\Local\Temp` 或具体项目目录开始，不要直接扫描整个 `C:\`。
2. 优先使用“移至回收站（推荐）”。
3. 高风险文件不要为了释放空间强行处理，尤其是文档、照片、数据库、证书、配置和系统文件。
4. 清理前可以先导出 JSON 报告留档。
5. AI 建议只是解释辅助，最终以用户确认和规则风险为准。
6. 批量 AI 分析会消耗 API 额度，未知文件很多时建议分批处理。

---

## 开发者说明

该项目仍在维护中，欢迎反馈问题和建议。

开发者邮箱：

- [1131230221@stu.jiangnan.edu.cn](mailto:1131230221@stu.jiangnan.edu.cn)
- [zhihangxin691@gmail.com](mailto:zhihangxin691@gmail.com)

（中国·无锡·江南大学·数学与数据科学学院）
