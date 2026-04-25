# StorageCleaner - 智能存储空间分析与安全清理工具

## 项目概述

StorageCleaner 是一个针对 Windows 系统设计的存储空间分析与安全清理工具，核心理念是：
**不盲目删除，先分析后决策，删除前必须可解释、可恢复。**

---

## 系统架构

```
storage_cleaner/
├── main.py          # 程序入口，依赖检查
├── config.py        # 全局配置（Windows路径、阈值、扩展名分组）
├── scanner.py       # 扫描模块（递归遍历、哈希查重）
├── rule_engine.py   # 规则引擎（纯规则，无AI）
├── risk_assessor.py # 风险评估与统计摘要
├── explainer.py     # AI解释模块（Anthropic API）
├── executor.py      # 安全执行模块（回收站/删除 + 日志）
├── ui_main.py       # 主界面（Tkinter）
└── requirements.txt # 依赖列表
```

### 模块职责

| 模块 | 职责 | 是否涉及删除 |
|------|------|-------------|
| scanner.py | 扫描文件系统，收集元数据，查重 | ❌ |
| rule_engine.py | 基于规则分类文件，给出初步风险 | ❌ |
| risk_assessor.py | 汇总统计，生成报告 | ❌ |
| explainer.py | 调用LLM生成可读解释 | ❌ |
| executor.py | 执行删除，记录日志 | ✅（需用户确认） |
| ui_main.py | 展示结果，接收用户决策 | ❌（只触发executor）|

---

## 安装步骤

### 环境要求
- Windows 10 / 11
- Python 3.10+

### 安装依赖

```bash
# 基础功能（推荐：回收站删除）
pip install send2trash

# 可选：Claude(Anthropic) 官方 SDK（不装也能用内置 HTTP 调用）
pip install anthropic
```

| 依赖 | 用途 | 必须 |
|------|------|------|
| send2trash | 将文件移入回收站（可恢复） | 推荐 |
| anthropic | Claude 官方 SDK（可选；不装也可走内置 HTTP 调用） | 可选 |

**说明：**
- **ChatGPT(OpenAI) / DeepSeek / Gemini**：本项目默认使用 **内置 HTTP 调用**，因此**不强制安装对应 SDK**；只需要在设置里配置 Provider/Model/Base URL/API Key（或设置环境变量）。
- **Claude(Anthropic)**：可直接用内置 HTTP；如果安装 `anthropic`，会优先使用官方 SDK。

### 运行

```bash
python main.py
```

---

## 功能说明

### 1. 扫描模块

- 递归遍历指定目录
- 自动跳过系统关键目录（C:\Windows、Program Files 等）
- 收集：文件名、大小、创建/修改/访问时间、扩展名
- 基于哈希检测重复文件：小文件直接全量 MD5；大文件先部分哈希筛选，再用全量 MD5 二次确认（降低误判风险）
- 支持取消操作

### 2. 风险分级机制

| 风险等级 | 颜色 | 典型文件 | 默认操作 |
|---------|------|---------|---------|
| 低风险 🟢 | 绿色 | .tmp/.cache/已知缓存目录 | 默认选中，可直接清理 |
| 中风险 🟡 | 橙色 | 重复文件/大文件/安装包/.log | 需用户确认 |
| 高风险 🔴 | 红色 | 系统文件/.dll/.reg/未知文件 | 默认不选中，拒绝自动删除 |

### 3. 规则引擎（rule_engine.py）

共 15 条规则，按优先级排序：

| 规则 | 优先级 | 匹配条件 | 结果 |
|------|--------|---------|------|
| SystemDirectoryRule | 100 | 路径在系统关键目录内 | 高风险 |
| HighRiskExtensionRule | 80 | .dll/.sys/.reg/.cfg等 | 高风险 |
| KnownTempDirRule | 90 | %TEMP%/%TMP%路径 | 低风险 |
| KnownCacheDirRule | 85 | 已知缓存路径片段 | 低风险 |
| DuplicateFileRule | 75 | MD5一致的重复副本 | 中风险 |
| LowRiskExtensionRule | 70 | .tmp/.cache/.lock等 | 低风险 |
| LogFileRule | 70 | .log文件 | 低/中风险 |
| InstallerRule | 65 | .exe/.msi/.iso | 中风险 |
| ... | ... | ... | ... |

所有规则均基于可解释的条件，不依赖 AI 判断。

### 4. AI 解释模块

- 支持多种大语言模型接口（用于解释未知文件用途，**不参与规则判定**）
  - Claude (Anthropic)
  - ChatGPT (OpenAI)
  - DeepSeek（OpenAI 兼容接口）
  - Gemini (Google)
- 单文件解释：分析文件用途 + 给出删除建议
- 批量分析：对未知文件批量请求，减少 API 调用
- 本地缓存：相同类型文件不重复请求
- 离线降级：无 API Key 时系统照常运行，仅跳过 AI 功能

配置方式：
```bash
# 方式1：环境变量（任选其一）
set ANTHROPIC_API_KEY=sk-ant-xxxx
set OPENAI_API_KEY=sk-xxxx
set DEEPSEEK_API_KEY=sk-xxxx
set GEMINI_API_KEY=xxxx
set GOOGLE_API_KEY=xxxx

# 方式2：程序内设置（⚙ 设置 按钮：选择 Provider/Model/Base URL/API Key）
```

**DeepSeek Base URL 说明（官方文档）：**
- **OpenAI 兼容格式**：`https://api.deepseek.com`（程序会调用 `/v1/chat/completions`）
- **Anthropic 兼容格式**：`https://api.deepseek.com/anthropic`（程序会调用 `/v1/messages`）

当你在设置里把 Provider 选为 DeepSeek：
- Base URL 留空或填 `https://api.deepseek.com` → 使用 OpenAI 兼容格式
- Base URL 填 `https://api.deepseek.com/anthropic` → 自动切换到 Anthropic 兼容格式

可选：在“额外参数(JSON)”里填写 OpenAI/DeepSeek 兼容接口需要的扩展字段（例如推理强度等）。

### 5. 安全删除机制

**删除流程：**
1. 用户在列表中勾选文件
2. 点击「移至回收站」或「永久删除」
3. 系统检查：高风险文件自动跳过（除非明确允许）
4. 回收站模式下若移入回收站失败，默认仅报错，不会静默降级为永久删除
5. 永久删除需要二次输入 `DELETE` 确认
5. 每次操作写入 JSON 日志

### 6. 软链接（符号链接）功能

- 在文件列表中选中一个文件后，点击右侧「🔗 创建软链接」
- 选择软链接保存路径后，程序会创建一个指向源文件的 **Windows 符号链接**（不会删除/移动源文件）

**安全限制：**
- 高风险文件、系统关键目录中的文件默认禁止创建软链接
- 源文件本身已是链接时，会拒绝创建

**Windows 权限提示：**
- Windows 创建符号链接可能需要开启“开发者模式”或以管理员权限运行
- 若失败，程序会给出提示信息并写入操作日志

### 6. 软链接（符号链接）功能

- 在文件列表中选中一个文件后，点击右侧「🔗 创建软链接」
- 选择软链接保存路径后，程序会创建一个指向源文件的 **Windows 符号链接**（不会删除/移动源文件）

**安全限制：**
- 高风险文件、系统关键目录中的文件默认禁止创建软链接
- 源文件本身已是链接时，会拒绝创建

**Windows 权限提示：**
- Windows 创建符号链接可能需要开启“开发者模式”或以管理员权限运行
- 若失败，程序会给出提示信息并写入操作日志

**操作日志位置：**
```
%LOCALAPPDATA%\StorageCleaner\operation_log.json
```

日志内容：
- 操作时间
- 文件路径、大小、名称
- 风险等级、类别
- 操作结果（成功/失败/跳过）
- 错误信息（如有）

---

## UI 界面说明

### 标签页

| 标签 | 内容 |
|------|------|
| 📊 概览 | 统计卡片（总大小、各风险等级大小）+ 分类表 |
| 📄 文件列表 | 可筛选/排序的文件表，支持逐个勾选 |
| 🔗 重复文件 | 按组展示重复文件，标注原始/副本 |
| 📁 目录分析 | Top 50 目录空间占用排名 |
| 📋 操作日志 | 历史删除记录，可导出 |

### 文件列表操作

- **单击 ☑/☐ 列**：切换文件选中状态
- **全选低风险**：一键选中所有低风险文件
- **筛选**：按风险等级或最小文件大小筛选
- **排序**：点击列表表头排序

### 底部操作区

- **获取 AI 分析**：对当前选中文件调用 AI 生成解释
- **批量分析未知文件**：对所有"未知文件"类别批量 AI 分析
- **移至回收站**：安全删除，可从回收站恢复
- **永久删除**：不可恢复，需二次确认
- **导出报告**：将扫描结果导出为 JSON

---

## 配置说明（config.py）

可按需修改以下参数：

```python
LARGE_FILE_THRESHOLD   = 500 * 1024 * 1024  # 大文件阈值（默认500MB）
OLD_FILE_DAYS          = 365                  # 旧文件阈值（默认1年）
VERY_OLD_FILE_DAYS     = 730                  # 更旧文件阈值（默认2年）
LLM_MODEL              = "claude-sonnet-4-20250514"  # 使用的AI模型
```

---

## 注意事项

1. **不会自动删除任何文件**，所有删除操作需用户明确触发
2. **高风险文件默认被排除在外**，系统目录绝不可删
3. 建议优先使用**回收站模式**，保留恢复可能
4. 首次使用建议先**导出报告**，检查无误再执行清理
5. 扫描 C:\ 根目录时间较长，可先从 Downloads / AppData 开始

---

## 开发者说明

- 该项目正在维护中，如您有对本项目的建议均可以与开发者联系
- 开发者邮箱：
 [1131230221@stu.jiangnan.edu.cn](mailto:1131230221@stu.jiangnan.edu.cn)  [zhihangxin691@gmail.com](mailto:zhihangxin691@gmail.com) （中国·无锡·江南大学·数学与数据科学学院）
