# sec-analyzer

> API 审计告警智能分析平台 —— 部门内部安全运营工具

## 概述

sec-analyzer 是面向安全运营团队的 API 告警分析工具，用于替代人工逐条研判海量 API 审计告警。平台通过两阶段聚类降噪 + 大模型判定，将告警分析效率提升一个数量级，并自动生成结构化处置建议。

**当前版本**：v1.2.0
**技术栈**：Python / Flask / SQLite / DeepSeek LLM

---

## 核心能力

| 模块 | 说明 |
|---|---|
| 告警批量分析 | 上传 API 审计日志 JSON，自动聚类降噪后调用大模型判定误报 |
| 两阶段聚类 | Stage1 按 `host + rule_id + path` 粗聚；Stage2 按 payload 语义相似度二次聚合 |
| 多轮投票 | 每组采样告警送 LLM 判定多次，共识阈值控制误判 |
| 报文分析器 | 粘贴单条 HTTP 原始报文，实时返回攻击类型与处置建议 |
| 人工复核 | 对 LLM 判定不确定的告警进行人工确认，结果回流为 Few-shot 样本 |
| 缓存层 | 相同 payload 的告警命中缓存，避免重复调用 LLM |

---

## 快速部署

### 环境要求

- Python 3.10+
- 一个 DeepSeek API Key（[platform.deepseek.com](https://platform.deepseek.com)）

### 安装

```bash
pip install flask openai
```

### 启动

```bash
python app.py
# 访问 http://localhost:8080
```

首次使用需注册账号，然后在「我的设置」中绑定 DeepSeek API Key。

---

## 项目结构

```
sec-analyzer/
├── app.py              # Flask 路由
├── core.py             # 聚类 / 缓存 / 语义相似度
├── db.py               # SQLite 数据模型
├── templates/          # 前端页面
├── sample_alerts.json  # 示例告警数据
└── data/               # 运行时数据（自动生成，不入库）
```

---

## 分析流程

```
告警 JSON 上传
    ↓
Stage1 聚类（host + rule_id + path_template）
    ↓
Stage2 语义聚类（payload n-gram 相似度 > 0.35）
    ↓
采样送 DeepSeek 判定（带缓存命中检查）
    ↓
多轮投票 + 共识判定
    ↓
输出结论 / 风险等级 / 处置建议
    ↓
人工复核 → 反馈回流为 Few-shot 样本
```

---

## 配置

| 配置项 | 位置 | 说明 |
|---|---|---|
| DeepSeek API Key | 页面「我的设置」 | 按用户绑定，存储在本地 SQLite |
| 聚类阈值 | `core.py CONFIG` | 可调相似度阈值、采样数、投票轮数 |

---

## 许可证

内部工具，仅限部门内使用。
