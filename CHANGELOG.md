# Changelog

## v1.2.0 (2026-10)

### Added
- 报文分析器：单条 HTTP 报文实时判定攻击类型与处置建议
- Stage2 payload 语义聚类：n-gram Jaccard 相似度二次聚合
- Few-shot 反馈闭环：人工复核结果自动回流
- 告警缓存层：相同 payload 命中缓存，避免重复调用 LLM

### Changed
- 分析任务改为后台异步执行，前端轮询进度
- 数据库从 JSON 文件迁移至 SQLite，支持多用户隔离

## v1.0.0 (2026-06)

### Added
- 基础告警批量分析流程
- 用户注册 / 登录
- DeepSeek API 集成
