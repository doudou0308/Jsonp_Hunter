# 更新记录

## 2026-11-01 — 交互版与 Repeater 修复

- 新增 `jsonp_v.py` 交互版：独立结果面板、后台探测、过滤、CSV、手动扫描与 Repeater 入口。
- Repeater 未选中行时提示；双击定位点击行，发送前转换视图/模型行，校验请求和目标。
- 为每次发送命名 `JSONP-N`，增加成功反馈与 Python/Java 异常日志；UI 初始化及发送流程调度到 EDT。
- 保留已有 `jsonp_burp.py` Scanner 版和测试，避免覆盖其随机 callback、scope 与容量限制。
- README 增加版本选择、与上游的实际差异及界面版已知限制。
- 新增 Repeater 模拟回归测试；未声称已通过 Burp/Jython 实机验收。

## 先前 Scanner 版改动

- 修正路径、已有回调参数与查询字符串的构造和处理。
- 改为随机 callback 与完整 JSONP 响应体验证，报告观察到的行为而非直接认定漏洞。
- 仅处理 GET，默认限定 Burp scope，删除不适用于空 GET 请求的头。
- 增加响应大小限制、URL 去重和自发请求标记。
- 添加模拟 Burp API 的自动化测试及本地 HTTP 集成测试。
- 文档说明真实 Burp/Jython 验证、限制和上游来源与许可说明。
