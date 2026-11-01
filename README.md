# JSONP Hunter

基于 [kapytein/jsonp](https://github.com/kapytein/jsonp) 改写的 Burp Suite JSONP 探测扩展，使用 Jython 2.7 和 legacy Extender API。检测结果表示 JSONP 行为或线索，不能直接证明敏感数据泄露或可利用漏洞。

## 选择版本

| 文件 | 用途 | 检测与控制 |
| --- | --- | --- |
| [`jsonp_v.py`](jsonp_v.py) | 带独立结果面板的交互版，支持过滤、CSV 和发送到 Repeater | `IHttpListener` 自动监听 JSON 响应；两个后台 worker；探测标记防递归；按 host、path、payload 去重；基础 MIME 和 callback 特征检查 |
| [`jsonp_burp.py`](jsonp_burp.py) | 使用 Scanner 扩展检查的版本 | 默认 scope 内 GET；随机 callback；完整 JSONP/JSON 参数验证；响应大小和记录数量限制 |

**一次只加载其中一个版本**，避免重复探测。界面版的判定和资源限制尚未与 Scanner 版统一。

## 界面版相对上游的改进

| 方面 | kapytein/jsonp | 界面版 |
| --- | --- | --- |
| 触发入口 | Scanner 被动检查回调 | HTTP listener，可处理各工具经过的 JSON 响应 |
| 结果展示 | Scanner issue | 独立 JSONP 标签页，展示候选、状态码、MIME、判定、摘要 |
| 判定 | 返回 `script` MIME 即报告 | JS MIME 与 callback 特征结合；区分 HIT / SOFT / MISS / ERR |
| 候选处理 | 首个命中后返回 | 继续检查剩余候选 |
| 执行 | 扫描回调中同步请求 | 后台队列和两个 worker；单个任务中的候选仍串行发送 |
| 重复发包 | 无显式发包去重 | 带锁的去重集合及探测头防递归 |
| 证据 | issue 附带原始 JSON 消息 | HIT issue 附带实际探测请求和响应 |
| 复测与整理 | 无专用面板 | 手动扫描、Repeater、筛选与 CSV 导出 |

四种 payload 来自上游，不是新增检测策略：`.jsonp?callback=test`、`.jsonp`、`?callback=test`、`?jsonp=test`。当前 `.jsonp` 后缀在带扩展名的路径上会插入扩展名前，具体限制见下文。

## 安装与使用

目标环境：Burp Suite Professional 2025.7（Java 24）、Jython 2.7.4 standalone。代码使用 Python 2.7 语法；仍需在该实际环境验收。

1. 在 Burp 的 Extensions 设置中配置 Jython standalone JAR。
2. 添加 Python 扩展，选择 `jsonp_v.py`，确认 Output 出现加载提示。
3. 打开 JSONP 标签页。默认 Auto scan 开启，观察经过 Burp 的 JSON 响应即可入队；也可以从已有 JSON 响应的右键菜单选择 `JSONP: scan selected`。
4. 选中结果行后点击 **Send to Repeater**，或双击目标行。成功调用后，底部和 Output 显示编号，如 `JSONP-1`。
5. 打开 Repeater，找到对应编号；在 Repeater 中点击 **Send** 才会实际发送该请求。失败时查看扩展 Errors。

未选中行会弹出提示；双击按鼠标实际点击行定位；发送前会进行视图行到模型行转换。发送 API 正常返回只说明调用完成，仍应在 Repeater 中确认请求已出现。

筛选支持文本和 Only HIT；CSV 导出全部已记录结果。Clear 只清显示记录；关闭 Auto scan 只停止接收新的自动任务，已有任务仍可继续运行。

### Scanner 版

若使用 `jsonp_burp.py`：先将授权目标加入 Burp Target scope，再用 Scanner 的被动检查或配置了扩展检查的 live audit 触发。该版本没有独立结果面板，代理流量经过 Burp 本身不保证触发检查。它使用随机 callback，只报告 2xx 且完整 callback 调用中包含可解析 JSON 的响应。

源码配置：`REQUIRE_SCOPE=True`、`MAX_RESPONSE_BYTES=1 MiB`、`MAX_TRACKED_URLS=10000`。去重使用完整原始 URL，但不区分登录态；重载扩展会清空记录。

## 界面版结果与已知限制

- **HIT**：JS MIME 且匹配预期 callback 子串；会生成 `Information / Firm` issue。当前不是 JavaScript 语法验证，字符串、注释、函数声明等仍可能误报。
- **SOFT**：JS MIME 但未匹配预期 callback，保留供人工检查。
- **MISS**：未识别为 JS，不代表端点不存在 JSONP。
- **ERR**：结果或响应为空；部分异常只记录到 Errors。

当前尚未合入整套审计修复，尤其需要了解：

- `?jsonp=test` 缺少 callback 映射，目前无法 HIT；无参数 `.jsonp` 通常只能 SOFT。
- URL 构造存在扩展名、分号路径参数和已有同名 query 参数问题；例如 `/api.json` 会生成 `/api.jsonp.json`。
- 去重忽略协议、端口、query 和登录态，可能漏测；Clear 不清除去重状态，手动扫描同样受去重限制。
- 自动模式尚无 scope 和原始方法过滤；探测使用 GET，继承部分原请求头及认证信息。POST 请求体不会迁移到 query。
- 队列、去重集合、结果与正文解析缺乏容量上限；CSV 尚未加固公式注入；大规模长时间运行需要进一步改进。
- 暂无卸载时的完整 worker 停止机制；legacy `makeHttpRequest` 无单次请求超时或可靠取消接口，应检查项目网络超时设置。

**两个版本都会主动发送额外 GET 请求。** 仅在明确授权的目标上使用。GET 也可能有业务副作用；认证头、Cookie 和标记头会到达目标。原版与这两个版本都不能自动证明跨站读取、凭证携带和数据敏感性。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

`test_scanner.py` 覆盖 Scanner 版逻辑和本地 HTTP 流程；`test_repeater.py` 通过提取界面版实际方法并模拟 Swing / Burp，检查行选择、排序映射、HTTPS、错误反馈和 EDT 调度。测试代码运行在 Python 3，扩展运行在 Jython 2.7；这些检查不等于 Burp / Java / Jython 实机兼容性验证。

## 来源与许可

上游：[kapytein/jsonp](https://github.com/kapytein/jsonp)，Copyright (c) 2019 kapytein，MIT License。原始声明及许可全文见 [LICENSE-UPSTREAM](LICENSE-UPSTREAM)，再分发时请保留。详见 [NOTICE.md](NOTICE.md)；本项目未另外指定新增改动的许可证。
