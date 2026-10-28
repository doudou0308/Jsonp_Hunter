# JSONP Scanner for Burp Suite

一个基于 Burp Suite Legacy Extender API 的 Jython 扩展，用随机回调名探测 JSONP 行为。它报告的是**可观察到的 JSONP 行为**，不能直接证明存在漏洞或敏感数据泄露。

> 本项目基于 [kapytein/jsonp](https://github.com/kapytein/jsonp) 修改。上游采用 MIT 许可证，版权声明及许可原文见 [LICENSE-UPSTREAM](LICENSE-UPSTREAM)。

## 功能

- 由 Burp Scanner 的扩展检查入口触发；只处理原始方法为 GET 的响应。
- 默认仅处理 Burp Target scope 内的 URL；需要配置 scope。
- 原响应声明为 JSON，或响应体可以解析成 JSON，才会探测。
- 测试 `.jsonp?callback=...`、`.jsonp`、`?callback=...` 和 `?jsonp=...` 四种变体；替换已有同名参数，保留其他查询参数。
- 使用每个原始 URL 独立生成的随机 callback，要求 2xx 响应体为完整的 callback 调用，且参数可被 JSON 解析。
- 清理与空 GET 请求不相符的请求头、请求不压缩的响应；保留 Cookie、Authorization 等原请求头。
- 内存去重、添加标记请求头防止自身请求递归触发，并限制检查的响应大小。
- 扫描结果包括原始请求/响应和匹配的探测请求/响应，便于手动复核。

## 使用前了解

**这个检查会发送额外请求。** 即使实现放在 `doPassiveScan`，它也不是纯被动分析：每个符合条件的 URL 最多发送四次 GET。GET 接口也可能有副作用；仅在明确授权且理解风险的范围内使用。探测会携带原请求的认证信息，测试请求会到达目标服务器，服务端也可能记录标记头和查询参数。

扩展需要支持 Scanner 扩展检查的 Burp 版本和 Jython 2.7 standalone JAR。该代码基于旧版 Extender API；实际可用性取决于 Burp/Jython 版本和运行环境，发布前请进行真实环境验证。Burp 的 UI 名称会随版本变化。

## 安装

1. 从 Jython 官方渠道获取 Jython 2.7 standalone JAR，在 Burp 的 Extensions 设置中配置 Python environment 路径。
2. 在 Extensions 中添加 Python 类型扩展，选择本仓库的 `jsonp_burp.py`。
3. Output 出现 `JSONP Scanner loaded...` 说明注册代码运行完成；加载成功不代表已检测到漏洞。
4. 在 Target 中将授权目标加入 scope，使用 Scanner 对含 JSON 响应的请求进行被动检查，或配置涵盖目标流量的 live audit。确认扫描配置启用了扩展检查。
5. 在扩展 Output 中查看 `JSONP Scanner testing:`。若返回与随机回调匹配的 JSONP，检查结果会显示 `JSONP callback supported`。

此扩展未注册 Proxy 流量监听器，流量经过代理本身不保证检查会运行。查询参数可能包含敏感信息，日志也会打印完整候选 URL，请妥善处理日志。

## 检查结果如何解读

`Information / Firm` 表示响应匹配了插件的 JSONP 语法检查；`Firm` 指对这种行为的确认程度，并非确认漏洞。请结合附带的 HTTP 消息，手动检查：数据是否敏感、认证是否必要、浏览器跨站请求是否携带相关 Cookie、目标是否提供其他保护，以及攻击者是否能实际读取数据。

默认只接受类似 `callback({"key":"value"});` 的完整响应，并要求参数为 JSON。具有防劫持前缀、注释、多个参数或 JavaScript 对象字面量等非标准形式可能漏报。仅凭端点支持 JSONP 或返回公开数据，不应认定存在泄露。

## 配置与限制

可在加载前修改源码顶部的常量：

| 常量 | 默认值 | 作用 |
| --- | --- | --- |
| `REQUIRE_SCOPE` | `True` | 只探测 Burp scope 内的原始 URL；建议保持开启。 |
| `MAX_RESPONSE_BYTES` | 1 MiB | 超过此大小的完整 HTTP 响应不解析。 |
| `MAX_TRACKED_URLS` | 10000 | 每次加载最多记录的原始 URL 数；达到上限后跳过新 URL。重载扩展清空记录。 |
| `CALLBACK_PARAMS` | `callback`, `jsonp` | 构造参数和去除原有参数所用的名称。 |

去重键是完整原始 URL，不区分不同 Cookie、响应内容或身份；同一 URL 的后续扫描会跳过。重载扩展可以重新检测。扩展不具备速率限制、并发控制、持久化配置或 UI；逐条请求同步发送，扫描大量不同 URL 时可能产生较高流量。不会自动跟随重定向；压缩响应或非常规编码可能导致漏报。无参数的 `.jsonp` 变体只有在服务端恰好返回本次随机 callback 时才会被报告，因此通常无法验证固定回调。带末尾斜杠的路径会尝试 `/path.jsonp/`，实际接口可能采用其他约定。

## 测试

在 Python 3 环境运行：

```bash
python3 -m unittest discover -s tests -v
```

测试使用模拟的 Burp/Java API 和本地 HTTP 服务，覆盖 URL 生成、重复 callback 参数、JSONP 内容验证、范围/方法/标记过滤、请求头清理、去重及成功与不匹配的请求流程。它**不是** Burp + Jython 的实际兼容性测试，也不能覆盖所有真实站点行为。

### 发布前的真实环境验收

1. 在隔离环境启动一个可控的 JSON 接口，让 `callback` 参数返回合法 JSONP；另准备一个只返回 JSON 的对照接口。
2. 在实际 Burp 和 Jython 2.7 环境加载扩展，加入目标 scope，使用 Scanner 处理两条 GET 响应。
3. 检查 Output、Errors、扫描结果和实际流量：JSONP 接口有结果，对照接口无结果；确认发出的请求数量、Cookie 和请求头符合预期。
4. 将目标移出 scope 再试、检查重复扫描、带原有 callback 的 URL，以及重载扩展后的行为。
5. 记录并发布测试所用 Burp 版本、Jython 版本和结果；如果遇到 Java/Jython 兼容问题，修复后重新测试。

## 目录

```text
jsonp_burp.py          扩展实现
tests/test_scanner.py  自动化测试
CHANGELOG.md           改动记录
NOTICE.md              来源和版权说明
LICENSE-UPSTREAM       上游 MIT 许可证原文
```

## 来源与许可

上游项目为 [kapytein/jsonp](https://github.com/kapytein/jsonp)，原作者版权声明与 MIT 许可证全文保存在 [LICENSE-UPSTREAM](LICENSE-UPSTREAM)。请在再分发时保留该声明及许可证。详见 [NOTICE.md](NOTICE.md)。本包未另外指定新增改动的许可证。
