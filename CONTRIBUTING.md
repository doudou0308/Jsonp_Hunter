# 参与贡献

## 反馈问题

提交 Issue 前，请先查看 [README 中的已知限制](README.md#界面版结果与已知限制)，确认是否已有说明。

为了方便复现，请提供：

- 使用的脚本：`jsonp_v.py` 或 `jsonp_burp.py`，以及版本或提交编号。
- 操作系统、Burp Suite、Java 和 Jython 的版本。
- 最短复现步骤、预期结果与实际结果。
- 扩展 Output / Errors 中的相关信息；附请求或日志时先移除 Cookie、认证头等敏感内容。

## 提交修改

从新分支发起 PR，说明解决了什么问题、修改范围和验证方法。尽量让一个 PR 聚焦一项改动，便于检查和回退。

扩展使用 Jython 2.7，修改脚本时请保留 Python 2.7 兼容性。自动化测试使用 Python 3，在仓库根目录执行：

```bash
python3 -m unittest discover -s tests -v
```

Windows 安装了 Python Launcher 时可用：

```powershell
py -3 -m unittest discover -s tests -v
```

模拟 Burp / Swing 的测试不能替代实际环境验收。修改界面或 Burp API 调用时，请在 PR 中写清是否做过实机验证，以及实际使用的版本。

## 上游声明

保留 [LICENSE-UPSTREAM](LICENSE-UPSTREAM) 和 [NOTICE.md](NOTICE.md) 中的上游声明。涉及版本差异或使用限制的修改，请同步更新 README。
