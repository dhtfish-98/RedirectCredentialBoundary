# RedirectCredentialBoundary 0.1.1

作者：dhtfish98。此项目独立实现一个范围有限的 HTTP(S) GET 客户端，用于研究重定向时请求凭据的来源边界。默认只向当前请求的相同 `scheme/host/port` 来源继续发送 `Authorization`、`Cookie`、`Cookie2` 与可能含令牌的 `Referer`；转向其他来源时，从后续请求中永久移除这些标头。客户端不实现代理，因而拒绝调用方提供 `Proxy-Authorization`，避免把代理凭据直接发给目标站。自定义凭据标头可显式列入 `credential_header_names`。跨来源转发只能通过精确且有方向的 `credential_redirects=((来源, 目标),)` 例外显式允许，HTTPS 转 HTTP 时即使列入也会剥离。

源码位于 [src](../src)，实验和测试位于 [tests](../tests)。本项目许可证与说明集中在「项目文档」；本地构建时，缓存、隔离安装环境、分发包与运行收据均写入仓库的 `Build` 目录，该目录不会进入 Git。

## 使用

从本地 `Build/dist` 的 wheel 或 GitHub Release 附件安装后：

```python
from redirect_credential_boundary import RedirectClient

response = RedirectClient(max_redirects=5).get(
    "http://127.0.0.1:8000/start",
    headers={"Authorization": "Bearer example", "Cookie": "session=example"},
)
print(response.status, response.url, response.history)
```

`response.history` 只记录来源（不含路径和查询）、状态码和移除的**标头名**，不会记录请求凭据值。最终 `response.url`、响应标头与请求 URL 仍可能含敏感数据，调用方应按敏感信息处理。API 返回最终状态、标头和有上限的响应体。仅支持 GET；URL 中的用户名与密码、未编码空格或控制字符、未作百分号编码的非 ASCII 路径与查询、调用方自定义 `Host`、非 HTTP(S) 跳转会被拒绝。请求标头值限制为可用 Latin-1 编码且不含控制字符。默认最多跟随 5 次跳转，最终响应体最多 1 MiB。可显式配置超时和限额。

## 自有实验与验收

`tests/run_local_experiment.py` 启动两个绑定 `127.0.0.1` 随机端口的 HTTP 服务。故意弱化的**测试基线**在 A→B 后仍传送一次性合成 `Authorization` 和 `Cookie`；正式客户端在相同输入下剥离凭据。运行记录包含输入标记散列、A/B 收到的标头存在性与标记匹配结果、最终状态、同源相对跳转、混合大小写主机、循环/跳数限制。原始合成值不写入收据。

完整验证入口：

```text
python3 .github/scripts/validate.py
```

该入口测试源码、构建 sdist 和 wheel、将 wheel 安装到 Build 下隔离环境，再从项目源码外执行安装版测试及双服务器实验；每个步骤保存实际退出码和日志。本地查看 `Build/validation.json` 的 `status`，不能仅凭有分发包认定运行通过。公开版本另需核对相同提交的 CI、标签与附件。

## 研究来源与权利

独立问题范围参考 [urllib3 在固定源码快照中的跨主机重定向标头处理](https://github.com/urllib3/urllib3/blob/a164d79c8cf760f222daa2dc7f67d0e1ca7fb17c/src/urllib3/poolmanager.py#L491-L501)。此 SHA 只锁定所读仓库状态；[该提交本身](https://github.com/urllib3/urllib3/commit/a164d79c8cf760f222daa2dc7f67d0e1ca7fb17c)修复的是 HTTP/2 探测缓存锁，与本项目的实验缺陷无关。上游许可证为 [MIT](https://github.com/urllib3/urllib3/blob/a164d79c8cf760f222daa2dc7f67d0e1ca7fb17c/LICENSE.txt)。本项目没有复制或改署名上游源码；本项目新写代码的[许可证](LICENSE)保存在「项目文档」，构建时复制到 Build 暂存源码以随包分发。这里的故意弱化基线不是 urllib3 漏洞，也不代表外部真实事件。

## 限制

本项目不提供通用浏览器 Cookie jar、代理、任意 HTTP 方法、上传、DNS 重绑定/SSRF 防护或复杂连接池。默认策略只识别列出的敏感标头；使用其他私有标头时必须通过 `credential_header_names` 标记。URL 查询参数中的令牌不是标头策略的保护对象，调用方不应把秘密放入 URL。当前实验是本机 HTTP 双来源，未实测 HTTPS 证书链、代理链、IPv6 和多主机 DNS 条件。它证明本项目在自有实验中的边界行为，不证明 CVP 资格、真实用户任务受模型防护影响或外部部署有效性。
