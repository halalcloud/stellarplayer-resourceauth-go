# Contributing

`resourceauth` 位于 OAuth Resource Server 的信任边界。贡献应保持验证策略严格、默认失败关闭，并避免把产品业务授权塞进通用中间件。

## 开发要求

- 代码保持 Go 1.24 语言兼容；开发和发布使用仍受支持且已安装安全补丁的 Go 工具链。
- 不记录或提交真实 Token、私钥、账号或生产 Endpoint 凭据。
- 不增加允许跳过签名、Issuer、Audience、时间或 `kid` 校验的选项。
- Resource Server 的 Client allowlist、角色和对象归属继续由调用方负责。
- 公共 API 或 Token 接受边界发生变化时同步更新 README、`docs/` 和 CHANGELOG。

提交前运行：

```powershell
$files = gofmt -l .
if ($files) { throw "gofmt required: $files" }
go test ./...
go vet ./...
```

涉及并发、公钥刷新或 Context 生命周期的修改还必须在支持 Race Detector 的平台运行：

```bash
go test -race ./...
```
