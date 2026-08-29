# 从 Gateway 内置包迁移

早期版本的 Resource Server 包位于：

```go
import "github.com/city404/stellarplayer-gateway/resourceauth"
```

独立模块发布后，消费者应固定一个经过审核的 Release Tag，并修改为：

```go
import resourceauth "github.com/halalcloud/stellarplayer-resourceauth-go"
```

公共 API 和安全语义保持一致；调用代码通常只需要修改 import path。迁移后运行：

```powershell
go get github.com/halalcloud/stellarplayer-resourceauth-go@<approved-version>
go mod tidy
go test ./...
go vet ./...
```

至少重新验证：

- 正确 Issuer、Audience、签名与 Scope 的 Token 可以进入业务 Handler；
- 错误 Issuer、Audience、`kid`、签名和时间 Claim 返回 401；
- 缺少路由 Scope 返回 403；
- JWKS 初始加载失败会阻止受保护服务启动；
- JWKS 轮换和最后可信 Key 保留行为符合预期；
- 日志、追踪、指标和错误响应不包含 Bearer Token。

不要在生产 `go.mod` 中提交指向开发者本机兄弟目录的 `replace`。跨仓库联调可以使用不提交的 Go Workspace；发布构建必须依赖可获取的固定 Tag 或 Commit。

Gateway 主仓库应在独立模块首个 Commit/Tag 可从 GitHub 获取之后再切换 import path。旧路径如需兼容，可以保留一个短期 Deprecated 转发层；该转发层不应复制验证实现。
