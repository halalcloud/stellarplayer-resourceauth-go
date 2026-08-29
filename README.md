# StellarPlayer Resource Auth for Go

`resourceauth` 是 StellarPlayer Gateway 的官方 Go Resource Server SDK。它通过 Authorization Server Metadata 和 JWKS 严格验证 Gateway 签发的短期 ES256 Access Token，并为 `net/http` 提供 Bearer、Scope 和可信 `Principal` 中间件。

本模块不连接 Gateway 数据库，不持有签名私钥，也不处理登录、授权码、Refresh Token、撤销或业务对象授权。

## 快速事实

| 项目 | 约束 |
|---|---|
| Module | `github.com/halalcloud/stellarplayer-resourceauth-go` |
| Package | `resourceauth` |
| 最低语言/依赖版本 | Go 1.24；生产构建应使用仍受支持且已安装安全补丁的 Go 工具链 |
| 推荐验证器 | `RemoteVerifier` |
| Token 传输 | 唯一的 `Authorization: Bearer <token>` Header |
| 公钥来源 | Issuer Metadata 中经过校验的同源 HTTPS `jwks_uri` |
| 路由授权 | `RequireScopes`，列出的 Scope 全部必需 |
| 业务主体 | `PrincipalFromContext` 返回的 Gateway 本地 Subject UUID |

## 安装

生产服务应固定一个经过审核的 Release Tag，不要长期依赖浮动的 `@main`：

```powershell
go get github.com/halalcloud/stellarplayer-resourceauth-go@<approved-version>
```

提交调用方的 `go.mod` 和 `go.sum`。升级本模块时重新运行认证、Scope、401/403、Audience 和密钥轮换测试。

## 最小完整接入

```go
package api

import (
    "context"
    "encoding/json"
    "log/slog"
    "net/http"
    "time"

    resourceauth "github.com/halalcloud/stellarplayer-resourceauth-go"
)

func NewHandler(
    ctx context.Context,
    logger *slog.Logger,
    issuer string,
    audience string,
) (http.Handler, error) {
    verifier, err := resourceauth.NewRemoteVerifier(ctx, resourceauth.RemoteVerifierOptions{
        Issuer:          issuer,
        Audience:        audience,
        MaxTokenTTL:     15 * time.Minute,
        RefreshInterval: 5 * time.Minute,
    })
    if err != nil {
        return nil, err
    }

    authenticator, err := resourceauth.NewAuthenticator(verifier)
    if err != nil {
        return nil, err
    }
    go verifier.Run(ctx, logger)

    router := http.NewServeMux()
    router.HandleFunc("GET /health/live", func(writer http.ResponseWriter, _ *http.Request) {
        writer.WriteHeader(http.StatusNoContent)
    })
    router.Handle(
        "GET /api/profile",
        authenticator.Authenticate(
            resourceauth.RequireScopes("profile.read")(http.HandlerFunc(profile)),
        ),
    )
    return router, nil
}

func profile(writer http.ResponseWriter, request *http.Request) {
    principal, ok := resourceauth.PrincipalFromContext(request.Context())
    if !ok {
        http.Error(writer, "principal missing", http.StatusInternalServerError)
        return
    }
    writer.Header().Set("Content-Type", "application/json; charset=utf-8")
    _ = json.NewEncoder(writer).Encode(map[string]string{
        "subject_id": principal.SubjectID.String(),
        "client_id":  principal.ClientID,
    })
}
```

中间件顺序必须是：

```text
HTTP request
  -> Authenticator.Authenticate
  -> service-owned allowed-client policy (optional but recommended)
  -> resourceauth.RequireScopes
  -> business handler
  -> resourceauth.PrincipalFromContext
```

`RequireScopes("a", "b")` 表示两个 Scope 全部必需。不同路由应分别声明最小 Scope，不要给整组路由统一配置最大权限。

## 公开 API

| API | 用途 |
|---|---|
| `NewRemoteVerifier` | 启动时发现 Metadata、加载 JWKS，并建立严格 Token 验证器 |
| `(*RemoteVerifier).Run` | 在进程生命周期内刷新 JWKS；刷新失败保留最后可信公钥 |
| `NewAuthenticator`、`Authenticate` | 验证唯一 Bearer Header，并把可信 Principal 注入 Context |
| `RequireScopes` | 声明一条路由所需的全部 Scope |
| `PrincipalFromContext`、`Principal.HasScope` | 读取可信主体和已验证 Scope |
| `NewAccessTokenVerifier` | 使用调用方自行安全分发的 P-256 公钥窗口直接验证 |
| `TokenVerifier` | 最小验证接口，主要用于调用方测试替身 |
| `ErrInvalidAccessToken` | 统一的不可信 Token 错误，不向客户端泄露内部失败原因 |

## 信任与业务边界

- 必须配置精确 HTTPS Issuer 和本服务的精确 Audience，不能从未验证 Token 动态推导。
- Metadata 或初始 JWKS 不可用、不可信时，服务启动失败关闭；不得降级成跳过认证。
- 业务代码只能使用 `PrincipalFromContext`，不能再次解析 JWT，也不能信任客户端提交的 `subject_id`、`client_id` 或 Scope。
- `Principal.SubjectID` 是 Gateway 本地稳定 UUID，不是上游数字 UID。业务表可以把它存为 `owner_subject_id UUID`。
- 本模块只验证 Client ID 的结构；每个 Resource Server 仍需拥有自己的 Client allowlist、路由权限和对象归属策略。
- Bearer Token 不得进入 URL、Cookie、请求体、源码、配置、日志、追踪属性、指标标签或错误响应。
- Resource Server 不应持有 Gateway 签名私钥或接收 Refresh Token。

认证失败的固定 HTTP 行为：

| 情况 | HTTP | `WWW-Authenticate` |
|---|---:|---|
| Header 缺失、重复、畸形或 Token 无效 | 401 | `Bearer error="invalid_token"` |
| Token 有效但缺少路由 Scope | 403 | `Bearer error="insufficient_scope", scope="..."` |
| Token 和 Scope 均有效 | 进入业务 Handler | 不设置认证错误 Challenge |

## 文档

- [完整接入与业务授权边界](docs/integration.md)
- [Access Token 与 Metadata/JWKS Profile](docs/token-profile.md)
- [从 Gateway 内置包迁移](docs/migration-from-gateway.md)
- [安全漏洞报告](SECURITY.md)
- [贡献指南](CONTRIBUTING.md)
- [变更记录](CHANGELOG.md)
- [可运行示例](example/basic/main.go)

包级文档也可以通过以下命令读取：

```powershell
go doc -all github.com/halalcloud/stellarplayer-resourceauth-go
```

## 本地验证

```powershell
go test ./...
go vet ./...
```

测试只使用本地 TLS Metadata/JWKS 服务和内存请求，不连接真实 Gateway，不读取账号或 Token。

## 版本与许可证

`v1` 前可能调整公共 API；生产消费者仍应固定具体 Tag。进入 `v1` 后遵循 Semantic Versioning，任何会改变 Token 接受边界或公共 API 的不兼容修改都必须进入新的 Major Version。

本项目使用 [Apache License 2.0](LICENSE)。
