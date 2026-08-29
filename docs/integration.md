# Resource Server 接入与业务授权

本文描述业务 API 如何使用 `resourceauth`，以及本模块刻意不负责的授权边界。

## 运行时依赖

Resource Server 不连接 Gateway 数据库。启动时它通过 HTTPS 读取 Authorization Server Metadata 和 JWKS；成功加载后，每个请求都在本地完成 JWT 验证。运行期间刷新失败会保留最后一组已经验证的公钥。

```text
client -- Authorization: Bearer <access token> --> Resource Server
                                                   |
                                                   +-- local signature/claim validation
                                                   +-- route Scope validation
                                                   +-- service-owned Client policy
                                                   +-- service-owned object authorization

Resource Server -- startup/periodic HTTPS --> Issuer Metadata and JWKS
```

## 初始化

生产服务优先使用 `NewRemoteVerifier`：

```go
verifier, err := resourceauth.NewRemoteVerifier(ctx, resourceauth.RemoteVerifierOptions{
    Issuer:          "https://issuer.example/",
    Audience:        "https://api.example/",
    MaxTokenTTL:     15 * time.Minute,
    ClockSkew:       30 * time.Second,
    RefreshInterval: 5 * time.Minute,
})
if err != nil {
    return err
}
authenticator, err := resourceauth.NewAuthenticator(verifier)
if err != nil {
    return err
}
go verifier.Run(ctx, logger)
```

配置约束：

| 字段 | 约束 |
|---|---|
| `Issuer` | 精确 HTTPS 根 URL，包含尾随 `/`，不能含 userinfo、query 或 fragment |
| `Audience` | 本 Resource Server 的精确 Audience，不能含首尾空白 |
| `MaxTokenTTL` | 1 至 15 分钟，并与签发端策略一致或更严格 |
| `ClockSkew` | 0 至 1 分钟；只容忍有限时钟偏差，不延长 Token 生命周期 |
| `RefreshInterval` | 1 分钟至 1 小时；零值默认 5 分钟 |
| `HTTPClient` | 可选；Timeout 必须大于 0 且不超过 30 秒 |
| `Now` | 生产保持 nil；只在确定性测试中注入 |

## 路由中间件

认证必须位于 Scope 检查外层：

```go
router.Handle(
    "GET /api/library",
    authenticator.Authenticate(
        resourceauth.RequireScopes("library.read")(handler),
    ),
)
```

使用 chi 等支持中间件链的路由器时，保持相同执行顺序：

```go
router.With(
    authenticator.Authenticate,
    requireAllowedClient(allowedClients),
    resourceauth.RequireScopes("library.read"),
).Get("/api/library", handler)
```

`resourceauth` 不决定哪些 Client 可以访问某个业务 API。服务应在认证后根据 `Principal.ClientID` 执行自己的静态或动态 allowlist；不能根据未验证的请求参数判断 Client。

## 业务主体

业务 Handler 只使用认证中间件注入的 Principal：

```go
principal, ok := resourceauth.PrincipalFromContext(request.Context())
if !ok {
    return errors.New("authenticated principal missing")
}
ownerSubjectID := principal.SubjectID
```

`SubjectID` 是 Issuer 身份域内的稳定本地 UUID。单 Issuer 业务库可以直接存 `owner_subject_id UUID`；同时接受多个 Issuer 时使用 `(issuer, subject_id)` 复合身份。不要把 `ClientID` 或 `TokenID` 当作用户身份，也不要尝试从 Subject UUID 推导上游账号 UID。

Scope 只表示能力类别，不替代对象级授权。数据库查询应同时约束资源 ID 和 `owner_subject_id`：

```sql
SELECT *
FROM favorites
WHERE id = $1
  AND owner_subject_id = $2;
```

## Token 生命周期

Access Token 是短期、自包含 JWT。Resource Server 不接收 Refresh Token，也不在每个请求上查询 Gateway。撤销 Refresh Token 不会立刻撤销已经签发的 Access Token；需要即时冻结的高风险业务应额外接入服务自有封禁状态、受信任的安全状态服务或未来的 Token Introspection。

## 调用方测试清单

- 缺少、重复、非 Bearer 或畸形 Authorization Header 返回 401。
- 错误 issuer、audience、签名、`kid`、过期时间和超长 TTL 全部被拒绝。
- Token 有效但缺 Scope 返回 403；全部 Scope 存在才进入 Handler。
- 未允许的 Client 返回业务定义的 403。
- Handler 只使用 `PrincipalFromContext`，不接受客户端提交的 Subject。
- Metadata/JWKS 启动失败时服务失败关闭。
- JWKS 刷新失败保留最后可信 Key，恢复后接受轮换窗口中的新 Key。
- 日志、错误、追踪和指标不包含原始 Bearer Token。
