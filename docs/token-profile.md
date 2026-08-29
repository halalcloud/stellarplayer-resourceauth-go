# Access Token 与发现 Profile

本模块验证 StellarPlayer Gateway 的受限 Access Token Profile。它不是一个允许调用方自行放宽算法或 Claim 的通用 JWT 验证器。

## JOSE Header

| 字段 | 要求 |
|---|---|
| `alg` | 精确为 `ES256` |
| `typ` | 精确为 `at+jwt` |
| `kid` | P-256 公钥 RFC 7638 SHA-256 JWK Thumbprint |

Token 必须是单签名 Compact JWS，最大 8 KiB。验证器不会接受 Token 自报的其他算法。

## Claims

| Claim | 要求 |
|---|---|
| `iss` | 与配置的精确 HTTPS Issuer 完全一致 |
| `sub` | 规范、非零 Gateway 本地 UUID |
| `aud` | 1 至 8 个严格递增、无重复值，并包含本服务精确 Audience |
| `client_id` | 1 至 128 字节可见 ASCII |
| `scope` | 非空、最多 1024 字节、严格排序且无重复 Scope Token |
| `iat` | 必需，且通过时间校验 |
| `exp` | 必需，晚于 `iat`，生命周期不得超过配置的 `MaxTokenTTL` |
| `jti` | 严格 Base64url 编码的 32 字节随机值 |
| `nbf` | 不允许 |

`Principal.SubjectID` 来自完成全部验证后的 `sub`。JWT 是签名而非加密格式，持有 Token 的一方可以读取 Payload；业务服务仍只能信任完成验签后的 Principal。

## Authorization Server Metadata

`RemoteVerifier` 从精确 Issuer 根 URL读取：

```text
/.well-known/oauth-authorization-server
```

Metadata 必须返回完全相同的 `issuer`，且 `jwks_uri` 必须满足：

- 绝对 HTTPS URL；
- 与 Issuer 同源；
- 具有非空 Path；
- 不包含 userinfo、query 或 fragment；
- Metadata 和 JWKS 请求均不允许重定向。

Metadata/JWKS 响应最大 64 KiB，并校验 HTTP 200 与媒体类型。JWKS 必须包含 1 至 5 把 P-256 ES256 签名公钥；每把 Key 的 `kid` 必须和重新计算的 RFC 7638 Thumbprint 一致，重复或不支持的 Key 会使刷新失败。

## 启动和轮换行为

首次 Metadata 或 JWKS 加载失败会使 `NewRemoteVerifier` 返回错误，Resource Server 应因此拒绝启动受保护路由。初始化成功后，`Run` 定期刷新 JWKS；后续刷新失败不会清空最后一组可信 Key。

签发端应先把新公钥加入 JWKS，等待缓存和刷新窗口，再切换签名 Key；旧公钥至少保留到旧 Access Token 最大生命周期和刷新余量结束。

## 错误收敛

所有不可信、畸形或验证失败的 Token 对包调用方统一返回 `ErrInvalidAccessToken`。HTTP 中间件统一输出 `401 invalid_token`，不会向客户端泄露签名、Claim、Key 或时间校验的内部原因。
