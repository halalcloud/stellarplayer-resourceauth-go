// Package resourceauth authenticates HTTP requests to Resource Servers using
// Access Tokens issued by StellarPlayer Gateway.
//
// Most Resource Servers should create a RemoteVerifier with their exact HTTPS
// issuer, exact audience, and maximum accepted token lifetime; wrap it in an
// Authenticator; run the verifier's refresh loop for the process lifetime; and
// apply Authenticate outside RequireScopes on every protected route:
//
//	authenticator.Authenticate(
//		resourceauth.RequireScopes("profile.read")(handler),
//	)
//
// After both middleware layers succeed, handlers obtain the verified local
// subject with PrincipalFromContext. Principal.SubjectID is a Gateway-local
// UUID and is not an upstream provider UID.
//
// The package deliberately excludes token issuance, browser login, grants,
// refresh tokens, signing private keys, and application-specific authorization
// policy. The canonical integration guide is the repository README.
package resourceauth
