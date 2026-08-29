package resourceauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// TokenVerifier is the minimal verification contract used by Authenticator.
// Production Resource Servers should normally use RemoteVerifier; tests may
// provide a deterministic in-memory implementation.
type TokenVerifier interface {
	Verify(string) (AccessTokenClaims, error)
}

// Principal is the identity and authorization state that handlers may trust
// after Authenticate has completed. SubjectID is the Gateway-local stable
// subject from the JWT sub claim; it is not an upstream provider UID.
type Principal struct {
	SubjectID uuid.UUID
	ClientID  string
	Scopes    []string
	TokenID   string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// HasScope reports whether the verified Principal contains scope.
func (principal Principal) HasScope(scope string) bool {
	index := sort.SearchStrings(principal.Scopes, scope)
	return index < len(principal.Scopes) && principal.Scopes[index] == scope
}

type principalContextKey struct{}

// PrincipalFromContext returns a defensive copy of the Principal injected by
// Authenticate. It returns false outside an authenticated middleware chain.
func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(Principal)
	if !ok || principal.SubjectID == uuid.Nil {
		return Principal{}, false
	}
	principal.Scopes = append([]string(nil), principal.Scopes...)
	return principal, true
}

// Authenticator verifies Bearer tokens and injects trusted Principals into HTTP
// request contexts.
type Authenticator struct {
	verifier TokenVerifier
}

// NewAuthenticator creates HTTP authentication middleware for verifier.
func NewAuthenticator(verifier TokenVerifier) (*Authenticator, error) {
	if verifier == nil {
		return nil, errors.New("resource authentication verifier is required")
	}
	return &Authenticator{verifier: verifier}, nil
}

// Authenticate accepts exactly one Authorization: Bearer header, verifies the
// compact JWT, and injects a Principal. Tokens in query strings, cookies, or
// request bodies are deliberately unsupported.
func (authenticator *Authenticator) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		token, ok := bearerToken(request.Header.Values("Authorization"))
		if !ok {
			writeBearerError(writer, http.StatusUnauthorized, "invalid_token", nil)
			return
		}
		claims, err := authenticator.verifier.Verify(token)
		if err != nil {
			writeBearerError(writer, http.StatusUnauthorized, "invalid_token", nil)
			return
		}
		subjectID, err := uuid.Parse(claims.Subject)
		if err != nil || subjectID == uuid.Nil || subjectID.String() != claims.Subject ||
			claims.IssuedAt == nil || claims.Expiry == nil || !validClientID(claims.ClientID) ||
			!validScope(claims.Scope) {
			writeBearerError(writer, http.StatusUnauthorized, "invalid_token", nil)
			return
		}
		scopes := strings.Split(claims.Scope, " ")
		principal := Principal{
			SubjectID: subjectID,
			ClientID:  claims.ClientID,
			Scopes:    append([]string(nil), scopes...),
			TokenID:   claims.ID,
			IssuedAt:  time.Unix(int64(*claims.IssuedAt), 0).UTC(),
			ExpiresAt: time.Unix(int64(*claims.Expiry), 0).UTC(),
		}
		ctx := context.WithValue(request.Context(), principalContextKey{}, principal)
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}

// RequireScopes authorizes a route after Authenticate has injected a
// Principal. All listed scopes are required. Invalid scope configuration
// fails closed without reflecting the invalid value into a response header.
func RequireScopes(required ...string) func(http.Handler) http.Handler {
	required = append([]string(nil), required...)
	sort.Strings(required)
	valid := true
	for index, scope := range required {
		if !validScopeToken(scope) || index > 0 && required[index-1] == scope {
			valid = false
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			principal, ok := PrincipalFromContext(request.Context())
			if !ok {
				writeBearerError(writer, http.StatusUnauthorized, "invalid_token", nil)
				return
			}
			if !valid {
				writeBearerError(writer, http.StatusForbidden, "insufficient_scope", nil)
				return
			}
			for _, scope := range required {
				if !principal.HasScope(scope) {
					writeBearerError(writer, http.StatusForbidden, "insufficient_scope", required)
					return
				}
			}
			next.ServeHTTP(writer, request)
		})
	}
}

func bearerToken(values []string) (string, bool) {
	if len(values) != 1 || values[0] == "" || values[0] != strings.TrimSpace(values[0]) {
		return "", false
	}
	scheme, token, found := strings.Cut(values[0], " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || token == "" ||
		strings.ContainsAny(token, " \t\r\n,") {
		return "", false
	}
	return token, true
}

func writeBearerError(writer http.ResponseWriter, status int, code string, scopes []string) {
	challenge := `Bearer error="` + code + `"`
	if len(scopes) != 0 {
		challenge += `, scope="` + strings.Join(scopes, " ") + `"`
	}
	writer.Header().Set("WWW-Authenticate", challenge)
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]string{"error": code})
}
