package resourceauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
)

type fixedVerifier struct {
	claims AccessTokenClaims
	err    error
}

func (verifier fixedVerifier) Verify(string) (AccessTokenClaims, error) {
	return verifier.claims, verifier.err
}

func TestAuthenticateInjectsVerifiedPrincipal(t *testing.T) {
	now := time.Date(2026, 8, 11, 8, 0, 0, 0, time.UTC)
	subjectID := uuid.New()
	authenticator, err := NewAuthenticator(fixedVerifier{claims: middlewareClaims(subjectID, "library.read", now)})
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}
	handler := authenticator.Authenticate(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		principal, ok := PrincipalFromContext(request.Context())
		if !ok || principal.SubjectID != subjectID || principal.ClientID != "resource-client" ||
			!principal.HasScope("library.read") || principal.TokenID != "token-id" ||
			!principal.IssuedAt.Equal(now) || !principal.ExpiresAt.Equal(now.Add(10*time.Minute)) {
			t.Fatalf("PrincipalFromContext() = %#v, %t", principal, ok)
		}
		principal.Scopes[0] = "mutated"
		second, ok := PrincipalFromContext(request.Context())
		if !ok || !second.HasScope("library.read") {
			t.Fatalf("PrincipalFromContext() exposed mutable scope state: %#v", second)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "/resource", nil)
	request.Header.Set("Authorization", "bearer compact.jwt.value")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("authenticated response = %d", response.Code)
	}
}

func TestAuthenticateRejectsInvalidBearerBoundaries(t *testing.T) {
	now := time.Date(2026, 8, 11, 8, 0, 0, 0, time.UTC)
	valid := fixedVerifier{claims: middlewareClaims(uuid.New(), "library.read", now)}
	invalid := fixedVerifier{err: ErrInvalidAccessToken}
	tests := []struct {
		name     string
		values   []string
		verifier TokenVerifier
	}{
		{name: "missing", verifier: valid},
		{name: "empty", values: []string{""}, verifier: valid},
		{name: "basic", values: []string{"Basic abc"}, verifier: valid},
		{name: "extra whitespace", values: []string{"Bearer  abc"}, verifier: valid},
		{name: "comma joined", values: []string{"Bearer abc,Bearer def"}, verifier: valid},
		{name: "duplicate", values: []string{"Bearer abc", "Bearer def"}, verifier: valid},
		{name: "failed verification", values: []string{"Bearer compact.jwt.value"}, verifier: invalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authenticator, err := NewAuthenticator(test.verifier)
			if err != nil {
				t.Fatalf("NewAuthenticator() error = %v", err)
			}
			called := false
			handler := authenticator.Authenticate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				called = true
			}))
			request := httptest.NewRequest(http.MethodGet, "/resource", nil)
			request.Header["Authorization"] = test.values
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if called || response.Code != http.StatusUnauthorized ||
				response.Header().Get("WWW-Authenticate") != `Bearer error="invalid_token"` {
				t.Fatalf("invalid Bearer response = %d %#v, called=%t", response.Code, response.Header(), called)
			}
		})
	}
}

func TestRequireScopesAllowsAllAndRejectsMissing(t *testing.T) {
	now := time.Date(2026, 8, 11, 8, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		tokenScope string
		wantStatus int
	}{
		{name: "all present", tokenScope: "library.read library.write", wantStatus: http.StatusNoContent},
		{name: "missing write", tokenScope: "library.read", wantStatus: http.StatusForbidden},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authenticator, err := NewAuthenticator(fixedVerifier{claims: middlewareClaims(uuid.New(), test.tokenScope, now)})
			if err != nil {
				t.Fatalf("NewAuthenticator() error = %v", err)
			}
			handler := authenticator.Authenticate(RequireScopes(
				"library.read", "library.write",
			)(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(http.StatusNoContent)
			})))
			request := httptest.NewRequest(http.MethodGet, "/resource", nil)
			request.Header.Set("Authorization", "Bearer compact.jwt.value")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("scope response = %d, want %d", response.Code, test.wantStatus)
			}
			if test.wantStatus == http.StatusForbidden &&
				response.Header().Get("WWW-Authenticate") != `Bearer error="insufficient_scope", scope="library.read library.write"` {
				t.Fatalf("scope challenge = %q", response.Header().Get("WWW-Authenticate"))
			}
		})
	}
}

func TestRequireScopesDoesNotReflectInvalidConfiguration(t *testing.T) {
	now := time.Date(2026, 8, 11, 8, 0, 0, 0, time.UTC)
	authenticator, err := NewAuthenticator(fixedVerifier{claims: middlewareClaims(uuid.New(), "library.read", now)})
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}
	handler := authenticator.Authenticate(RequireScopes("bad\"scope")(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("handler called with invalid scope configuration")
		}),
	))
	request := httptest.NewRequest(http.MethodGet, "/resource", nil)
	request.Header.Set("Authorization", "Bearer compact.jwt.value")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden ||
		response.Header().Get("WWW-Authenticate") != `Bearer error="insufficient_scope"` {
		t.Fatalf("invalid scope configuration response = %d %#v", response.Code, response.Header())
	}
}

func TestNewAuthenticatorRequiresVerifier(t *testing.T) {
	if _, err := NewAuthenticator(nil); err == nil {
		t.Fatal("NewAuthenticator(nil) succeeded")
	}
}

func middlewareClaims(subjectID uuid.UUID, scope string, now time.Time) AccessTokenClaims {
	return AccessTokenClaims{
		Claims: jwt.Claims{
			Subject: subjectID.String(), ID: "token-id",
			IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(10 * time.Minute)),
		},
		ClientID: "resource-client", Scope: scope,
	}
}
