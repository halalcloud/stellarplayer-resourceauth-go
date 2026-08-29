package resourceauth

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
)

func TestRemoteVerifierDiscoversJWKSAndVerifiesToken(t *testing.T) {
	privateKey := newResourceSigningKey(t)
	keyID := mustResourceKeyID(t, &privateKey.PublicKey)
	server := newResourceAuthorizationServer(t, privateKey, nil)
	now := time.Date(2026, 8, 11, 8, 0, 0, 0, time.UTC)
	client := server.Client()
	client.Timeout = 2 * time.Second
	verifier, err := NewRemoteVerifier(context.Background(), RemoteVerifierOptions{
		Issuer: server.URL + "/", Audience: testAudience,
		MaxTokenTTL: 10 * time.Minute, RefreshInterval: 5 * time.Minute,
		HTTPClient: client, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewRemoteVerifier() error = %v", err)
	}
	claims := validResourceClaims(
		now, uuid.New(), server.URL+"/", testAudience, "resource-client", "library.read",
	)
	serialized := signResourceClaims(t, jose.ES256, privateKey, keyID, accessTokenType, claims)
	verified, err := verifier.Verify(serialized)
	if err != nil || verified.Subject != claims.Subject {
		t.Fatalf("Verify() claims = %#v, error = %v", verified, err)
	}
}

func TestRemoteVerifierRetainsLastKnownGoodKeysAfterRefreshFailure(t *testing.T) {
	privateKey := newResourceSigningKey(t)
	keyID := mustResourceKeyID(t, &privateKey.PublicKey)
	var invalid atomic.Bool
	server := newResourceAuthorizationServer(t, privateKey, &invalid)
	now := time.Date(2026, 8, 11, 8, 0, 0, 0, time.UTC)
	client := server.Client()
	client.Timeout = 2 * time.Second
	verifier, err := NewRemoteVerifier(context.Background(), RemoteVerifierOptions{
		Issuer: server.URL + "/", Audience: testAudience,
		MaxTokenTTL: 10 * time.Minute, RefreshInterval: 5 * time.Minute,
		HTTPClient: client, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewRemoteVerifier() error = %v", err)
	}
	claims := validResourceClaims(now, uuid.New(), server.URL+"/", testAudience, "client-a", "library.read")
	serialized := signResourceClaims(t, jose.ES256, privateKey, keyID, accessTokenType, claims)

	invalid.Store(true)
	if err := verifier.refresh(context.Background()); err == nil {
		t.Fatal("refresh() accepted an empty JWKS")
	}
	if _, err := verifier.Verify(serialized); err != nil {
		t.Fatalf("Verify() after failed refresh error = %v", err)
	}
}

func TestRemoteVerifierRejectsUntrustedMetadata(t *testing.T) {
	tests := []struct {
		name     string
		metadata func(string) authorizationServerMetadata
	}{
		{
			name: "issuer mismatch",
			metadata: func(serverURL string) authorizationServerMetadata {
				return authorizationServerMetadata{Issuer: "https://other.example/", JWKSURI: serverURL + "/keys"}
			},
		},
		{
			name: "cross origin JWKS",
			metadata: func(serverURL string) authorizationServerMetadata {
				return authorizationServerMetadata{Issuer: serverURL + "/", JWKSURI: "https://other.example/keys"}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var server *httptest.Server
			server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.URL.Path != authorizationServerMetadataPath {
					http.NotFound(writer, request)
					return
				}
				writer.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(writer).Encode(test.metadata(server.URL))
			}))
			t.Cleanup(server.Close)
			client := server.Client()
			client.Timeout = 2 * time.Second
			if _, err := NewRemoteVerifier(context.Background(), RemoteVerifierOptions{
				Issuer: server.URL + "/", Audience: testAudience,
				MaxTokenTTL: 10 * time.Minute, RefreshInterval: 5 * time.Minute,
				HTTPClient: client,
			}); err == nil {
				t.Fatal("NewRemoteVerifier() accepted untrusted Metadata")
			}
		})
	}
}

func TestRemoteVerifierRejectsMetadataRedirect(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, "/redirected", http.StatusFound)
	}))
	t.Cleanup(server.Close)
	client := server.Client()
	client.Timeout = 2 * time.Second
	if _, err := NewRemoteVerifier(context.Background(), RemoteVerifierOptions{
		Issuer: server.URL + "/", Audience: testAudience,
		MaxTokenTTL: 10 * time.Minute, RefreshInterval: 5 * time.Minute,
		HTTPClient: client,
	}); err == nil {
		t.Fatal("NewRemoteVerifier() followed a Metadata redirect")
	}
}

func newResourceAuthorizationServer(
	t *testing.T,
	privateKey *ecdsa.PrivateKey,
	invalid *atomic.Bool,
) *httptest.Server {
	t.Helper()
	keyID := mustResourceKeyID(t, &privateKey.PublicKey)
	var server *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc(authorizationServerMetadataPath, func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(writer).Encode(authorizationServerMetadata{
			Issuer: server.URL + "/", JWKSURI: server.URL + "/keys",
		})
	})
	mux.HandleFunc("/keys", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/jwk-set+json")
		if invalid != nil && invalid.Load() {
			_, _ = writer.Write([]byte(`{"keys":[]}`))
			return
		}
		_ = json.NewEncoder(writer).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: &privateKey.PublicKey, KeyID: keyID, Algorithm: string(jose.ES256), Use: "sig",
		}}})
	})
	server = httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	return server
}
