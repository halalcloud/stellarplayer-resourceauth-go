package resourceauth

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	authorizationServerMetadataPath = "/.well-known/oauth-authorization-server"
	defaultJWKSRefreshInterval      = 5 * time.Minute
	maxDiscoveryResponseBytes       = 64 << 10
	maxJWKSResponseBytes            = 64 << 10
)

// RemoteVerifierOptions configures Metadata discovery, JWKS refresh, and the
// exact trust boundary for one Resource Server.
type RemoteVerifierOptions struct {
	Issuer          string           // Exact HTTPS issuer root URL, including the trailing slash.
	Audience        string           // Exact audience assigned to this Resource Server.
	MaxTokenTTL     time.Duration    // Maximum accepted exp minus iat; from one through 15 minutes.
	ClockSkew       time.Duration    // Accepted clock leeway; from zero through one minute.
	RefreshInterval time.Duration    // JWKS refresh period; from one minute through one hour.
	HTTPClient      *http.Client     // Optional client with a positive timeout no greater than 30 seconds.
	Now             func() time.Time // Optional clock function; nil selects time.Now.
}

// RemoteVerifier discovers and periodically loads an Authorization Server's
// public signing keys. Startup fails closed if Metadata or JWKS cannot be
// validated. A later refresh failure retains the last known-good key set.
type RemoteVerifier struct {
	options RemoteVerifierOptions
	client  http.Client
	jwksURL string

	mu       sync.RWMutex
	verifier *AccessTokenVerifier
}

// NewRemoteVerifier loads and validates Authorization Server Metadata and its
// initial JWKS. It fails closed when either document is unavailable or invalid.
func NewRemoteVerifier(ctx context.Context, options RemoteVerifierOptions) (*RemoteVerifier, error) {
	if ctx == nil {
		return nil, errors.New("remote verifier context is required")
	}
	if options.RefreshInterval == 0 {
		options.RefreshInterval = defaultJWKSRefreshInterval
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if !validIssuer(options.Issuer) || !validAudience(options.Audience) ||
		options.MaxTokenTTL < time.Minute || options.MaxTokenTTL > maxAccessTokenTTL ||
		options.ClockSkew < 0 || options.ClockSkew > time.Minute ||
		options.RefreshInterval < time.Minute || options.RefreshInterval > time.Hour {
		return nil, errors.New("remote verifier options are invalid")
	}

	client := http.Client{Timeout: 5 * time.Second}
	if options.HTTPClient != nil {
		client = *options.HTTPClient
	}
	if client.Timeout <= 0 || client.Timeout > 30*time.Second {
		return nil, errors.New("OAuth HTTP client timeout is invalid")
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	remote := &RemoteVerifier{options: options, client: client}
	jwksURL, err := remote.discover(ctx)
	if err != nil {
		return nil, fmt.Errorf("load Authorization Server Metadata: %w", err)
	}
	remote.jwksURL = jwksURL
	if err := remote.refresh(ctx); err != nil {
		return nil, fmt.Errorf("load initial OAuth JWKS: %w", err)
	}
	return remote, nil
}

// Verify authenticates one compact Gateway Access Token against the most
// recent successfully loaded public-key window.
func (remote *RemoteVerifier) Verify(serialized string) (AccessTokenClaims, error) {
	if remote == nil {
		return AccessTokenClaims{}, ErrInvalidAccessToken
	}
	remote.mu.RLock()
	verifier := remote.verifier
	remote.mu.RUnlock()
	if verifier == nil {
		return AccessTokenClaims{}, ErrInvalidAccessToken
	}
	return verifier.Verify(serialized)
}

// Run refreshes the trusted public key window until ctx is cancelled.
func (remote *RemoteVerifier) Run(ctx context.Context, logger *slog.Logger) {
	if remote == nil || ctx == nil {
		return
	}
	ticker := time.NewTicker(remote.options.RefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := remote.refresh(ctx); err != nil && logger != nil {
				logger.WarnContext(ctx, "OAuth JWKS refresh failed; retaining last known-good keys", "error", err)
			}
		}
	}
}

type authorizationServerMetadata struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

func (remote *RemoteVerifier) discover(ctx context.Context) (string, error) {
	contents, err := remote.getJSON(
		ctx, remote.options.Issuer+authorizationServerMetadataPath[1:],
		maxDiscoveryResponseBytes, "Authorization Server Metadata", "application/json",
	)
	if err != nil {
		return "", err
	}
	var metadata authorizationServerMetadata
	if err := json.Unmarshal(contents, &metadata); err != nil {
		return "", errors.New("decode Authorization Server Metadata")
	}
	if metadata.Issuer != remote.options.Issuer || !validJWKSURL(remote.options.Issuer, metadata.JWKSURI) {
		return "", errors.New("Authorization Server Metadata is invalid")
	}
	return metadata.JWKSURI, nil
}

func (remote *RemoteVerifier) refresh(ctx context.Context) error {
	contents, err := remote.getJSON(
		ctx, remote.jwksURL, maxJWKSResponseBytes, "OAuth JWKS",
		"application/json", "application/jwk-set+json",
	)
	if err != nil {
		return err
	}

	var keySet jose.JSONWebKeySet
	if err := json.Unmarshal(contents, &keySet); err != nil ||
		len(keySet.Keys) == 0 || len(keySet.Keys) > maxPublishedSigningKeys {
		return errors.New("decode OAuth JWKS")
	}
	publicKeys := make(map[string]*ecdsa.PublicKey, len(keySet.Keys))
	for _, key := range keySet.Keys {
		publicKey, ok := key.Key.(*ecdsa.PublicKey)
		if !ok || key.KeyID == "" || key.Use != "sig" || key.Algorithm != string(jose.ES256) {
			return errors.New("OAuth JWKS contains an unsupported key")
		}
		keyID, err := es256KeyID(publicKey)
		if err != nil || keyID != key.KeyID {
			return errors.New("OAuth JWKS key ID is invalid")
		}
		if _, duplicate := publicKeys[keyID]; duplicate {
			return errors.New("OAuth JWKS contains a duplicate key")
		}
		publicKeys[keyID] = publicKey
	}
	verifier, err := NewAccessTokenVerifier(AccessTokenVerifierOptions{
		Issuer: remote.options.Issuer, Audience: remote.options.Audience,
		PublicKeys: publicKeys, MaxTTL: remote.options.MaxTokenTTL,
		ClockSkew: remote.options.ClockSkew, Now: remote.options.Now,
	})
	if err != nil {
		return errors.New("construct Access Token verifier")
	}
	remote.mu.Lock()
	remote.verifier = verifier
	remote.mu.Unlock()
	return nil
}

func (remote *RemoteVerifier) getJSON(
	ctx context.Context,
	endpoint string,
	limit int64,
	label string,
	acceptedMediaTypes ...string,
) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create %s request", label)
	}
	request.Header.Set("Accept", strings.Join(acceptedMediaTypes, ", "))
	response, err := remote.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("request %s", label)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned HTTP %d", label, response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || !contains(acceptedMediaTypes, mediaType) {
		return nil, fmt.Errorf("%s content type is invalid", label)
	}
	if response.ContentLength > limit {
		return nil, fmt.Errorf("%s response is too large", label)
	}
	contents, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s", label)
	}
	if len(contents) == 0 || int64(len(contents)) > limit {
		return nil, fmt.Errorf("%s response is invalid", label)
	}
	return contents, nil
}

func validJWKSURL(issuer string, value string) bool {
	issuerURL, issuerErr := url.Parse(issuer)
	jwksURL, jwksErr := url.Parse(value)
	return issuerErr == nil && jwksErr == nil && jwksURL.IsAbs() &&
		jwksURL.Scheme == "https" && strings.EqualFold(jwksURL.Host, issuerURL.Host) &&
		jwksURL.Path != "" && jwksURL.User == nil && jwksURL.Opaque == "" &&
		jwksURL.RawQuery == "" && !jwksURL.ForceQuery && jwksURL.Fragment == ""
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
