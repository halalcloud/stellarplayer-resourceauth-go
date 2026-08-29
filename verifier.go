package resourceauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
)

const (
	accessTokenType         = "at+jwt"
	accessTokenJTIBytes     = 32
	maxAccessTokenBytes     = 8 << 10
	maxAccessTokenTTL       = 15 * time.Minute
	maxPublishedSigningKeys = 5
	maxAccessTokenAudiences = 8
	maxScopeBytes           = 1024
	maxClientIDBytes        = 128
)

// ErrInvalidAccessToken is returned for every untrusted or malformed Access
// Token. Callers must not use verification errors to disclose token details.
var ErrInvalidAccessToken = errors.New("invalid access token")

// AccessTokenClaims is the restricted RFC 9068 claim set emitted by the
// Gateway. Callers should use a verified Principal in HTTP handlers instead
// of parsing or trusting this type directly.
type AccessTokenClaims struct {
	jwt.Claims
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"`
}

// AccessTokenVerifierOptions configures direct verification with an already
// trusted public-key window. Most external services should use RemoteVerifier.
type AccessTokenVerifierOptions struct {
	Issuer     string                      // Exact HTTPS issuer URL, including the trailing slash.
	Audience   string                      // Exact audience assigned to this Resource Server.
	PublicKeys map[string]*ecdsa.PublicKey // Trusted P-256 keys indexed by their JWK Thumbprint kid.
	MaxTTL     time.Duration               // Maximum accepted exp minus iat; at most 15 minutes.
	ClockSkew  time.Duration               // Accepted clock leeway; from zero through one minute.
	Now        func() time.Time            // Required clock function; use time.Now in production.
}

// AccessTokenVerifier enforces the algorithm, protected header, issuer,
// audience, temporal bounds, and the Gateway token profile. It validates
// client IDs and scopes structurally; each Resource Server owns its client
// and route-scope authorization policy.
type AccessTokenVerifier struct {
	options AccessTokenVerifierOptions
}

// NewAccessTokenVerifier constructs a strict verifier from an already trusted
// P-256 public-key window.
func NewAccessTokenVerifier(options AccessTokenVerifierOptions) (*AccessTokenVerifier, error) {
	if !validIssuer(options.Issuer) || !validAudience(options.Audience) || options.MaxTTL <= 0 ||
		options.MaxTTL > maxAccessTokenTTL || options.ClockSkew < 0 ||
		options.ClockSkew > time.Minute || options.Now == nil || len(options.PublicKeys) == 0 ||
		len(options.PublicKeys) > maxPublishedSigningKeys {
		return nil, errors.New("access token verifier options are invalid")
	}
	keys := make(map[string]*ecdsa.PublicKey, len(options.PublicKeys))
	for keyID, publicKey := range options.PublicKeys {
		derivedKeyID, err := es256KeyID(publicKey)
		if err != nil || keyID != derivedKeyID {
			return nil, errors.New("access token verifier key is invalid")
		}
		keys[keyID] = cloneP256PublicKey(publicKey)
	}
	options.PublicKeys = keys
	return &AccessTokenVerifier{options: options}, nil
}

// Verify authenticates one compact Gateway Access Token and returns its
// restricted claims. HTTP handlers should normally consume Principal after the
// Authenticate middleware instead of calling Verify directly.
func (verifier *AccessTokenVerifier) Verify(serialized string) (AccessTokenClaims, error) {
	if verifier == nil || serialized == "" || len(serialized) > maxAccessTokenBytes ||
		strings.Count(serialized, ".") != 2 {
		return AccessTokenClaims{}, ErrInvalidAccessToken
	}
	token, err := jwt.ParseSigned(serialized, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil || len(token.Headers) != 1 {
		return AccessTokenClaims{}, ErrInvalidAccessToken
	}
	header := token.Headers[0]
	typ, typeOK := header.ExtraHeaders[jose.HeaderKey(jose.HeaderType)].(string)
	publicKey, keyOK := verifier.options.PublicKeys[header.KeyID]
	if header.Algorithm != string(jose.ES256) || !typeOK || typ != accessTokenType || !keyOK {
		return AccessTokenClaims{}, ErrInvalidAccessToken
	}

	var claims AccessTokenClaims
	if err := token.Claims(publicKey, &claims); err != nil {
		return AccessTokenClaims{}, ErrInvalidAccessToken
	}
	now := verifier.options.Now().UTC()
	if err := claims.ValidateWithLeeway(jwt.Expected{
		Issuer: verifier.options.Issuer, AnyAudience: jwt.Audience{verifier.options.Audience}, Time: now,
	}, verifier.options.ClockSkew); err != nil {
		return AccessTokenClaims{}, ErrInvalidAccessToken
	}
	if !validAudiences(claims.Audience, verifier.options.Audience) ||
		claims.Expiry == nil || claims.IssuedAt == nil || claims.NotBefore != nil ||
		claims.Subject == "" || !validClientID(claims.ClientID) || !validScope(claims.Scope) ||
		!validJTI(claims.ID) {
		return AccessTokenClaims{}, ErrInvalidAccessToken
	}
	subjectID, err := uuid.Parse(claims.Subject)
	if err != nil || subjectID == uuid.Nil || subjectID.String() != claims.Subject {
		return AccessTokenClaims{}, ErrInvalidAccessToken
	}
	issuedAt := time.Unix(int64(*claims.IssuedAt), 0)
	expiresAt := time.Unix(int64(*claims.Expiry), 0)
	if !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > verifier.options.MaxTTL {
		return AccessTokenClaims{}, ErrInvalidAccessToken
	}
	return claims, nil
}

func validAudiences(audiences jwt.Audience, expected string) bool {
	if len(audiences) == 0 || len(audiences) > maxAccessTokenAudiences {
		return false
	}
	found := false
	for index, audience := range audiences {
		if !validAudience(audience) || (index > 0 && audiences[index-1] >= audience) {
			return false
		}
		found = found || audience == expected
	}
	return found
}

func validAudience(value string) bool {
	return value != "" && value == strings.TrimSpace(value)
}

func es256KeyID(publicKey *ecdsa.PublicKey) (string, error) {
	if !validP256PublicKey(publicKey) {
		return "", errors.New("ES256 public key is invalid")
	}
	thumbprint, err := (&jose.JSONWebKey{Key: publicKey}).Thumbprint(crypto.SHA256)
	if err != nil {
		return "", errors.New("derive ES256 key ID")
	}
	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
}

func validIssuer(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || !strings.HasSuffix(value, "/") {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.Path == "/" &&
		parsed.User == nil && parsed.Opaque == "" && parsed.RawQuery == "" &&
		!parsed.ForceQuery && parsed.Fragment == ""
}

func validP256PublicKey(publicKey *ecdsa.PublicKey) bool {
	return publicKey != nil && publicKey.Curve == elliptic.P256() &&
		publicKey.X != nil && publicKey.Y != nil && publicKey.Curve.IsOnCurve(publicKey.X, publicKey.Y)
}

func cloneP256PublicKey(publicKey *ecdsa.PublicKey) *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(), X: new(big.Int).Set(publicKey.X), Y: new(big.Int).Set(publicKey.Y),
	}
}

func validClientID(value string) bool {
	if value == "" || len(value) > maxClientIDBytes {
		return false
	}
	for index := range len(value) {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func validScope(value string) bool {
	if value == "" || len(value) > maxScopeBytes || value != strings.TrimSpace(value) {
		return false
	}
	scopes := strings.Split(value, " ")
	for index, scope := range scopes {
		if !validScopeToken(scope) || index > 0 && scopes[index-1] >= scope {
			return false
		}
	}
	return true
}

func validScopeToken(value string) bool {
	if value == "" {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if character != 0x21 && (character < 0x23 || character > 0x5b) &&
			(character < 0x5d || character > 0x7e) {
			return false
		}
	}
	return true
}

func validJTI(value string) bool {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) == accessTokenJTIBytes
}
