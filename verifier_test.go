package resourceauth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
)

const (
	testIssuer   = "https://issuer.example/"
	testAudience = "https://resource.example/"
)

func TestAccessTokenVerifierAcceptsStructurallyValidClientAndScopes(t *testing.T) {
	now := time.Date(2026, 8, 11, 8, 0, 0, 0, time.UTC)
	privateKey := newResourceSigningKey(t)
	verifier := newResourceVerifier(t, privateKey, now, testIssuer, testAudience)
	subjectID := uuid.New()
	claims := validResourceClaims(
		now, subjectID, testIssuer, testAudience, "another-public-client", "library.read profile.read",
	)
	serialized := signResourceClaims(t, jose.ES256, privateKey, mustResourceKeyID(t, &privateKey.PublicKey), accessTokenType, claims)

	verified, err := verifier.Verify(serialized)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if verified.Subject != subjectID.String() || verified.ClientID != "another-public-client" ||
		verified.Scope != "library.read profile.read" {
		t.Fatalf("Verify() claims = %#v", verified)
	}
}

func TestAccessTokenVerifierAcceptsItsAudienceFromCanonicalAudienceSet(t *testing.T) {
	now := time.Date(2026, 8, 12, 8, 0, 0, 0, time.UTC)
	privateKey := newResourceSigningKey(t)
	secondAudience := "https://user-resource.example/"
	verifier := newResourceVerifier(t, privateKey, now, testIssuer, secondAudience)
	claims := validResourceClaims(
		now, uuid.New(), testIssuer, testAudience, "client-a", "profile.read",
	)
	claims.Audience = jwt.Audience{testAudience, secondAudience}
	serialized := signResourceClaims(
		t, jose.ES256, privateKey, mustResourceKeyID(t, &privateKey.PublicKey), accessTokenType, claims,
	)
	if _, err := verifier.Verify(serialized); err != nil {
		t.Fatalf("Verify() rejected canonical multi-audience token: %v", err)
	}

	for name, audiences := range map[string]jwt.Audience{
		"missing expected": {testAudience},
		"duplicate":        {secondAudience, secondAudience},
		"unsorted":         {secondAudience, testAudience},
		"invalid":          {testAudience, " audience-with-leading-space"},
	} {
		t.Run(name, func(t *testing.T) {
			claims.Audience = audiences
			serialized := signResourceClaims(
				t, jose.ES256, privateKey, mustResourceKeyID(t, &privateKey.PublicKey), accessTokenType, claims,
			)
			if _, err := verifier.Verify(serialized); !errors.Is(err, ErrInvalidAccessToken) {
				t.Fatalf("Verify() error = %v, want ErrInvalidAccessToken", err)
			}
		})
	}
}

func TestAccessTokenVerifierRejectsInvalidTrustAndProfileBoundaries(t *testing.T) {
	now := time.Date(2026, 8, 11, 8, 0, 0, 0, time.UTC)
	privateKey := newResourceSigningKey(t)
	keyID := mustResourceKeyID(t, &privateKey.PublicKey)
	verifier := newResourceVerifier(t, privateKey, now, testIssuer, testAudience)
	subjectID := uuid.New()
	validClaims := validResourceClaims(now, subjectID, testIssuer, testAudience, "client-a", "library.read")
	valid := signResourceClaims(t, jose.ES256, privateKey, keyID, accessTokenType, validClaims)

	wrongIssuer := validResourceClaims(now, subjectID, "https://other.example/", testAudience, "client-a", "library.read")
	wrongAudience := validResourceClaims(now, subjectID, testIssuer, "https://other.example/", "client-a", "library.read")
	expired := validResourceClaims(now.Add(-11*time.Minute), subjectID, testIssuer, testAudience, "client-a", "library.read")
	badClient := validResourceClaims(now, subjectID, testIssuer, testAudience, "client with space", "library.read")
	badScope := validResourceClaims(now, subjectID, testIssuer, testAudience, "client-a", "profile.read library.read")
	untrustedKey := newResourceSigningKey(t)
	tamperAt := len(valid) - 10
	tampered := valid[:tamperAt] + alternateResourceBase64Character(valid[tamperAt]) + valid[tamperAt+1:]

	tests := map[string]string{
		"wrong issuer":    signResourceClaims(t, jose.ES256, privateKey, keyID, accessTokenType, wrongIssuer),
		"wrong audience":  signResourceClaims(t, jose.ES256, privateKey, keyID, accessTokenType, wrongAudience),
		"expired":         signResourceClaims(t, jose.ES256, privateKey, keyID, accessTokenType, expired),
		"invalid client":  signResourceClaims(t, jose.ES256, privateKey, keyID, accessTokenType, badClient),
		"unsorted scope":  signResourceClaims(t, jose.ES256, privateKey, keyID, accessTokenType, badScope),
		"wrong type":      signResourceClaims(t, jose.ES256, privateKey, keyID, "JWT", validClaims),
		"wrong algorithm": signResourceClaims(t, jose.HS256, bytes.Repeat([]byte{0x42}, 32), keyID, accessTokenType, validClaims),
		"unknown key":     signResourceClaims(t, jose.ES256, untrustedKey, mustResourceKeyID(t, &untrustedKey.PublicKey), accessTokenType, validClaims),
		"tampered":        tampered,
	}
	for name, serialized := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := verifier.Verify(serialized); !errors.Is(err, ErrInvalidAccessToken) {
				t.Fatalf("Verify() error = %v, want ErrInvalidAccessToken", err)
			}
		})
	}
}

func TestNewAccessTokenVerifierRequiresThumbprintKeyIDsAndBoundedKeyset(t *testing.T) {
	privateKey := newResourceSigningKey(t)
	if _, err := NewAccessTokenVerifier(AccessTokenVerifierOptions{
		Issuer: testIssuer, Audience: testAudience,
		PublicKeys: map[string]*ecdsa.PublicKey{"operator-selected-kid": &privateKey.PublicKey},
		MaxTTL:     10 * time.Minute, Now: time.Now,
	}); err == nil {
		t.Fatal("NewAccessTokenVerifier() accepted a non-thumbprint key ID")
	}

	tooMany := make(map[string]*ecdsa.PublicKey, maxPublishedSigningKeys+1)
	for range maxPublishedSigningKeys + 1 {
		key := newResourceSigningKey(t)
		tooMany[mustResourceKeyID(t, &key.PublicKey)] = &key.PublicKey
	}
	if _, err := NewAccessTokenVerifier(AccessTokenVerifierOptions{
		Issuer: testIssuer, Audience: testAudience, PublicKeys: tooMany,
		MaxTTL: 10 * time.Minute, Now: time.Now,
	}); err == nil {
		t.Fatal("NewAccessTokenVerifier() accepted too many signing keys")
	}
}

func newResourceSigningKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}
	return privateKey
}

func mustResourceKeyID(t testing.TB, publicKey *ecdsa.PublicKey) string {
	t.Helper()
	keyID, err := es256KeyID(publicKey)
	if err != nil {
		t.Fatalf("es256KeyID() error = %v", err)
	}
	return keyID
}

func newResourceVerifier(
	t testing.TB,
	privateKey *ecdsa.PrivateKey,
	now time.Time,
	issuer string,
	audience string,
) *AccessTokenVerifier {
	t.Helper()
	keyID := mustResourceKeyID(t, &privateKey.PublicKey)
	verifier, err := NewAccessTokenVerifier(AccessTokenVerifierOptions{
		Issuer: issuer, Audience: audience,
		PublicKeys: map[string]*ecdsa.PublicKey{keyID: &privateKey.PublicKey},
		MaxTTL:     10 * time.Minute, ClockSkew: 0, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewAccessTokenVerifier() error = %v", err)
	}
	return verifier
}

func validResourceClaims(
	now time.Time,
	subjectID uuid.UUID,
	issuer string,
	audience string,
	clientID string,
	scope string,
) AccessTokenClaims {
	return AccessTokenClaims{
		Claims: jwt.Claims{
			Issuer: issuer, Subject: subjectID.String(), Audience: jwt.Audience{audience},
			IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(10 * time.Minute)),
			ID: strings.Repeat("A", 43),
		},
		ClientID: clientID, Scope: scope,
	}
}

func signResourceClaims(
	t testing.TB,
	algorithm jose.SignatureAlgorithm,
	key any,
	keyID string,
	typ string,
	claims AccessTokenClaims,
) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: algorithm, Key: key},
		new(jose.SignerOptions).WithType(jose.ContentType(typ)).WithHeader(jose.HeaderKey("kid"), keyID),
	)
	if err != nil {
		t.Fatalf("jose.NewSigner() error = %v", err)
	}
	serialized, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("Serialize() error = %v", err)
	}
	return serialized
}

func alternateResourceBase64Character(character byte) string {
	if character == 'A' {
		return "B"
	}
	return "A"
}
