package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const testAudience = "secobserve-trivyignore"

type testEnv struct {
	key      *rsa.PrivateKey
	verifier *Verifier
}

func newTestEnv(t *testing.T, owners ...string) *testEnv {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ks := &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}
	v := oidc.NewVerifier(githubIssuer, ks, &oidc.Config{ClientID: testAudience, SupportedSigningAlgs: []string{"RS256"}})
	return &testEnv{key: key, verifier: NewVerifier(v, owners)}
}

type tokenOpts struct {
	aud        string
	exp        time.Time
	repository string
	owner      string
}

func (e *testEnv) sign(t *testing.T, o tokenOpts) string {
	t.Helper()
	if o.aud == "" {
		o.aud = testAudience
	}
	if o.exp.IsZero() {
		o.exp = time.Now().Add(time.Hour)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: e.key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	std := jwt.Claims{Issuer: githubIssuer, Subject: "repo:x", Audience: jwt.Audience{o.aud}, Expiry: jwt.NewNumericDate(o.exp), IssuedAt: jwt.NewNumericDate(time.Now())}
	priv := struct {
		Repository      string `json:"repository"`
		RepositoryOwner string `json:"repository_owner"`
	}{o.repository, o.owner}
	tok, err := jwt.Signed(signer).Claims(std).Claims(priv).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}
