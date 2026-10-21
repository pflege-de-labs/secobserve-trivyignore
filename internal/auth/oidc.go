// Package auth verifies GitHub Actions OIDC tokens; the repository claim is the service's only access control.
package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

const githubIssuer = "https://token.actions.githubusercontent.com"

var (
	ErrUnauthenticated = errors.New("unauthenticated")
	ErrForbidden       = errors.New("forbidden")
)

type Claims struct {
	Repository      string `json:"repository"`
	RepositoryOwner string `json:"repository_owner"`
}

type Verifier struct {
	v      *oidc.IDTokenVerifier
	owners []string
}

func NewVerifier(v *oidc.IDTokenVerifier, allowedOwners []string) *Verifier {
	return &Verifier{v: v, owners: allowedOwners}
}

func NewGitHubVerifier(ctx context.Context, audience string, allowedOwners []string) (*Verifier, error) {
	p, err := oidc.NewProvider(ctx, githubIssuer)
	if err != nil {
		return nil, fmt.Errorf("oidc provider: %w", err)
	}
	v := p.Verifier(&oidc.Config{ClientID: audience, SupportedSigningAlgs: []string{"RS256"}})
	return NewVerifier(v, allowedOwners), nil
}

func (v *Verifier) Verify(ctx context.Context, authorizationHeader string) (Claims, error) {
	parts := strings.Split(authorizationHeader, " ")
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return Claims{}, ErrUnauthenticated
	}
	tok, err := v.v.Verify(ctx, parts[1])
	if err != nil {
		// go-oidc errors do not echo the token, but we keep the text generic anyway.
		return Claims{}, fmt.Errorf("%w: token verification failed", ErrUnauthenticated)
	}
	var c Claims
	if err := tok.Claims(&c); err != nil {
		return Claims{}, fmt.Errorf("%w: unreadable claims", ErrUnauthenticated)
	}
	owner, name, ok := strings.Cut(c.Repository, "/")
	if !ok || owner == "" || name == "" || strings.Contains(name, "/") || !strings.EqualFold(owner, c.RepositoryOwner) {
		return Claims{}, fmt.Errorf("%w: malformed repository claim", ErrForbidden)
	}
	for _, a := range v.owners {
		if strings.EqualFold(a, c.RepositoryOwner) {
			return c, nil
		}
	}
	return Claims{}, fmt.Errorf("%w: owner not allowed", ErrForbidden)
}
