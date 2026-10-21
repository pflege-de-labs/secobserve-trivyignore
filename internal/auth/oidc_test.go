package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func verify(e *testEnv, tok string) (Claims, error) {
	return e.verifier.Verify(context.Background(), "Bearer "+tok)
}

func TestVerifyOK(t *testing.T) {
	e := newTestEnv(t, "pflege-de-labs")
	c, err := verify(e, e.sign(t, tokenOpts{repository: "pflege-de-labs/app", owner: "pflege-de-labs"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Repository != "pflege-de-labs/app" || c.RepositoryOwner != "pflege-de-labs" {
		t.Fatalf("claims = %+v", c)
	}
}

func TestVerifyHeaderForms(t *testing.T) {
	e := newTestEnv(t, "pflege-de-labs")
	tok := e.sign(t, tokenOpts{repository: "pflege-de-labs/app", owner: "pflege-de-labs"})
	if _, err := e.verifier.Verify(context.Background(), "bearer "+tok); err != nil {
		t.Fatalf("lowercase scheme: %v", err)
	}
	for _, h := range []string{"", "Basic " + tok, tok, "Bearer", "Bearer  " + tok, "Bearer " + tok + " x"} {
		if _, err := e.verifier.Verify(context.Background(), h); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("header %q: err = %v", h, err)
		}
	}
}

func TestVerifyMissingHeader(t *testing.T) {
	e := newTestEnv(t, "pflege-de-labs")
	if _, err := e.verifier.Verify(context.Background(), ""); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("err = %v", err)
	}
}

func TestVerifyWrongAudience(t *testing.T) {
	e := newTestEnv(t, "pflege-de-labs")
	_, err := verify(e, e.sign(t, tokenOpts{aud: "other", repository: "pflege-de-labs/app", owner: "pflege-de-labs"}))
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("err = %v", err)
	}
}

func TestVerifyExpired(t *testing.T) {
	e := newTestEnv(t, "pflege-de-labs")
	tok := e.sign(t, tokenOpts{exp: time.Now().Add(-time.Hour), repository: "pflege-de-labs/app", owner: "pflege-de-labs"})
	_, err := verify(e, tok)
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), tok) {
		t.Fatal("error leaks token")
	}
}

func TestVerifyBadSignature(t *testing.T) {
	e := newTestEnv(t, "pflege-de-labs")
	other := newTestEnv(t, "pflege-de-labs")
	_, err := verify(e, other.sign(t, tokenOpts{repository: "pflege-de-labs/app", owner: "pflege-de-labs"}))
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("err = %v", err)
	}
}

func TestVerifyForeignOwner(t *testing.T) {
	e := newTestEnv(t, "pflege-de-labs")
	_, err := verify(e, e.sign(t, tokenOpts{repository: "evil/app", owner: "evil"}))
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("err = %v", err)
	}
}

func TestVerifyOwnerCaseInsensitive(t *testing.T) {
	e := newTestEnv(t, "pflege-de-labs")
	if _, err := verify(e, e.sign(t, tokenOpts{repository: "Pflege-De-Labs/app", owner: "Pflege-De-Labs"})); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRepositoryOwnerMismatch(t *testing.T) {
	e := newTestEnv(t, "pflege-de-labs")
	for _, repo := range []string{"evil/app", "pflege-de-labs", "pflege-de-labs/", "/app", "pflege-de-labs/a/b", ""} {
		_, err := verify(e, e.sign(t, tokenOpts{repository: repo, owner: "pflege-de-labs"}))
		if !errors.Is(err, ErrForbidden) {
			t.Errorf("repo %q: err = %v", repo, err)
		}
	}
}
