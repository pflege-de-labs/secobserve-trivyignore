package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pflege-de-labs/secobserve-trivyignore/internal/auth"
	"github.com/pflege-de-labs/secobserve-trivyignore/internal/cache"
)

var (
	_ Store         = (*cache.Cache)(nil)
	_ Authenticator = (*auth.Verifier)(nil)
)

type fakeStore struct {
	byRepo   map[string][]string
	items    map[string]cache.Item
	listedAt time.Time
	listed   bool
	gotRepos *[]string
}

func (f fakeStore) Products(repo string) []string {
	if f.gotRepos != nil {
		*f.gotRepos = append(*f.gotRepos, repo)
	}
	return f.byRepo[repo]
}
func (f fakeStore) Get(p string) (cache.Item, bool) {
	i, ok := f.items[p]
	return i, ok
}
func (f fakeStore) ListedAt() (time.Time, bool) { return f.listedAt, f.listed }

// st builds a store whose repository o/r owns products, listed just now.
func st(products []string, items map[string]cache.Item) fakeStore {
	return fakeStore{byRepo: map[string][]string{"o/r": products}, items: items, listedAt: t0, listed: true}
}

type fakeAuth struct {
	claims auth.Claims
	err    error
}

func (f fakeAuth) Verify(context.Context, string) (auth.Claims, error) { return f.claims, f.err }

var t0 = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)

func item(p string, age time.Duration) cache.Item {
	return cache.Item{Product: p, Body: []byte("body-" + p), Entries: 3, FetchedAt: t0.Add(-age)}
}

func TestTrivyIgnore(t *testing.T) {
	one := st([]string{"a"}, map[string]cache.Item{"a": item("a", 10*time.Minute)})
	two := st([]string{"a", "b"}, map[string]cache.Item{"a": item("a", time.Minute), "b": item("b", time.Minute)})
	other := fakeStore{byRepo: map[string][]string{"o/other": {"x"}}, items: map[string]cache.Item{"x": item("x", 0)}, listedAt: t0, listed: true}
	both := one
	both.byRepo = map[string][]string{"o/r": {"a"}, "o/other": {"x"}}
	both.items = map[string]cache.Item{"a": item("a", 0), "x": item("x", 0)}
	neverListed := one
	neverListed.listed = false
	staleList := one
	staleList.listedAt = t0.Add(-time.Hour - time.Second)
	ok := fakeAuth{claims: auth.Claims{Repository: "o/r"}}
	tests := []struct {
		name   string
		store  fakeStore
		authn  fakeAuth
		query  string
		status int
		body   string
		age    string
	}{
		{"ok single", one, ok, "", 200, "body-a", "600"},
		{"ok single explicit", one, ok, "?product=a", 200, "body-a", "600"},
		{"ok multi", two, ok, "?product=b", 200, "body-b", "60"},
		{"unauthenticated", one, fakeAuth{err: fmt.Errorf("x: %w", auth.ErrUnauthenticated)}, "", 401, "unauthorized", ""},
		{"other verify error", one, fakeAuth{err: errors.New("boom")}, "", 401, "unauthorized", ""},
		{"forbidden", one, fakeAuth{err: fmt.Errorf("x: %w", auth.ErrForbidden)}, "", 403, "forbidden", ""},
		{"no product", other, ok, "", 404, "no SecObserve product for repository", ""},
		{"other repo's product", both, ok, "?product=x", 403, "product not allowed", ""},
		{"never listed", neverListed, ok, "", 503, "ignore file unavailable", ""},
		{"product list stale", staleList, ok, "", 503, "ignore file unavailable", ""},
		{"never listed but unauthenticated", neverListed, fakeAuth{err: auth.ErrUnauthenticated}, "", 401, "unauthorized", ""},
		{"multi without param", two, ok, "", 400, "product parameter required", ""},
		{"multi not in set", two, ok, "?product=z", 403, "product not allowed", ""},
		{"single mismatch", one, ok, "?product=z", 403, "product not allowed", ""},
		{"item missing", st([]string{"a"}, nil), ok, "", 503, "ignore file unavailable", ""},
		{"stale", st([]string{"a"}, map[string]cache.Item{"a": item("a", time.Hour+time.Second)}), ok, "", 503, "ignore file unavailable", ""},
		{"exactly max staleness", st([]string{"a"}, map[string]cache.Item{"a": item("a", time.Hour)}), ok, "", 200, "body-a", "3600"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := New(tt.store, tt.authn, time.Hour, func() time.Time { return t0 }, slog.New(slog.DiscardHandler))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/trivyignore"+tt.query, nil))
			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d", rec.Code, tt.status)
			}
			if got := strings.TrimSpace(rec.Body.String()); got != tt.body {
				t.Errorf("body = %q, want %q", got, tt.body)
			}
			if got := rec.Header().Get("X-Cache-Age"); got != tt.age {
				t.Errorf("X-Cache-Age = %q, want %q", got, tt.age)
			}
			if tt.status == 200 {
				if ct := rec.Header().Get("Content-Type"); ct != "application/yaml" {
					t.Errorf("Content-Type = %q", ct)
				}
				if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
					t.Errorf("Cache-Control = %q", cc)
				}
			}
		})
	}
}

func TestProbes(t *testing.T) {
	h := New(fakeStore{}, fakeAuth{}, time.Hour, time.Now, slog.New(slog.DiscardHandler))
	for _, p := range []string{"/livez", "/readyz"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", p, nil))
		if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
			t.Errorf("%s: %d %q", p, rec.Code, rec.Body.String())
		}
	}
}

func TestNoTokenInLogs(t *testing.T) {
	var buf bytes.Buffer
	store := st([]string{"a"}, map[string]cache.Item{"a": item("a", 0)})
	h := New(store, fakeAuth{claims: auth.Claims{Repository: "o/r"}}, time.Hour, func() time.Time { return t0 }, slog.New(slog.NewTextHandler(&buf, nil)))
	req := httptest.NewRequest("GET", "/v1/trivyignore", nil)
	req.Header.Set("Authorization", "Bearer s3cr3t-token")
	h.ServeHTTP(httptest.NewRecorder(), req)
	out := buf.String()
	if strings.Contains(out, "s3cr3t-token") {
		t.Fatalf("token leaked: %s", out)
	}
	for _, want := range []string{"repository=o/r", "product=a", "entries=3", "status=200"} {
		if !strings.Contains(out, want) {
			t.Errorf("log missing %q: %s", want, out)
		}
	}
}

func TestProductsScopedToTokenRepository(t *testing.T) {
	var got []string
	store := st([]string{"a"}, map[string]cache.Item{"a": item("a", 0)})
	store.gotRepos = &got
	h := New(store, fakeAuth{claims: auth.Claims{Repository: "o/r"}}, time.Hour, func() time.Time { return t0 }, slog.New(slog.DiscardHandler))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/v1/trivyignore?product=other-repos-product", nil))
	if len(got) != 1 || got[0] != "o/r" {
		t.Fatalf("Products called with %v, want [o/r]", got)
	}
}
