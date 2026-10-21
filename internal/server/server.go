// Package server serves per-repository .trivyignore.yaml files.
package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/pflege-de-labs/secobserve-trivyignore/internal/auth"
	"github.com/pflege-de-labs/secobserve-trivyignore/internal/cache"
)

type Store interface {
	Products(repository string) []string
	Get(product string) (cache.Item, bool)
}

type Authenticator interface {
	Verify(ctx context.Context, authorization string) (auth.Claims, error)
}

func New(store Store, authn Authenticator, maxStaleness time.Duration, now func() time.Time, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	ok := func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }
	mux.HandleFunc("GET /livez", ok)
	mux.HandleFunc("GET /readyz", ok)
	mux.HandleFunc("GET /v1/trivyignore", func(w http.ResponseWriter, r *http.Request) {
		var repo, product string
		var entries int
		status, msg, body := http.StatusOK, "", []byte(nil)
		defer func() {
			log.InfoContext(r.Context(), "trivyignore request",
				"repository", repo, "product", product, "entries", entries, "status", status)
		}()
		fail := func(code int, m string) { status, msg = code, m }

		claims, err := authn.Verify(r.Context(), r.Header.Get("Authorization"))
		repo = claims.Repository
		switch {
		case errors.Is(err, auth.ErrForbidden):
			fail(http.StatusForbidden, "forbidden")
		case err != nil:
			fail(http.StatusUnauthorized, "unauthorized")
		}

		var item cache.Item
		if status == http.StatusOK {
			products := store.Products(repo)
			want := r.URL.Query().Get("product")
			switch {
			case len(products) == 0:
				fail(http.StatusNotFound, "no SecObserve product for repository")
			case want == "" && len(products) > 1:
				fail(http.StatusBadRequest, "product parameter required")
			case want != "" && !slices.Contains(products, want):
				fail(http.StatusForbidden, "product not allowed")
			default:
				product = products[0]
				if want != "" {
					product = want
				}
			}
		}
		if status == http.StatusOK {
			var found bool
			item, found = store.Get(product)
			if !found || now().Sub(item.FetchedAt) > maxStaleness {
				fail(http.StatusServiceUnavailable, "ignore file unavailable")
			}
		}

		if status != http.StatusOK {
			http.Error(w, msg, status)
			return
		}
		entries, body = item.Entries, item.Body
		w.Header().Set("Content-Type", "application/yaml")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Cache-Age", strconv.FormatInt(int64(now().Sub(item.FetchedAt)/time.Second), 10))
		_, _ = w.Write(body)
	})
	return mux
}
