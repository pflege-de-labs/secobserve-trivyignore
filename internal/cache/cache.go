// Package cache holds compiled ignore files per SecObserve product and resolves repositories to products.
package cache

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pflege-de-labs/secobserve-trivyignore/internal/ignorefile"
	"github.com/pflege-de-labs/secobserve-trivyignore/internal/secobserve"
)

type Source interface {
	ListProducts(ctx context.Context) ([]secobserve.Product, error)
	ListObservations(ctx context.Context, productID, branchID int, statuses []string) ([]secobserve.Observation, error)
}

type Item struct {
	Product       string
	Body          []byte
	Entries       int
	SkippedNoPURL int
	FetchedAt     time.Time
}

type Cache struct {
	src         Source
	frontendURL string
	now         func() time.Time

	mu     sync.RWMutex
	items  map[string]Item     // by product name
	byRepo map[string][]string // normalized prefix -> sorted product names
}

func New(src Source, frontendURL string, now func() time.Time) *Cache {
	return &Cache{src: src, frontendURL: frontendURL, now: now, items: map[string]Item{}, byRepo: map[string][]string{}}
}

func normalize(prefix string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSuffix(prefix, "/"), ".git"))
}

func (c *Cache) Refresh(ctx context.Context) error {
	products, err := c.src.ListProducts(ctx)
	if err != nil {
		return fmt.Errorf("list products: %w", err)
	}

	c.mu.RLock()
	prev := c.items
	c.mu.RUnlock()

	items := make(map[string]Item, len(products))
	byRepo := map[string][]string{}
	var errs []error
	for _, p := range products {
		if p.RepositoryPrefix != "" {
			k := normalize(p.RepositoryPrefix)
			byRepo[k] = append(byRepo[k], p.Name)
		}
		it, err := c.build(ctx, p)
		if err != nil {
			errs = append(errs, fmt.Errorf("product %s: %w", p.Name, err))
			if old, ok := prev[p.Name]; ok {
				items[p.Name] = old
			}
			continue
		}
		items[p.Name] = it
	}
	for _, names := range byRepo {
		sort.Strings(names)
	}

	c.mu.Lock()
	c.items, c.byRepo = items, byRepo
	c.mu.Unlock()
	return errors.Join(errs...)
}

func (c *Cache) build(ctx context.Context, p secobserve.Product) (Item, error) {
	var res ignorefile.Result
	if p.RepositoryDefaultBranch != nil {
		obs, err := c.src.ListObservations(ctx, p.ID, *p.RepositoryDefaultBranch, ignorefile.SuppressingStatuses)
		if err != nil {
			return Item{}, err
		}
		res = ignorefile.Compile(obs, c.frontendURL)
	}
	body, err := res.File.Marshal()
	if err != nil {
		return Item{}, err
	}
	return Item{Product: p.Name, Body: body, Entries: len(res.File.Vulnerabilities), SkippedNoPURL: res.SkippedNoPURL, FetchedAt: c.now()}, nil
}

func (c *Cache) Run(ctx context.Context, every time.Duration) {
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		if err := c.Refresh(ctx); err != nil && ctx.Err() == nil {
			slog.Default().Warn("cache refresh failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (c *Cache) Products(repository string) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]string(nil), c.byRepo["https://github.com/"+strings.ToLower(repository)]...)
}

func (c *Cache) Get(product string) (Item, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	it, ok := c.items[product]
	return it, ok
}
