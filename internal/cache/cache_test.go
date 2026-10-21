package cache

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/pflege-de-labs/secobserve-trivyignore/internal/secobserve"
)

type fakeSource struct {
	products    []secobserve.Product
	productsErr error
	obsErr      map[int]error
	obsCalls    int
}

func (f *fakeSource) ListProducts(context.Context) ([]secobserve.Product, error) {
	return f.products, f.productsErr
}

func (f *fakeSource) ListObservations(_ context.Context, id, _ int, _ []string) ([]secobserve.Observation, error) {
	f.obsCalls++
	return nil, f.obsErr[id]
}

func prod(id int, name, prefix string) secobserve.Product {
	b := 1
	return secobserve.Product{ID: id, Name: name, RepositoryPrefix: prefix, RepositoryDefaultBranch: &b}
}

func clock(t *time.Time) func() time.Time { return func() time.Time { return *t } }

func TestRefreshPopulates(t *testing.T) {
	now := time.Unix(100, 0)
	c := New(&fakeSource{products: []secobserve.Product{prod(1, "A", "https://github.com/o/a"), prod(2, "B", "https://github.com/o/b")}}, "", clock(&now))
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"A", "B"} {
		it, ok := c.Get(n)
		if !ok || !it.FetchedAt.Equal(now) || it.Product != n {
			t.Fatalf("%s: %+v %v", n, it, ok)
		}
	}
}

func TestResolveNormalizesPrefix(t *testing.T) {
	now := time.Unix(100, 0)
	c := New(&fakeSource{products: []secobserve.Product{prod(1, "Teamster", "https://github.com/Pflege-De-Labs/Teamster.git/")}}, "", clock(&now))
	_ = c.Refresh(context.Background())
	if got := c.Products("pflege-de-labs/teamster"); !reflect.DeepEqual(got, []string{"Teamster"}) {
		t.Fatalf("got %v", got)
	}
	if got := c.Products("x/unknown"); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}

func TestResolveMonorepo(t *testing.T) {
	now := time.Unix(100, 0)
	c := New(&fakeSource{products: []secobserve.Product{prod(1, "Zed", "https://github.com/o/m"), prod(2, "Alpha", "https://github.com/o/m/")}}, "", clock(&now))
	_ = c.Refresh(context.Background())
	if got := c.Products("o/m"); !reflect.DeepEqual(got, []string{"Alpha", "Zed"}) {
		t.Fatalf("got %v", got)
	}
}

func TestEmptyPrefixNotIndexed(t *testing.T) {
	now := time.Unix(100, 0)
	c := New(&fakeSource{products: []secobserve.Product{prod(1, "A", "")}}, "", clock(&now))
	_ = c.Refresh(context.Background())
	if _, ok := c.Get("A"); !ok {
		t.Fatal("A should be cached")
	}
	if got := c.Products(""); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}

func TestNoDefaultBranchEmptyFile(t *testing.T) {
	now := time.Unix(100, 0)
	src := &fakeSource{products: []secobserve.Product{{ID: 1, Name: "A", RepositoryPrefix: "https://github.com/o/a"}}}
	c := New(src, "", clock(&now))
	_ = c.Refresh(context.Background())
	it, ok := c.Get("A")
	if !ok || string(it.Body) != "vulnerabilities: []\n" || src.obsCalls != 0 {
		t.Fatalf("%q %v calls=%d", it.Body, ok, src.obsCalls)
	}
}

func TestRefreshFailureKeepsCache(t *testing.T) {
	t0, t1 := time.Unix(100, 0), time.Unix(200, 0)
	now := t0
	src := &fakeSource{products: []secobserve.Product{prod(1, "A", "https://github.com/o/a")}}
	c := New(src, "", clock(&now))
	_ = c.Refresh(context.Background())
	now, src.productsErr = t1, errors.New("boom")
	if err := c.Refresh(context.Background()); err == nil {
		t.Fatal("want error")
	}
	if it, ok := c.Get("A"); !ok || !it.FetchedAt.Equal(t0) {
		t.Fatalf("%+v %v", it, ok)
	}
}

func TestProductFailureKeepsPrevious(t *testing.T) {
	t0, t1 := time.Unix(100, 0), time.Unix(200, 0)
	now := t0
	src := &fakeSource{products: []secobserve.Product{prod(1, "A", "https://github.com/o/a"), prod(2, "B", "https://github.com/o/b")}}
	c := New(src, "", clock(&now))
	_ = c.Refresh(context.Background())
	now, src.obsErr = t1, map[int]error{1: errors.New("boom")}
	if err := c.Refresh(context.Background()); err == nil {
		t.Fatal("want error")
	}
	a, _ := c.Get("A")
	b, _ := c.Get("B")
	if !a.FetchedAt.Equal(t0) || !b.FetchedAt.Equal(t1) {
		t.Fatalf("A=%v B=%v", a.FetchedAt, b.FetchedAt)
	}
}

func TestFirstFetchFailureHasNoItem(t *testing.T) {
	now := time.Unix(100, 0)
	src := &fakeSource{products: []secobserve.Product{prod(1, "A", "https://github.com/o/a")}, obsErr: map[int]error{1: errors.New("boom")}}
	c := New(src, "", clock(&now))
	_ = c.Refresh(context.Background())
	if _, ok := c.Get("A"); ok {
		t.Fatal("A must be absent")
	}
}

func TestRefreshDropsDeletedProduct(t *testing.T) {
	now := time.Unix(100, 0)
	src := &fakeSource{products: []secobserve.Product{prod(1, "A", "https://github.com/o/a"), prod(2, "B", "https://github.com/o/b")}}
	c := New(src, "", clock(&now))
	_ = c.Refresh(context.Background())
	src.products = src.products[1:]
	_ = c.Refresh(context.Background())
	if _, ok := c.Get("A"); ok {
		t.Fatal("A should be gone")
	}
	if got := c.Products("o/a"); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	now := time.Unix(100, 0)
	c := New(&fakeSource{}, "", clock(&now))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx, time.Hour); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return")
	}
}
