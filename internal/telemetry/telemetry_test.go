package telemetry

import (
	"context"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pflege-de-labs/secobserve-trivyignore/internal/cache"
	"github.com/pflege-de-labs/secobserve-trivyignore/internal/secobserve"
)

type failingSource struct{}

func (failingSource) ListProducts(context.Context) ([]secobserve.Product, error) {
	return nil, errors.New("boom")
}

func (failingSource) ListObservations(context.Context, int, int, []string) ([]secobserve.Observation, error) {
	return nil, nil
}

func TestMetricsExposed(t *testing.T) {
	h, shutdown, err := Setup()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = shutdown(context.Background()) }()

	c := cache.New(failingSource{}, "", time.Now)
	_ = c.Refresh(context.Background())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), "trivyignore_refresh_errors_total") {
		t.Fatalf("metric missing in:\n%s", body)
	}
}
