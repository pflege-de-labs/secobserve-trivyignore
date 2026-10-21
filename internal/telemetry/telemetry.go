// Package telemetry installs the global OpenTelemetry MeterProvider backed by a Prometheus exporter.
package telemetry

import (
	"context"
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/otlptranslator"
	"go.opentelemetry.io/otel"
	promexporter "go.opentelemetry.io/otel/exporters/prometheus"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

func Setup() (http.Handler, func(context.Context) error, error) {
	// Own registry: the default one is process-global and breaks repeated Setup calls in tests.
	registry := prometheus.NewRegistry()
	exporter, err := promexporter.New(
		promexporter.WithRegisterer(registry),
		promexporter.WithTranslationStrategy(otlptranslator.UnderscoreEscapingWithSuffixes),
		promexporter.WithoutScopeInfo(),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("prometheus exporter: %w", err)
	}
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter))
	otel.SetMeterProvider(mp)
	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{ErrorHandling: promhttp.ContinueOnError})
	return h, mp.Shutdown, nil
}
