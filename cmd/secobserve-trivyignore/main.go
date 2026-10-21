package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/pflege-de-labs/secobserve-trivyignore/internal/auth"
	"github.com/pflege-de-labs/secobserve-trivyignore/internal/cache"
	"github.com/pflege-de-labs/secobserve-trivyignore/internal/secobserve"
	"github.com/pflege-de-labs/secobserve-trivyignore/internal/server"
	"github.com/pflege-de-labs/secobserve-trivyignore/internal/telemetry"
)

var version = "dev"

type CLI struct {
	Listen          string        `env:"LISTEN" default:":8080" help:"Listen address."`
	SecObserveURL   string        `name:"secobserve-url" env:"SECOBSERVE_URL" required:"" help:"SecObserve API base URL."`
	SecObserveToken string        `name:"secobserve-token" env:"SECOBSERVE_TOKEN" required:"" help:"SecObserve API token."`
	FrontendURL     string        `env:"FRONTEND_URL" default:"https://secobserve.p4e.io" help:"SecObserve UI URL used in ignore-file links."`
	Audience        string        `env:"AUDIENCE" default:"secobserve-trivyignore" help:"Expected OIDC token audience."`
	AllowedOwners   []string      `env:"ALLOWED_OWNERS" default:"pflege-de,pflege-de-labs,webcarelbj" help:"GitHub owners allowed to call the service."`
	RefreshInterval time.Duration `env:"REFRESH_INTERVAL" default:"10m" help:"How often to refresh from SecObserve."`
	MaxStaleness    time.Duration `env:"MAX_STALENESS" default:"24h" help:"Refuse to serve data older than this."`
}

// Validate is a kong hook; time.NewTicker panics on non-positive intervals.
func (c *CLI) Validate() error {
	switch {
	case c.RefreshInterval <= 0:
		return errors.New("--refresh-interval must be > 0")
	case c.MaxStaleness <= 0:
		return errors.New("--max-staleness must be > 0")
	case len(c.AllowedOwners) == 0:
		return errors.New("--allowed-owners must not be empty")
	}
	return nil
}

func main() {
	var cli CLI
	kong.Parse(&cli, kong.Name("secobserve-trivyignore"))
	if err := run(&cli); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run(cli *CLI) error {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(log)
	log.Info("starting", "version", version, "listen", cli.Listen, "secobserve_url", cli.SecObserveURL,
		"frontend_url", cli.FrontendURL, "audience", cli.Audience, "allowed_owners", cli.AllowedOwners,
		"refresh_interval", cli.RefreshInterval, "max_staleness", cli.MaxStaleness)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	metricsHandler, shutdownTelemetry, err := telemetry.Setup()
	if err != nil {
		return err
	}

	client := secobserve.New(cli.SecObserveURL, cli.SecObserveToken, &http.Client{Timeout: 30 * time.Second})
	store := cache.New(client, cli.FrontendURL, time.Now)
	verifier, err := auth.NewGitHubVerifier(ctx, cli.Audience, cli.AllowedOwners)
	if err != nil {
		return err
	}
	go store.Run(ctx, cli.RefreshInterval)

	mux := http.NewServeMux()
	mux.Handle("/metrics", metricsHandler)
	mux.Handle("/", otelhttp.NewHandler(server.New(store, verifier, cli.MaxStaleness, time.Now, log), "secobserve-trivyignore"))
	srv := &http.Server{Addr: cli.Listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}

	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = srv.Shutdown(shutCtx)
	return errors.Join(err, shutdownTelemetry(shutCtx))
}
