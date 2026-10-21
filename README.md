# secobserve-trivyignore

Serves `.trivyignore.yaml` files compiled from SecObserve assessments to GitHub Actions. Callers
authenticate with their GitHub OIDC token, so SecObserve stays the only place where vulnerabilities
are reviewed and a pull request cannot add its own suppressions.

See [ADR 0001](docs/adr/0001-serve-trivy-ignore-files-from-secobserve.md) for the design.

## Configuration

| Flag | Env | Default | Meaning |
|------|-----|---------|---------|
| `--listen` | `LISTEN` | `:8080` | Listen address (also serves `/livez`, `/readyz`, `/metrics`) |
| `--secobserve-url` | `SECOBSERVE_URL` | required | SecObserve API base URL |
| `--secobserve-token` | `SECOBSERVE_TOKEN` | required | SecObserve API token |
| `--frontend-url` | `FRONTEND_URL` | `https://secobserve.p4e.io` | SecObserve UI URL used in ignore-file links |
| `--audience` | `AUDIENCE` | `secobserve-trivyignore` | Expected OIDC token audience |
| `--allowed-owners` | `ALLOWED_OWNERS` | `pflege-de,pflege-de-labs,webcarelbj` | GitHub owners allowed to call the service |
| `--refresh-interval` | `REFRESH_INTERVAL` | `10m` | How often to refresh from SecObserve (must be > 0) |
| `--max-staleness` | `MAX_STALENESS` | `24h` | Refuse to serve data older than this (must be > 0) |
