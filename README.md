# secobserve-trivyignore

Serves `.trivyignore.yaml` files compiled from SecObserve assessments to GitHub Actions. Callers
authenticate with their GitHub OIDC token, so SecObserve stays the only place where vulnerabilities
are reviewed and a pull request cannot add its own suppressions.

See [ADR 0001](docs/adr/0001-serve-trivy-ignore-files-from-secobserve.md) for the design.
