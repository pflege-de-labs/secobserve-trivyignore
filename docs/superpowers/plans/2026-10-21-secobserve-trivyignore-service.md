# secobserve-trivyignore Service Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Go service that serves per-product `.trivyignore.yaml` files compiled from approved SecObserve assessments to GitHub Actions jobs authenticated by OIDC.

**Architecture:** A background loop refreshes an in-memory cache of all products' ignore entries from the SecObserve API every 10 min. An HTTP handler verifies the caller's GitHub OIDC JWT, maps its `repository` claim to products via `repository_prefix`, and serves the cached file (stale up to 24h). Probes and OTEL metrics follow the `teamster` conventions.

**Tech Stack:** Go 1.26, `github.com/alecthomas/kong` (CLI/env config), `github.com/coreos/go-oidc/v3` (JWT), `go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp` + `go.opentelemetry.io/otel/exporters/prometheus`, `go.yaml.in/yaml/v3`, `log/slog`, stdlib `net/http/httptest` for tests.

**Spec:** `docs/adr/0001-serve-trivy-ignore-files-from-secobserve.md` (copied from the approved design in Task 0)

**Scope:** this repo only. Follow-up plans, not covered here: (B) github-ops `trivyignore` Reader authorization group in `product_group_governance` + manual SecObserve user/token; (C) cc-gitops Deployment, secret, ServiceMonitor, gateway route `webhooks.management.p4e.io/trivyignore`; (D) composite action `pflege-de-labs/github-workflows/actions/trivyignore`, wiring into `go-binaries.yml` and `pflege-de/github-workflows` `go-full*.yml`, plus Trivy→SecObserve upload in `go-full*`.

## Global Constraints

- Module: `github.com/pflege-de-labs/secobserve-trivyignore`; binary/cmd: `secobserve-trivyignore`.
- OIDC issuer `https://token.actions.githubusercontent.com`; audience default `secobserve-trivyignore`.
- Owner allowlist default: `pflege-de`, `pflege-de-labs`, `webcarelbj`.
- Suppressing statuses, exact strings: `False positive`, `Not affected`, `Not security`, `Risk accepted`.
- Refresh interval default `10m`; max staleness default `24h`; response header `X-Cache-Age` (integer seconds).
- Endpoint `GET /v1/trivyignore[?product=<name>]`, `Content-Type: application/yaml`; probes `/livez`, `/readyz`; metrics `/metrics`.
- `/readyz` must not depend on SecObserve reachability.
- Never log the JWT or the SecObserve token.
- Every config flag also settable by env (kong `env:` tag); SecObserve token only via env/file, never a default.
- Comments: one line max, explain why (user CLAUDE.md).

## Review Focus

- Observation with empty `origin_component_purl` → skipped and counted, never an `id`-only entry (Task 2 test `TestCompileSkipsMissingPurl`).
- Same (id, purl) from several observations (services/files), one `Risk accepted` with expiry and one `False positive` → single entry without `expired_at` (Task 2 `TestCompileDedupKeepsLongestValidity`).
- `repository_prefix` with different case, trailing `/` or `.git` vs. claim `Org/Repo` → still matches (Task 3 `TestResolveNormalizesPrefix`).
- Full product-list refresh fails after a good one → previous entries keep being served, age grows; product removed from SecObserve disappears only after the next successful refresh (Task 3 `TestRefreshFailureKeepsCache`, `TestRefreshDropsDeletedProduct`).
- More than one page of observations (`next` set) → all pages read (Task 1 `TestListObservationsFollowsPages`).

---

### Task 0: Repository bootstrap and assumption checks

**Files:**
- Create: `go.mod`, `README.md`, `docs/adr/0000-template.md` (copy from teamster), `docs/adr/0001-serve-trivy-ignore-files-from-secobserve.md` (approved spec), `docs/superpowers/plans/2026-10-21-secobserve-trivyignore-service.md` (this plan), `.github/workflows/ci.yml`, `.gitignore`

- [ ] **Step 1:** Clone `pflege-de-labs/secobserve-trivyignore` into a worktree-friendly path, branch `feat/bootstrap`. `go mod init github.com/pflege-de-labs/secobserve-trivyignore`, set `go 1.26.0`.
- [ ] **Step 2:** `ci.yml` calls `pflege-de-labs/github-workflows/.github/workflows/go-checks.yml` pinned to the same SHA teamster uses (`d5b9ce5cc098cf3239e796f49d742a48140130c0 # v1.0.0`).
- [ ] **Step 3: Assumption checks** — record results in the ADR's "Facts" section; stop and report if any fails:
  - Deployed SecObserve version: `curl -s https://secobserve.p4e.io/api/status/version/` (or UI footer) ≥ 1.55 (fields `vulnerability_id_aliases`, `repository_default_branch`, multi-value `current_status`).
  - Trivy honours `expired_at`: write `.trivyignore.yaml` with a known CVE of `alpine:3.18`, `expired_at: 2020-01-01`; `trivy image --ignorefile .trivyignore.yaml alpine:3.18` must still report the CVE; with `expired_at: 2099-01-01` it must not. If not honoured: Task 2 drops entries whose expiry ≤ today instead (one extra test).
- [ ] **Step 4:** Commit `chore: bootstrap repository with design ADR and plan`, open PR.

### Task 1: SecObserve API client

**Files:** Create `internal/secobserve/client.go`, `internal/secobserve/client_test.go`

**Interfaces — Produces:**
```go
type Product struct {
    ID                      int    `json:"id"`
    Name                    string `json:"name"`
    RepositoryPrefix        string `json:"repository_prefix"`
    RepositoryDefaultBranch *int   `json:"repository_default_branch"`
}
type Alias struct{ Alias string `json:"alias"` }
type Observation struct {
    ID                       int     `json:"id"`
    CurrentStatus            string  `json:"current_status"`
    VulnerabilityID          string  `json:"vulnerability_id"`
    VulnerabilityIDAliases   []Alias `json:"vulnerability_id_aliases"`
    OriginComponentPURL      string  `json:"origin_component_purl"`
    RiskAcceptanceExpiryDate *string `json:"risk_acceptance_expiry_date"` // "YYYY-MM-DD"
}
func New(baseURL, token string, hc *http.Client) *Client
func (c *Client) ListProducts(ctx context.Context) ([]Product, error)            // GET /api/products/?page_size=500
func (c *Client) ListObservations(ctx context.Context, productID, branchID int, statuses []string) ([]Observation, error)
// GET /api/observations/?product=<id>&branch=<id>&current_status=<s>...&page_size=500
```
Auth header: `Authorization: APIToken <token>`. Pagination: DRF `{"count","next","results"}`; follow `next` until null. Non-2xx → error including status and path, not the body.

- [ ] **Step 1: Failing tests** against `httptest.Server`:
  - `TestListProductsSendsToken` — handler asserts header `Authorization == "APIToken t0k"`; returns 1 product; result equals it.
  - `TestListObservationsQuery` — asserts `r.URL.Query()["current_status"]` equals the 4 statuses in order, `product=7`, `branch=3`.
  - `TestListObservationsFollowsPages` — page 1 has `next` = server URL `?page=2`, 2 results; page 2 has 1 result, `next: null` → 3 observations.
  - `TestListProductsNon2xx` — 403 → error containing `403`.
- [ ] **Step 2:** `go test ./internal/secobserve/...` → FAIL (undefined).
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** `go test ./internal/secobserve/...` → PASS.
- [ ] **Step 5:** Commit `feat(secobserve): add paginated API client`.

### Task 2: Ignore-file compiler

**Files:** Create `internal/ignorefile/compile.go`, `internal/ignorefile/compile_test.go`

**Interfaces — Consumes:** `secobserve.Observation`. **Produces:**
```go
var SuppressingStatuses = []string{"False positive", "Not affected", "Not security", "Risk accepted"}
type Entry struct {
    ID        string   `yaml:"id"`
    PURLs     []string `yaml:"purls"`
    ExpiredAt string   `yaml:"expired_at,omitempty"`
    Statement string   `yaml:"statement"`
}
type File struct{ Vulnerabilities []Entry `yaml:"vulnerabilities"` }
type Result struct { File File; SkippedNoPURL int }
func Compile(obs []secobserve.Observation, frontendURL string) Result
func (f File) Marshal() ([]byte, error)
```
Rules: skip empty `VulnerabilityID` or empty purl (count purl-less in `SkippedNoPURL`); ids = `VulnerabilityID` + each alias; one entry per (id, purl), `PURLs` has exactly that one purl; `ExpiredAt` only for `Risk accepted` with non-nil date; on duplicate (id, purl) keep no-expiry over any expiry, else later date; `Statement = "<status> — <frontendURL>/#/observations/<id>/show"`; sort by id, then purl. Empty input → `vulnerabilities: []` (valid file).

- [ ] **Step 1: Failing tests:**
  - `TestCompileBasic` — one `False positive` CVE-2025-1/`pkg:golang/a@v1` → 1 entry, no `ExpiredAt`, statement `"False positive — https://so/#/observations/9/show"`.
  - `TestCompileAliases` — aliases `GHSA-x` → 2 entries, ids `CVE-2025-1`, `GHSA-x`, same purl.
  - `TestCompileRiskAcceptedExpiry` — date `2027-01-19` → `ExpiredAt == "2027-01-19"`.
  - `TestCompileSkipsMissingPurl` — purl `""` → 0 entries, `SkippedNoPURL == 1`.
  - `TestCompileDedupKeepsLongestValidity` — same id/purl, Risk accepted 2027-01-19 + False positive → 1 entry, `ExpiredAt == ""`; two Risk accepted 2027-01-19/2027-03-01 → `2027-03-01`.
  - `TestMarshalEmpty` — `Compile(nil,…).File.Marshal()` == `"vulnerabilities: []\n"`.
  - `TestMarshalGolden` — compile 3 mixed observations, compare to `testdata/golden.yaml`.
- [ ] **Step 2:** `go test ./internal/ignorefile/...` → FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(ignorefile): compile SecObserve observations to trivyignore entries`.

### Task 3: Cache with refresh, staleness and product resolution

**Files:** Create `internal/cache/cache.go`, `internal/cache/cache_test.go`

**Interfaces — Consumes:** Task 1 types, `ignorefile.Compile`, `ignorefile.SuppressingStatuses`. **Produces:**
```go
type Source interface {
    ListProducts(ctx context.Context) ([]secobserve.Product, error)
    ListObservations(ctx context.Context, productID, branchID int, statuses []string) ([]secobserve.Observation, error)
}
type Item struct { Product string; Body []byte; Entries int; SkippedNoPURL int; FetchedAt time.Time }
func New(src Source, frontendURL string, now func() time.Time) *Cache
func (c *Cache) Refresh(ctx context.Context) error           // one full pass
func (c *Cache) Run(ctx context.Context, every time.Duration) // Refresh now, then on ticker until ctx done
func (c *Cache) Products(repository string) []string           // product names for claim "org/repo"
func (c *Cache) Get(product string) (Item, bool)
```
Rules: key products by normalized prefix `strings.ToLower(strings.TrimSuffix(strings.TrimSuffix(prefix, "/"), ".git"))`; claim normalized as `https://github.com/` + lower(repository). Product without default branch → empty file, no API call. `ListProducts` fails → keep everything, return error. One product's `ListObservations` fails → keep its previous `Item`, continue, return joined error. Successful `ListProducts` → products absent from it are removed. Guard with `sync.RWMutex`; swap maps atomically at end of pass.

- [ ] **Step 1: Failing tests** with a fake `Source` and fixed `now`:
  - `TestRefreshPopulates` — 2 products → `Get` returns both, `FetchedAt == now`.
  - `TestResolveNormalizesPrefix` — prefix `https://github.com/Pflege-De-Labs/Teamster.git/` resolves for claim `pflege-de-labs/teamster`.
  - `TestResolveMonorepo` — two products, same prefix → `Products` returns both names sorted.
  - `TestNoDefaultBranchEmptyFile` — `RepositoryDefaultBranch == nil` → `Body == "vulnerabilities: []\n"`, fake records no `ListObservations` call.
  - `TestRefreshFailureKeepsCache` — refresh OK at t0, then `ListProducts` errors at t1 → `Refresh` returns error, `Get` still returns t0 item.
  - `TestProductFailureKeepsPrevious` — second pass, product A observations error, B OK → A keeps t0 item, B has t1.
  - `TestRefreshDropsDeletedProduct` — second pass lists only B → `Get("A")` not found.
  - `go test -race` for all.
- [ ] **Step 2:** `go test -race ./internal/cache/...` → FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(cache): refresh and resolve compiled ignore files per product`.

### Task 4: GitHub OIDC verification

**Files:** Create `internal/auth/oidc.go`, `internal/auth/oidc_test.go`, `internal/auth/testkeys_test.go`

**Interfaces — Produces:**
```go
type Claims struct { Repository string `json:"repository"`; RepositoryOwner string `json:"repository_owner"` }
var ErrUnauthenticated, ErrForbidden error
func NewVerifier(v *oidc.IDTokenVerifier, allowedOwners []string) *Verifier
func NewGitHubVerifier(ctx context.Context, audience string, allowedOwners []string) (*Verifier, error) // oidc.NewProvider(issuer)
func (v *Verifier) Verify(ctx context.Context, authorizationHeader string) (Claims, error)
```
Missing/non-`Bearer` header, bad signature, wrong `aud`, expired → `ErrUnauthenticated`; owner not in allowlist (case-insensitive) or empty `repository` → `ErrForbidden`. Tests build the verifier with `oidc.NewVerifier(issuer, &oidc.StaticKeySet{PublicKeys: …}, &oidc.Config{ClientID: aud})` and sign with an RSA key (`github.com/go-jose/go-jose/v4`, already a go-oidc dependency).

- [ ] **Step 1: Failing tests:** `TestVerifyOK` (claims returned), `TestVerifyMissingHeader`, `TestVerifyWrongAudience`, `TestVerifyExpired`, `TestVerifyForeignOwner` (→ `ErrForbidden`), `TestVerifyOwnerCaseInsensitive` (`Pflege-De-Labs` allowed).
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(auth): verify GitHub Actions OIDC tokens`.

### Task 5: HTTP server

**Files:** Create `internal/server/server.go`, `internal/server/server_test.go`

**Interfaces — Consumes:** `cache.Cache` via interface `Store{ Products(string) []string; Get(string) (cache.Item, bool) }`, `auth.Verifier` via interface `Authenticator{ Verify(context.Context, string) (auth.Claims, error) }`. **Produces:**
```go
func New(store Store, authn Authenticator, maxStaleness time.Duration, now func() time.Time, log *slog.Logger) http.Handler
```
Routes (`http.ServeMux` patterns): `GET /v1/trivyignore`, `GET /livez` (200 `ok`), `GET /readyz` (200 `ok` once constructed). Status mapping: `ErrUnauthenticated` 401, `ErrForbidden` 403, no product 404, several products without `product` param 400, `product` not in set 403, item missing or `now-FetchedAt > maxStaleness` 503. Success: 200, `Content-Type: application/yaml`, `X-Cache-Age`. Log per request: repository, product, entries, status — never the header.

- [ ] **Step 1: Failing table test** `TestTrivyIgnore` with fakes covering each status above, plus `X-Cache-Age: 600` when item 10 min old, and `TestProbes`. Also `TestNoTokenInLogs` — capture `slog` output into a buffer, assert it doesn't contain the bearer value.
- [ ] **Step 2:** FAIL. **Step 3:** Implement. **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(server): serve trivyignore files with probes`.

### Task 6: Telemetry, config and main

**Files:** Create `internal/telemetry/telemetry.go`, `internal/telemetry/telemetry_test.go`, `cmd/secobserve-trivyignore/main.go`; Modify `internal/cache/cache.go` (record metrics), `README.md` (config table)

**Interfaces — Produces:**
```go
func Setup() (metricsHandler http.Handler, shutdown func(context.Context) error, err error) // prometheus exporter as global MeterProvider
```
Metrics (meter `secobserve-trivyignore`): `http.server.*` from `otelhttp.NewHandler`; cache observable gauges `trivyignore.cache.age` (s, attr `product`), `trivyignore.entries` (attr `product`), `trivyignore.skipped_no_purl` (attr `product`); counter `trivyignore.refresh.errors`.

CLI (kong, each with `env:`): `--listen` `:8080` (LISTEN); `--secobserve-url` required (SECOBSERVE_URL); `--secobserve-token` required (SECOBSERVE_TOKEN); `--frontend-url` `https://secobserve.p4e.io`; `--audience` `secobserve-trivyignore`; `--allowed-owners` `pflege-de,pflege-de-labs,webcarelbj`; `--refresh-interval` `10m`; `--max-staleness` `24h`. `/metrics` on same listener. Graceful shutdown on SIGTERM/SIGINT (`signal.NotifyContext`, `srv.Shutdown` with 10s timeout).

- [ ] **Step 1: Failing test** `TestMetricsExposed` — after `Setup()` and recording a refresh error, GET on handler body contains `trivyignore_refresh_errors_total`.
- [ ] **Step 2:** FAIL. **Step 3:** Implement telemetry, cache instrumentation, main.
- [ ] **Step 4:** `go test -race ./... && go vet ./...` → PASS; `go run ./cmd/secobserve-trivyignore --help` lists all flags.
- [ ] **Step 5: Smoke run** against real SecObserve from VPN: `SECOBSERVE_URL=https://api.secobserve.p4e.io SECOBSERVE_TOKEN=… go run ./cmd/secobserve-trivyignore`; `curl -s localhost:8080/metrics | grep trivyignore_entries` shows products. (Needs token from follow-up plan B; skip and note if not yet available.)
- [ ] **Step 6:** Commit `feat: wire service with config, metrics and graceful shutdown`.

### Task 7: Container image and release

**Files:** Create `Dockerfile`, `.dockerignore`; Modify `.github/workflows/ci.yml`; Create `docs/adr/0002-container-image.md`

- [ ] **Step 1:** `Dockerfile` copies teamster's (pinned `golang:1.27.2` builder, `distroless/static-debian12:nonroot`), minus the data dir; `ENTRYPOINT ["/usr/local/bin/secobserve-trivyignore"]`.
- [ ] **Step 2:** `ci.yml` adds `image-build.yml` and `secobserve-image.yml` jobs exactly as in teamster `ci.yml` (same SHA pins).
- [ ] **Step 3:** `docker build -t sti:dev . && docker run --rm sti:dev --help` → flags listed.
- [ ] **Step 4:** Short ADR 0002 (base image, non-root, scan upload) — link teamster ADR 0004 instead of repeating.
- [ ] **Step 5:** Commit `build: add container image and CI image jobs`; PR green.
