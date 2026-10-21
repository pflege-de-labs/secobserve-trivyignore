# 0001. Serve Trivy ignore files compiled from SecObserve

* Status: Accepted
* Date: 2026-10-21

## Context

CI Trivy gates (`pflege-de/github-workflows` `go-full*.yml`, `pflege-de-labs/labs-github-workflows` `go-binaries.yml`)
stop failing on vulnerabilities already reviewed in SecObserve. SecObserve stays the only place reviews happen; a PR
cannot add its own suppressions.

Non-goals:

- Replacing the Trivy gate with SecObserve's security gate.
- VEX output (SecObserve maps `Risk accepted` to `affected`, Trivy would not suppress it).
- Upstream SecObserve change (possible later, once the endpoint has proven itself).

### Facts this rests on (SecObserve v1.58 source)

- Pending assessments do not change `current_status` until approved (`assessments_need_approval`); expired risk
  acceptances fall back to Open via cron. Filtering on `current_status` = approved and unexpired.
- Assessments do not carry across branches (`propagate_branches` unset). Product/general rules do.
  → compile from the product's **default branch** only.
- Observation list API filters: `product`, `branch`, `current_status`. No `vulnerability_id` filter.
- Terraform sets `repository_prefix = https://github.com/<org>/<repo>` on every product.

Verified while bootstrapping the repository (2026-10-21):

- SecObserve version: >= 1.58.0 (inferred from chart history, not queried live). Helm chart 1.2.0 ships appVersion 1.58.0 (upstream
  `charts/secobserve/Chart.yaml` history) and cc-gitops deploys chart 1.2.2, which is newer. This
  covers the fields used (`vulnerability_id_aliases`, `repository_default_branch`, multi-value
  `current_status`).
- Trivy 0.76.0 honours `expired_at`, checked against `alpine:3.19`, CVE-2024-58251 on `busybox`:
  with `2020-01-01` the CVE is still reported, with `2099-01-01` it is suppressed. The service
  need not drop expired entries itself.
- Trivy matches a `purls` entry without qualifiers (`pkg:apk/alpine/busybox@1.36.1-r20`) against
  findings whose purl carries `?arch=...&distro=...`.
- `alpine:3.18` reports no vulnerabilities (end of life, no advisory data), so the plan's example
  image cannot be used for this check.

## Decision

We will run a Go service, `secobserve-trivyignore`, that compiles `.trivyignore.yaml` files from
SecObserve assessments and serves them to CI over GitHub OIDC. Rejected: replacing the Trivy gate
with SecObserve's security gate, VEX output (SecObserve maps `Risk accepted` to `affected`, which
Trivy does not suppress), and an upstream SecObserve change (possible later, once the endpoint has
proven itself).

```
GHA job ──OIDC JWT──▶ webhooks.management.p4e.io/trivyignore ──▶ secobserve-trivyignore ──Reader token──▶ SecObserve API
   │                                                                  │ in-memory cache, refreshed every 10 min
   └─ curl → .trivyignore.yaml → trivy --ignorefile
```

Go service, own Deployment in the SecObserve namespace (not a pod sidecar: upstream chart, independent lifecycle).

### API

`GET /v1/trivyignore[?product=<name>]` → `200 application/yaml`, `.trivyignore.yaml` format.

- Auth: `Authorization: Bearer <GitHub OIDC JWT>`. Verified against `https://token.actions.githubusercontent.com`
  JWKS; required `aud` = `secobserve-trivyignore`; `repository_owner` in allowlist
  (`pflege-de`, `pflege-de-labs`, `webcarelbj`).
- Product resolution: products whose `repository_prefix` == `https://github.com/<repository claim>`.
  - none → `404`; one → that product; several (monorepo) → `product` param required and must be in the set,
    else `400`/`403`.
- Cache older than `MAX_STALENESS` (default 24h) or never loaded → `503`.
- Response header `X-Cache-Age` (seconds) so CI can surface staleness.

### Compile rules

Per product, from observations on `product.repository_default_branch` with `current_status` in
`False positive`, `Not affected`, `Not security`, `Risk accepted` (one request, repeated `current_status` param),
non-empty `vulnerability_id` and non-empty `origin_component_purl`. Observations without purl are skipped and
counted: an `id`-only entry would suppress the CVE in every package, including unreviewed ones.
Each observation yields one entry for `vulnerability_id` plus one per `vulnerability_id_aliases[].alias`
(eases CVE↔GHSA mismatch). One entry per (`id`, purl), deduplicated keeping the latest `expired_at` (none = latest);
not merged by `id`, so each purl keeps its own expiry and statement.

```yaml
vulnerabilities:
  - id: CVE-2025-1234                     # vulnerability_id
    purls: [pkg:golang/x/y@v1.2.3]        # origin_component_purl
    expired_at: 2027-01-19                # risk_acceptance_expiry_date, Risk accepted only
    statement: "Not affected — https://secobserve.p4e.io/#/observations/<id>/show"
```

`expired_at` lets Trivy enforce expiry even when the served list is stale. Entries sorted for stable output.
Products without default branch → empty list (valid, suppresses nothing).

### Cache and failure modes

| Situation | Behaviour |
|---|---|
| SecObserve down, cache < 24h | serve cache, `X-Cache-Age` grows |
| SecObserve down, cache ≥ 24h or empty | `503` |
| Service/gateway down, invalid token, 5xx | CI runs Trivy **without** ignorefile (stricter), writes warning to step summary |
| 404 (repo has no product) | same as above, warning names the repo |

Cache is in memory; a restart during a SecObserve outage yields `503` until it recovers (accepted: stricter, not
weaker). Refresh fetches all products on a ticker; one product failing keeps its previous entry.

### Trust boundary and deployment

- The repository-to-product mapping trusts SecObserve's `repository_prefix`, which product owners can edit in
  SecObserve. They can thereby attach suppressions to a repository Terraform does not map to their product.
  Accepted: they can already assess those findings.
- `/metrics` shares the listener with `/v1/trivyignore`, and metric labels carry product names. The gateway
  route must expose only `/v1/trivyignore`.
- The service needs egress to `token.actions.githubusercontent.com` (OIDC discovery and JWKS).

### Credentials

- SecObserve: one user API token in a SecObserve user that belongs to a new authorization group
  `trivyignore` with role `Reader`, added to every product group via github-ops' default governance
  (`secobserve/groups.tf` `product_group_governance`). User + token created manually once (provider has no user
  resource), stored as Kubernetes secret via existing secret mechanism in `cc-gitops`.
- CI: none. Workflows add `permissions: id-token: write`.

### Observability

- `/livez`: process up. `/readyz`: HTTP server up **only** — not tied to SecObserve, otherwise an outage
  removes the pods whose cache is the point.
- OTEL metrics via `otelhttp` + Prometheus exporter (as `teamster`), scraped by ServiceMonitor:
  request count/latency by status, `cache_age_seconds` per product, `refresh_errors_total`,
  `ignore_entries` per product.
- Structured logs (`slog`): request repo, product, entry count; never the JWT.

### CI wiring

Shared composite action `pflege-de-labs/github-workflows/actions/trivyignore` (public, usable from both orgs):

1. `core.getIDToken('secobserve-trivyignore')` (via `actions/github-script` or the `ACTIONS_ID_TOKEN_REQUEST_*` env).
2. `curl --fail` → `.trivyignore.yaml`; on any failure delete file, `::warning::`, step summary note.
3. Output `ignorefile` path (empty on failure).

Gates pass it to Trivy (`TRIVY_IGNOREFILE` env, works with `trivy-action` regardless of its `trivyignores` input).

**ID alignment (pflege-de):** `go-full*` never uploads to SecObserve; observations there come from OSV (GHSA/GO-IDs)
and won't match Trivy CVE IDs. `go-full*` additionally uploads its Trivy result to SecObserve (non-gating, as in
`secobserve-image.yml`), so reviewers assess Trivy observations with matching IDs.

### Testing

- Unit: compile rules (status filter, expiry, purl omission, sort), product resolution (0/1/n, param), staleness.
- HTTP tests with a fake SecObserve (`httptest`) and locally signed JWTs against a test JWKS.
- Trivy 0.76.0 honours `expired_at` (verified 2026-10-21, see Facts), so the service does not drop expired entries.
- End-to-end: one labs repo with a known false-positive CVE; PR passes gate, entry visible in step summary.

### Open checks (follow-up plans C and D)

- OPEN: Gateway `webhooks.management.p4e.io` can route a new path and passes `Authorization` through.
- OPEN: `go-full` repos: `SO_API_TOKEN` present (only for repos with a `secobserve:` block).

## Consequences

- CI gates stop failing on vulnerabilities already reviewed in SecObserve; reviews stay in one place.
- A new service to run: Deployment, ServiceMonitor, a SecObserve Reader user and token, and a
  gateway route on `webhooks.management.p4e.io`.
- When the service is unreachable CI runs Trivy without an ignorefile: outages make gates
  stricter, never weaker.
- `go-full*` workflows must also upload Trivy results to SecObserve so reviewed IDs match.
