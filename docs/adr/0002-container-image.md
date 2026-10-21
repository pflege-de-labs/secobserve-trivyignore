# 0002. Container image built multi-stage onto distroless nonroot

* Status: Accepted
* Date: 2026-10-21

## Context

The service runs as a long-lived container and needs an image. It calls SecObserve over TLS and
holds no state on disk.

## Decision

We will follow [teamster ADR 0004](https://github.com/pflege-de-labs/teamster/blob/main/docs/adr/0004-container-image.md)
and not repeat its reasoning here.

* Two stages: a pinned `golang` builder produces a static binary (`CGO_ENABLED=0`), copied onto
  `gcr.io/distroless/static-debian12:nonroot`, pinned by digest.
* The process runs as `nonroot` (65532). Unlike teamster there is no data directory or volume.
* CI builds the image with the shared `image-build.yml` and, outside pull requests, uploads its
  SBOM and Trivy results to SecObserve with `secobserve-image.yml`.

## Consequences

* The image has no shell; diagnosis happens through logs.
* The base image must be rebuilt to pick up CA certificate updates.
