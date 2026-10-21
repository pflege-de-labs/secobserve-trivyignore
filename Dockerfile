# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e

# Building on the native platform and cross-compiling avoids QEMU emulation.
FROM --platform=$BUILDPLATFORM golang:1.27.2@sha256:5bc7f572bbaa98885a3a1fd9c0aa76b59e3e14e8628bfc316bbfd0c701e4818c AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod \
	--mount=type=cache,target=/root/.cache/go-build,id=go-build-$TARGETOS-$TARGETARCH \
	CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
	-trimpath \
	-ldflags "-s -w -X main.version=${VERSION}" \
	-o /out/secobserve-trivyignore ./cmd/secobserve-trivyignore

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

COPY --from=build /out/secobserve-trivyignore /usr/local/bin/secobserve-trivyignore

USER nonroot:nonroot
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/secobserve-trivyignore"]
