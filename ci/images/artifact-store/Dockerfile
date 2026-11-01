# syntax=docker/dockerfile:1
# The Artifact Store image; context = repository root. The build adds
# org.opencontainers.image.revision (the commit) and .version (its first 12
# characters) as build arguments; the release is published by revision tag and
# consumed by digest.

FROM docker.io/library/golang:1.26.9-alpine@sha256:3082400e369fa24d5fc60bca20edab3f6d604e0c5a690ec66b295eff4dd87ade AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/artifact-store ./cmd/artifact-store

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
ARG REVISION=unknown
ARG VERSION=unknown
LABEL org.opencontainers.image.source="https://github.com/PathOps/pathops-artifact-store" \
      org.opencontainers.image.title="pathops-artifact-store" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.version="${VERSION}"
COPY --from=build /out/artifact-store /usr/local/bin/artifact-store
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/artifact-store"]
