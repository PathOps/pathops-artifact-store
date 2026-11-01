# pathops-artifact-store

The PathOps Artifact Store: a small, Cell-internal HTTPS service that keeps
immutable, opaque artifact bundles (Decision 0047). It is written in Go and
stores data on the Cell's persistent volume.

Application workflows will use it from Slice 37 on. Each workflow Step Attempt
may store zero or one primary bundle; the Tenant Control Plane persists the
returned reference. Typical producers are a Tekton build packaging its reports
or the Evidence Collector packaging Kubernetes/Flux state.

## Scope

- **PathOps depends on the `ArtifactStore` interface, not on S3.**
  - `internal/store` defines streaming `Put`, `Get`, `Stat` and `Delete` of
    immutable objects (bytes + media type + size + SHA-256 + small metadata).
  - `internal/store/fsstore` is the first backend: a directory on a
    ReadWriteOnce volume.
  - An S3-compatible backend can implement the same interface later. The HTTP
    API, its clients and the Tenant CP would not change.
- **Cell-internal only.** A ClusterIP Service over HTTPS; there is no Ingress,
  public route or UI. Workloads never mount the volume; they use the API.
- **Bundles are opaque.** The store does not read inside a bundle. Producers
  choose its content; `tar.gz` is the recommended v1 format and `tar+zstd` is
  equally acceptable (see "Bundle format").

## API

```text
GET    /healthz                 liveness; no authentication, no API server call
POST   /v1/capabilities         privileged: issue an attempt-scoped capability
PUT    /v1/objects/{key}        stream an object in (immutable)
GET    /v1/objects/{key}        stream an object out
HEAD   /v1/objects/{key}        describe an object (headers only)
DELETE /v1/objects/{key}        privileged: remove an object
```

There is no LIST: a reader always knows the reference it stored.

### PUT

The body streams to a temporary file on the volume. The store computes its
SHA-256 while writing, syncs it and commits it with a rename.

Request headers:

| Header | Meaning |
|---|---|
| `Content-Type` | the bundle's media type, e.g. `application/gzip` (default `application/octet-stream`) |
| `X-PathOps-SHA256` | optional; the expected SHA-256 in lowercase hex; a mismatch is 422 and nothing is stored |
| `X-PathOps-Metadata` | optional; a JSON object with at most 16 short string values, e.g. `{"format":"tar+gzip"}` |

Responses:

| Status | Meaning |
|---|---|
| `201` | `{ref, key, size, sha256, mediaType, metadata, createdAt, createdBy}` |
| `200` | the same key already holds identical content; this makes a retry after a lost response safe |
| `409` | the key holds different content: objects are immutable |
| `413` | larger than the maximum object size |

`ref` is `pathops-artifact://<store-name>/<key>`. The caller persists it and
reads through it later; it never reconstructs a key from a naming convention.

### GET and HEAD

- **GET** streams the object.
- **HEAD** returns only the headers: `Content-Type`, `Content-Length`,
  `X-PathOps-SHA256`, `ETag: "sha256:<hex>"`, `X-PathOps-Created-At` and
  `X-PathOps-Metadata`.

### Keys

A key has 1–16 segments separated by `/`, 1024 bytes at most.

- **Segments:** each segment starts with a letter or digit and may then contain
  `.`, `_` and `-` (128 bytes at most).
- **Raw path:** the key is read from the raw request path. Anything else is
  rejected with 400, not resolved: `..`, `.`, `//`, a percent-encoded character,
  a query or a leading `@`.
- **Filesystem confinement:** the backend also accesses its directory only
  through `os.Root`.

The write-time convention, chosen by the Tenant Control Plane, is:

```text
applications/{applicationId}/runs/{runId}/steps/{stepId}/attempts/{attempt}/<file>
```

## Authentication and authorization

Workloads use their **Kubernetes ServiceAccount identity**. There is no static
shared credential.

1. **Token.** The workload projects a ServiceAccount token with the audience
   `pathops-artifact-store` (600 s) and sends it as
   `Authorization: Bearer <token>`.
2. **Validation.** The store sends a TokenReview with that audience to the
   Kubernetes API server. The API server checks:
   - signature;
   - expiry;
   - audience;
   - for a Pod-bound token, that the Pod still exists (a deleted Pod's token is
     refused within about 10 s).

   Only `system:serviceaccount:<ns>:<name>` identities are accepted. Human
   OIDC tokens are not workload credentials.
3. **Privileged identities** (`PATHOPS_ARTIFACT_STORE_ADMINS`, the Tenant
   Control Plane) may do everything.
4. **Any other workload** also needs `X-PathOps-Capability`. The privileged
   identity requests it with `POST /v1/capabilities`, sending `subject`,
   `prefix`, `operations` (`put`, `get`, `stat`) and `ttlSeconds`.
   - **Signature:** the store signs it with HMAC-SHA256 using a key that only
     it holds, on the volume.
   - **Binding:** it is bound to `subject`. It only works together with a valid
     token of exactly that ServiceAccount, so it can travel as an ordinary
     parameter.
   - **Scope:** it allows its operations only under its prefix.
   - **Application identity:** the Application is never a value the workload
     supplies. The privileged identity derives the prefix from the
     Application/Run/Step/Attempt it executes.

Status codes:

| Status | When |
|---|---|
| `401` | the token is missing, forged, expired, wrong-audience or of a deleted Pod |
| `403` | the capability is missing, invalid, expired, for another subject, or does not cover the key or operation; or a non-privileged caller tries `DELETE` |
| `503` | the API server cannot be asked |

Logs are JSON, one line per request: operation, key, subject, status, bytes,
duration and process peak RSS. A token or capability is never logged.

## Configuration

Environment variables. An invalid value stops the start.

| Variable | Meaning |
|---|---|
| `PATHOPS_ARTIFACT_STORE_NAME` | the store's name in references (the Cell id) |
| `PATHOPS_ARTIFACT_STORE_ADMINS` | privileged ServiceAccount subjects, comma-separated |
| `TLS_CERT_FILE`, `TLS_KEY_FILE` | the serving certificate (HTTPS only) |
| `PATHOPS_ARTIFACT_STORE_DATA_DIR` | the volume (default `/data`: objects in `store/`, the capability key in `capability.key`) |
| `PATHOPS_ARTIFACT_STORE_AUDIENCE` | default `pathops-artifact-store` |
| `PATHOPS_ARTIFACT_STORE_MAX_OBJECT_BYTES` | default 4 GiB |
| `PATHOPS_ARTIFACT_STORE_MAX_CAPABILITY_TTL` | default `6h` |
| `PATHOPS_ARTIFACT_STORE_REQUEST_TIMEOUT` | per request, default `30m` |
| `LISTEN_ADDRESS` | default `:8443` |

The store's ServiceAccount needs only `create` on `tokenreviews`.

## Bundle format

Measured for Slice 35 on a 165 MiB mixed evidence corpus (logs, Kubernetes
YAML, PNGs, a video, a binary), one thread:

| Format | Ratio | Compression CPU | Decompression CPU |
|---|---|---|---|
| `gzip -6` | 4.12 | 4.5 s | 0.58 s |
| `zstd -3` | 4.13 | 1.4 s | 0.35 s |
| `zstd -19` | 4.98 | 222 s | 0.30 s |

zstd is about 3x cheaper at the same ratio. gzip, however, is in every small
image (busybox and alpine have no `zstd`) and in the standard libraries of Go
and Python. For typical bundles of tens of MiB the difference is under a
second.

`tar.gz` is therefore the v1 recommendation. The store records the media type
either way.

## Build and test

```bash
go test ./...            # includes a 256 MiB streaming test (skipped with -short)
go test -race ./...
go vet ./...
docker build -f ci/images/artifact-store/Dockerfile \
  --build-arg REVISION=$(git rev-parse HEAD) --build-arg VERSION=$(git rev-parse --short=12 HEAD) .
```

The release is `ghcr.io/pathops/pathops-artifact-store:<revision>`, consumed by
digest. The lab installs and accepts it with
`scripts/artifact-store.sh <cell> install|verify|acceptance` in
`PathOps/pathops-dev-cell-bootstrap`.
