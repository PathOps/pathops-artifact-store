# pathops-artifact-store

The PathOps Artifact Store: a small Cell tool that keeps immutable, opaque
artifact bundles (Decisions 0047, 0061). It is written in Go and stores data on
the Cell's persistent volume.

The Tenant Control Plane stores the evidence of a failed Application build here
(a `BUILD_FAILURE_LOGS` bundle) and persists the returned reference; the Cell's
people download it directly from the store's public URL after signing in with
the Cell's Dex. The Tenant CP is never in the download path.

## Scope

- **PathOps depends on the `ArtifactStore` interface, not on S3.**
  - `internal/store` defines streaming `Put`, `Get`, `Stat` and `Delete` of
    immutable objects (bytes + media type + size + SHA-256 + small metadata +
    the object's Application and owner).
  - `internal/store/fsstore` is the first backend: a directory on a
    ReadWriteOnce volume.
  - An S3-compatible backend can implement the same interface later. The HTTP
    API, its clients and the Tenant CP would not change.
- **A Cell tool with a public URL** (`https://artifacts-<cell>.<domain>`),
  like Forgejo or zot, behind the Cell's ingress. Workloads never mount the
  volume; they use the API.
- **Bundles are opaque.** The store does not read inside a bundle. Producers
  choose its content; `tar.gz` is the recommended v1 format (see "Bundle
  format").

## API

```text
GET  /healthz             liveness; no authentication
PUT  /v1/objects/{key}    workload: stream an object in (immutable)
GET  /v1/objects/{key}    workload: stream an object out
HEAD /v1/objects/{key}    workload: describe an object (headers only)
GET  /objects/{key}       person: download (Dex SSO), Content-Disposition attachment
HEAD /objects/{key}       person: describe
GET  /oauth2/callback     person: the end of a Dex sign-in
```

There is no LIST and no DELETE: a reader always knows the reference it stored,
and retention is not part of v1.

### PUT

The body streams to a temporary file on the volume. The store computes its
SHA-256 while writing, syncs it and commits it with a rename.

| Header | Meaning |
|---|---|
| `Content-Type` | the bundle's media type, e.g. `application/gzip` (default `application/octet-stream`) |
| `X-PathOps-SHA256` | optional; the expected SHA-256 in lowercase hex; a mismatch is 422 and nothing is stored |
| `X-PathOps-Owner` | optional; the Dex subject of the Application's owner, who may download it |
| `X-PathOps-Metadata` | optional; a JSON object with at most 16 short string values, e.g. `{"type":"BUILD_FAILURE_LOGS"}` |

| Status | Meaning |
|---|---|
| `201` | `{ref, key, size, sha256, mediaType, metadata, createdAt, createdBy, application, owner}` |
| `200` | the same key already holds identical content of the same Application; a retry after a lost response is safe |
| `409` | the key holds different content: objects are immutable |
| `413` | larger than the maximum object size |

`ref` is `pathops-artifact://<store-name>/<key>`. The caller persists it and
reads through it later.

### GET and HEAD

- **GET** streams the object; **HEAD** returns only the headers:
  `Content-Type`, `Content-Length`, `X-PathOps-SHA256`, `ETag: "sha256:<hex>"`,
  `X-PathOps-Created-At`, `X-PathOps-Application` and `X-PathOps-Metadata`.

### Keys

A key has 1–16 segments separated by `/`, 1024 bytes at most.

- **Segments:** each segment starts with a letter or digit and may then contain
  `.`, `_` and `-` (128 bytes at most).
- **Raw path:** the key is read from the raw request path. Anything else is
  rejected with 400, not resolved: `..`, `.`, `//`, a percent-encoded character,
  a query or a leading `@`.
- **Filesystem confinement:** the backend also accesses its directory only
  through `os.Root`.
- **Application:** every object lives under `applications/<application id>/`.
  The Tenant CP writes a failed build's evidence at
  `applications/<application id>/deliveries/<delivery run id>/build-failure.tar.gz`.

## Authentication and authorization

### Workloads: Dex token exchange

A workload acts for exactly one Application and one key prefix inside it, with
a short-lived Artifact Store token issued by the Cell's Dex through its
generic workload token exchange (Decision 0065; Dex patch `0006`,
`workloadTokenExchange`, output `pathops-artifact-store`). There is no static
credential and no TokenReview.

The workload is a real one. Today that is the Tenant Control Plane, which
collects and stores a failed build's evidence itself. Later it will be the
environment Evidence Collector. No Application has an Artifact Store
ServiceAccount of its own.

```text
the workload's own ServiceAccount token (audience pathops-workload-exchange)
  + the Tenant CP's actor token, bound to it: one Application, operations,
    key prefix (e.g. applications/<id>/deliveries/<run>/)
  -> Dex workload token exchange (audience pathops-artifact-store)
  -> JWT: aud pathops-artifact-store, sub <the workload's ServiceAccount>,
          pathops_application <id>, pathops_operations [read, write],
          pathops_key_prefix applications/<id>/<scope>/, at most 5 minutes
  -> Authorization: Bearer <token>
```

Dex copies the `pathops_*` claims from the Tenant CP's authorization without
interpreting them. The store verifies the token locally:

- the EdDSA signature with Dex's artifact public key and its `kid`;
- the issuer and the audience;
- `exp`/`nbf` (30 s leeway) and a lifetime of at most 5 minutes;
- a UUID `pathops_application` and known operations;
- a `pathops_key_prefix` that is a directory strictly inside
  `applications/<that Application>/`.

Then:

- **PUT** needs `write` and a key under the token's key prefix. The object
  records the token's Application.
- **GET/HEAD** need `read`, a key under the token's key prefix, **and** an
  object that recorded that Application.

The recorded Application is the boundary. The key prefix is a second defense
and the token's scope: the Tenant CP scopes a failed build's token to its
DeliveryRun. Another Application's object, or another scope's, is 403 (prefix)
or 404 (recorded Application), never its content.

A Dex OIDC token, a registry token or a token of another Cell's Dex is not an
Artifact Store token (other key, issuer or audience): 401. So is a token
without a valid key prefix.

### People: Dex SSO

A person opens `https://artifacts-<cell>.<domain>/objects/<key>`. Without a
session the store redirects to the Cell's Dex: OpenID Connect Authorization
Code with PKCE (S256), `state` (bound to the browser by a cookie) and `nonce`,
as a confidential client. An existing Dex session answers without a password.
On the callback the store redeems the code, verifies the ID token (Dex's JWKS,
issuer, audience, expiry, nonce), keeps a server-side session for 8 hours and
sets `__Host-pathops-artifacts` (`Secure`, `HttpOnly`, `SameSite=Lax`, a random
value; no token in any URL or cookie). Sessions are in memory: after a restart
the next request signs in through Dex again.

v1 has one owner/admin per Cell (Decision 0061). An object is returned to:

- **the Cell admin**: the configured admin email, verified by Dex
  (`PATHOPS_ARTIFACT_STORE_ADMIN_EMAILS`, the Cell's `identity.adminEmail`);
- **the owner of the object's Application**: the Dex subject the writer
  recorded (`X-PathOps-Owner`).

Anyone else signed in gets 403. There are no other roles.

### Status codes

| Status | When |
|---|---|
| `302` | a person without a session (to Dex), or after the callback (to the object) |
| `401` | a workload token is missing, forged, expired, of another issuer or audience, or lacks a valid PathOps claim; a refused sign-in |
| `403` | the token lacks the operation or the key is outside its Application or key prefix; a person who is neither the admin nor the owner |
| `404` | no such object, or (workloads) an object of another Application |
| `503` | Dex cannot be reached for a sign-in |

Logs are JSON, one line per request: operation, key, subject, Application,
status, bytes and duration. A token, code or cookie is never logged.

## Configuration

Environment variables. An invalid value stops the start.

| Variable | Meaning |
|---|---|
| `PATHOPS_ARTIFACT_STORE_NAME` | the store's name in references (the Cell id) |
| `TLS_CERT_FILE`, `TLS_KEY_FILE` | the serving certificate (HTTPS only) |
| `PATHOPS_ARTIFACT_STORE_TOKEN_ISSUER` | the `iss` of Dex's artifact tokens, e.g. `https://dex-<cell>.<domain>/artifacts` |
| `PATHOPS_ARTIFACT_STORE_TOKEN_AUDIENCE` | default `pathops-artifact-store` |
| `PATHOPS_ARTIFACT_STORE_TOKEN_KEY_ID` | the `kid` of Dex's artifact key |
| `PATHOPS_ARTIFACT_STORE_TOKEN_PUBLIC_KEY_FILE` | its Ed25519 public key (PEM) |
| `PATHOPS_ARTIFACT_STORE_PUBLIC_URL` | `https://artifacts-<cell>.<domain>` (the OIDC redirect URI is `<url>/oauth2/callback`) |
| `PATHOPS_ARTIFACT_STORE_OIDC_ISSUER` | the Cell's Dex issuer |
| `PATHOPS_ARTIFACT_STORE_OIDC_CLIENT_ID` | the store's Dex client |
| `PATHOPS_ARTIFACT_STORE_OIDC_CLIENT_SECRET_FILE` | its secret |
| `PATHOPS_ARTIFACT_STORE_OIDC_CA_FILE` | optional; extra roots for Dex (the Cell CA) |
| `PATHOPS_ARTIFACT_STORE_ADMIN_EMAILS` | the Cell admin's email(s), comma-separated |
| `PATHOPS_ARTIFACT_STORE_DATA_DIR` | the volume (default `/data`: objects in `store/`) |
| `PATHOPS_ARTIFACT_STORE_MAX_OBJECT_BYTES` | default 4 GiB |
| `PATHOPS_ARTIFACT_STORE_REQUEST_TIMEOUT` | per request, default `30m` |
| `LISTEN_ADDRESS` | default `:8443` |

The store's ServiceAccount needs no Kubernetes permission.

## Bundle format

Measured for Slice 35 on a 165 MiB mixed evidence corpus (logs, Kubernetes
YAML, PNGs, a video, a binary), one thread:

| Format | Ratio | Compression CPU | Decompression CPU |
|---|---|---|---|
| `gzip -6` | 4.12 | 4.5 s | 0.58 s |
| `zstd -3` | 4.13 | 1.4 s | 0.35 s |
| `zstd -19` | 4.98 | 222 s | 0.30 s |

zstd is about 3x cheaper at the same ratio. gzip, however, is in every small
image and in the standard libraries of Go and Python. For typical bundles of
tens of MiB the difference is under a second.

`tar.gz` is therefore the v1 recommendation. The store records the media type
either way.

## Build, test and release

```bash
go test ./...            # includes a 256 MiB streaming test (skipped with -short)
go test -race ./...
go vet ./...
docker build -f ci/images/artifact-store/Dockerfile \
  --build-arg REVISION=$(git rev-parse HEAD) --build-arg VERSION=$(git rev-parse --short=12 HEAD) .
```

A tag `vX.Y.Z` publishes `ghcr.io/pathops/pathops-artifact-store:vX.Y.Z`
(`.github/workflows/release.yml`), consumed by digest. The Cell's bootstrap
core installs it as a normal Cell tool.
