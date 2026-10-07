# Tetragon API v1.7.1

This is the gRPC API of [Tetragon](https://github.com/cilium/tetragon)
(Apache-2.0, see LICENSE), used by the Linux sensor helper
(`cmd/defenseclaw-sensor-helper`, `internal/sensor/tetragon`) to read a
Tetragon agent the customer already runs. DefenseClaw does not ship Tetragon.

- `api/v1/tetragon/*.proto` are the five upstream files, unmodified:
  `bpf.proto`, `capabilities.proto`, `events.proto`, `sensors.proto`,
  `tetragon.proto`. `eventlogservice.proto` is not needed and not vendored.
- `api/v1/tetragon/*.pb.go` and `sensors_grpc.pb.go` are generated from them by
  `make proto` (protoc 29.3, protoc-gen-go v1.36.6, protoc-gen-go-grpc v1.5.1;
  `make proto-check` keeps them in sync). The upstream `go_package` is remapped
  to this directory with `M` options, so the build never imports the
  `github.com/cilium/tetragon` modules, whose go.mod needs a `replace` and pulls
  in Tetragon's whole module graph. Upstream's hand-written `*.pb.json.go` and
  `codegen/` helpers are not used.

## Provenance (checked 2026-10-07)

| Check | Value |
|---|---|
| Release | v1.7.1, published 2026-08-25; tags `v1.7.1` and `api/v1.7.1` both point at commit `99ca93d98710b98a42551bf3c12613e32888885d` |
| Go checksum database | `github.com/cilium/tetragon/api v1.7.1 h1:egf4Tn1F6F7kXOrbp4/EMG/P14M0UJs2K9e43Yd+prU=` (sum.golang.org, matched by `go mod download`) |
| Source | the files were taken from that verified module zip |
| Git blobs | each file's `git hash-object` equals the blob in the `v1.7.1` tag tree |
| Release tarball (reference) | `tetragon-v1.7.1-amd64.tar.gz` sha256 `2f36a7bbb2b3d77a011383a01c8f804fe7761d934a76ff2fdf99ebad6f3e89ae` (GitHub asset digest) |

| File | git blob | SHA-256 |
|---|---|---|
| `bpf.proto` | `486c4ed32e0c756c89d32d81d7c76ac0b33b0536` | `b09c8b5ba2f0c6430bfbed95ec3b6251f40b07199258ebcf73212c2406685c21` |
| `capabilities.proto` | `032e16c815c62e81a6bfbedc2cea98afc6d82817` | `49057d368aec5f36e0007e8fd1654524cdf049afe6b1db57af9916bca6edfd25` |
| `events.proto` | `af17e6cec6201b7c61e1419ffe9aa94e423efa92` | `e35c2b3cc1e0e7eaf11fd89d55b8036bce3046c852a89382ab1b9e1babe86d4a` |
| `sensors.proto` | `de44295577e942ddcdbecaae6c25f9cfa495f5a3` | `f3840fd2dbc67079f0026b24456d58a205da8f8517ff24b40f307f0f0c0b2345` |
| `tetragon.proto` | `83e0a12cb00790a62eccf7b3648bcdf51c1ad194` | `24a95c84c94e7e10cdcece1899232cb1639f5f786baa8d255ddf74c4c433d348` |
| `LICENSE` (repository root) | `a2e486a803a5aba3295ad18ff7599db80c6cef3a` | `f096c31ac0fb2e66df5b7ec20049741ae15accd50c8cd4d100b4db6c9353f6aa` |

## Updating

Support is N and N-1 minor releases (1.7 and 1.6). A new minor release means
re-vendoring these files from the module zip at its `api/vX.Y.Z` tag, repeating
the checks above, `make proto`, and a live round on the RHEL 9 Tetragon host.
1.7.1 already changed the TracingPolicy schema (it removed
`returnArgAction: Post`), so a newer API is never assumed compatible.
