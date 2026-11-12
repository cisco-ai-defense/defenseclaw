# Agent Substrate API v1.0.0

This is the public control API of [Agent Substrate](https://github.com/agent-substrate/substrate)
(Apache-2.0, see LICENSE), used by the Substrate controller
(`internal/substrate/ateapi`, `internal/substrate/controller`) to read actors,
templates and atespaces and to write actor egress policies. DefenseClaw does
not ship Substrate.

- `api/ateapi/v1/ateapi.proto` is the upstream file, unmodified.
- `api/ateapi/v1/ateapi.pb.go` and `ateapi_grpc.pb.go` are generated from it by
  `make proto` (protoc 29.3, protoc-gen-go v1.36.6, protoc-gen-go-grpc v1.5.1;
  `make proto-check` keeps them in sync) from a patched copy: `make proto`
  runs `strip-options.awk` over the vendored file first (see below). The upstream `go_package` is remapped
  to this directory with an `M` option, so the build never imports the
  `go.ate.dev/substrate` module, whose go.mod needs Go 1.27 and pulls in the
  Kubernetes module graph. The descriptor path stays
  `api/ateapi/v1/ateapi.proto`, as upstream registers it. Upstream's own
  generated stubs, `source.go` and its declarative-validation code are not
  used; `internal/substrate/render` mirrors the admission checks DefenseClaw
  needs.

## The generation patch (GAP-0014)

Upstream declares its API annotations as extensions of the protobuf
descriptor options:

```proto
extend google.protobuf.MessageOptions { ResourceAnnotation resource = 50000; }
extend google.protobuf.MethodOptions  { MethodAnnotation method = 50000; }
```

The OpenShell SDK (`github.com/NVIDIA/OpenShell/sdk/go/proto/optionsv1`), which
the gateway already links, registers extension 50000 on the same descriptor
messages. Go's protobuf registry refuses the second registration at init, so a
binary linking both panics before `main`. `strip-options.awk` writes a copy
without the two `extend` blocks, the 50 `option (resource)` / `option
(method)` uses and the then-unused `descriptor.proto` import, and the stubs
are generated from that copy. Options are descriptor metadata only:
messages, fields, services, method names and the wire format are unchanged,
and ate-api-server never sends the annotations. The `ResourceAnnotation`,
`MethodAnnotation` and `Scope` messages remain as ordinary messages. The
filter fails on any other option or `extend` form, so a re-vendored file
with new annotations stops `make proto` instead of slipping through.
`ateapi.proto` here stays byte-identical to upstream (the hashes below).
`GOLANG_PROTOBUF_REGISTRATION_CONFLICT` is not used.

## Provenance (checked 2026-11-12)

| Check | Value |
|---|---|
| Release | v1.0.0, published 2026-11-05; tag `v1.0.0` (annotated, object `fd67f6204a7c287f658d080f6196ba1638744a10`) points at commit `b34fbee742906494b5eb4f1f36987176bf8770a4` |
| Source | a clone of `https://github.com/agent-substrate/substrate` at `v1.0.0` |
| Git blobs | each file's `git hash-object` equals the blob in the `v1.0.0` tag tree |
| protoc | `protoc-29.3-linux-x86_64.zip` sha256 `3e866620c5be27664f3d2fa2d656b5f3e09b5152b42f1bedbf427b333e90021a` |

| File | git blob | SHA-256 |
|---|---|---|
| `api/ateapi/v1/ateapi.proto` | `51ed7d1e32815a97b748b7da10df291f4bd371de` | `b5bb348f04b8f8d9f24c4c880e1f4176771e1556cfd0cff95a97ca8bee079722` |
| `LICENSE` (repository root) | `d645695673349e3947e8e5ae42332d0ac3164cd7` | `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30` |

## Updating

The tested range is `>=1.0.0 <1.1.0` (`substrate.supported_versions`).
Upstream's version-skew policy keeps 1.x patch and minor releases compatible
and forbids skipping a minor. A new minor release means re-vendoring this file
from its tag, repeating the checks above, `make proto` (which re-applies
the generation patch, or stops on a new annotation form), the controller unit
tests and a live round on the Substrate dev cluster.
