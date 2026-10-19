<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Private host bridge protocol

This Go package implements framing, typed message validation and ordered
conversation admission. No Rust peer, native adapter, credential broker or
process supervisor is wired to it yet. It starts no listener, process,
goroutine or queue and does not enable customer AXIS execution.

The host owns the complete session and policy records. `Binding` contains
correlation digests only. Neither a frame nor a digest reconstructs policy
authority, verifies an artifact, grants credentials or replaces `LaunchGate`.
The trusted adapter must independently establish workspace/executable custody,
translate every resolved policy component and bind its exact evidence before
launch. The helper must receive no provider credentials or resolver snapshot.
Wire path checks establish only absolute-path syntax, not alias/reparse/ADS
admission. Both trusted adapter and native helper must enforce their platform
path/custody rules before using those paths; the hash never authorizes a path.
`Preparation` is trusted-host-helper input, not data for the contained child.
A separate deliberately restricted child plan remains to be implemented.

## Wire format

Each frame is a four-byte unsigned big-endian payload length followed by one
UTF-8 JSON object, at most 256 KiB. No compression, implicit defaults, explicit
null, extra JSON values or unknown fields are accepted. Field names must match
their exact JSON tags. Duplicate keys, case aliases, invalid UTF-8, unpaired
UTF-16 escapes, NUL strings and excessive depth/token counts refuse.
All fields without `omitempty` are required, including false/zero result
fields and explicit empty environment/filesystem arrays. Stdio is base64
binary data, up to 16 KiB per frame. Literal empty arguments, Unicode, quotes
and shell metacharacters are preserved as data. V1 admits explicit offline
preparation only; broker transport needs a separately qualified protocol.

`PreparationHash` is SHA256 over this exact binary encoding:

1. ASCII `defenseclaw-mxc-preparation-v1` followed by one NUL byte.
2. Backend string, argv string list, environment count and its ordered
   name/value string pairs, workdir string, then read/write/deny string lists.
3. One byte `1` for offline. Then one byte for terminal presence: `0`, or `1`
   followed by rows and columns as unsigned big-endian 16-bit integers.
4. Timeout milliseconds and aggregate output limit as unsigned big-endian
   32-bit integers.

A string is a big-endian unsigned 32-bit UTF-8 byte length plus those exact
bytes. A string list is its big-endian unsigned 32-bit count followed by its
ordered strings. Counts/lengths are validated before hashing. The resulting
digest uses `sha256:` followed by lowercase hexadecimal. This encoding is
independent of either language's JSON serializer.

## Ordering and owner obligations

Sequences start at one and increase by exactly one per direction. Host request
IDs are positive and strictly increasing. Prepared/started/destroyed replies
refer to their triggering request. Output and the single exited event always
refer to launch, including when wait/cancel travels in the other direction.
At an already exited helper, late bounded input/EOF/resize/wait/cancel controls
are no-ops; they cannot recreate a process. The eventual native handler must
honor that contract. Destroy still requires its own cleanup acknowledgement.

The conversation stores only metadata and counters. It rejects replay,
foreign bindings, invalid phase changes and output beyond the admitted
aggregate cap. EOF or malformed/partial I/O permanently poisons the decoder;
partial writes permanently poison the encoder. The owner must admit each
outbound command before writing and each decoded event before dispatching it.
An error must revoke grants and contain/wait the exact owned helper/workload.
An admitted `failed` event also closes the conversation and requires that
cleanup; successful protocol admission never means successful execution.
These protocol checks do not establish native process-tree cleanup.

Encoders/decoders perform synchronous bounded I/O without read-ahead. The
supervisor must set deadlines or close its owned pipes on cancellation,
backpressure or peer death. This package does not interrupt an arbitrary
blocking `io.Reader`/`io.Writer`. It also does not enforce elapsed execution
time; the native supervisor must enforce the admitted deadline and cleanup.
One owner must serialize sequence assignment, conversation admission and the
corresponding frame write together. Encoder locking alone cannot preserve that
order across independent callers that admit and write in separate steps.
