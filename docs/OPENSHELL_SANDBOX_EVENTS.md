# OpenShell Sandbox: Security Controls and Observability

What protections the OpenShell sandbox provides, what it can tell you when
something happens, and what it can't.

> **Scope**: This covers the NVIDIA `openshell-sandbox` binary as-is.
> DefenseClaw orchestrates it but does not modify it.

---

## Security Controls

The sandbox enforces three independent security boundaries around the
sandboxed process. Each operates at a different level of the stack.

### Filesystem Isolation (Landlock)

Restricts which files and directories the sandboxed process can access.
Paths are partitioned into read-only and read-write sets via policy. Any
access outside those sets is denied by the kernel. The sandboxed process
cannot read, write, or even stat paths it hasn't been granted.

### Syscall Filtering (Seccomp)

Blocks the creation of network sockets for dangerous address families
(`AF_PACKET`, `AF_BLUETOOTH`, `AF_VSOCK`). When the network mode restricts
connectivity, also blocks `AF_INET`, `AF_INET6`, and `AF_NETLINK` socket
creation. This prevents the sandboxed process from opening raw sockets or
creating network connections outside the proxy.

### Network Proxy (HTTP CONNECT + Network Namespace)

All network traffic from the sandboxed process is forced through an HTTP
CONNECT proxy. The sandbox creates an isolated network namespace with a
veth pair — the only path out is through the proxy.

The proxy provides:

- **Per-connection policy evaluation** — OPA (Rego) rules evaluate every
  connection against (destination, binary, ancestors) with process identity
  resolved via `/proc/net/tcp`.
- **L7 inspection** — For configured endpoints, the proxy terminates TLS,
  parses HTTP requests, and evaluates each request (method + path) against
  L7 policy rules. Enforcement can be `enforce` (block) or `audit` (log only).
- **SSRF defense** — DNS resolution results are checked against internal IP
  ranges (RFC 1918, loopback, link-local) and optional CIDR allowlists.
  Connections to internal addresses are rejected.
- **Binary integrity** — Trust-on-first-use (TOFU) hash verification of the
  connecting binary and its process ancestor chain.
- **Bypass detection** — iptables rules in the sandbox namespace LOG and
  REJECT any traffic that attempts to bypass the proxy. A background monitor
  reads kernel log entries and reports bypass attempts.
- **Credential injection** — Secrets are injected into HTTP headers at the
  proxy layer so the sandboxed process never sees real credentials.

---

## Observability

### What You Can See

The network proxy is the **only observable enforcement surface**. Every
network connection attempt — allowed, denied, or bypassed — is logged with
structured fields including destination, process identity, policy match,
and deny reason.

| Event | What happened |
|---|---|
| Connection denied | Process tried to reach a destination not permitted by policy |
| Connection allowed | Process connected to a permitted destination |
| SSRF blocked | DNS resolved to an internal/private address |
| L7 request denied | HTTP request (method + path) violated L7 policy |
| L7 request audited | HTTP request flagged by policy but not blocked (audit mode) |
| Bypass attempt | Process tried to make a direct connection outside the proxy |
| Credential injection | Proxy rewrote HTTP headers to inject real secrets |

Each event includes:

| Field | Description |
|---|---|
| `dst_host` / `dst_port` | Where the connection was going |
| `binary` | Full path of the binary that initiated the connection |
| `binary_pid` | PID of the connecting process |
| `ancestors` | Process tree ancestor chain (e.g. `bash -> python -> curl`) |
| `action` | `allow`, `deny`, or `reject` |
| `policy` | Name of the matched policy rule (or `-` if none matched) |
| `reason` | Why the connection was denied (empty on allow) |
| `l7_action` / `l7_target` | HTTP method and path (L7 events only) |
| `l7_decision` | `allow`, `deny`, or `audit` (L7 events only) |

### What You Cannot See

Landlock and seccomp violations are **invisible to userspace**. When the
kernel blocks a filesystem access or a socket syscall, the sandboxed process
receives a permission error (`EPERM` / `EACCES`) but nothing is logged and
no notification is sent. There is no callback mechanism and no way for the
sandbox supervisor to know a violation occurred.

Detecting these would require Linux's audit subsystem (`auditd`), which
needs root and kernel audit rules — out of scope for the standalone
deployment.

| Control | Violations observable? |
|---|---|
| Filesystem (Landlock) | No — silent kernel denial |
| Syscall (Seccomp) | No — silent kernel denial |
| Network proxy | Yes — full structured logging |

---

## Deny Reasons

When the proxy blocks a connection, the `reason` field explains why:

| Reason | What it means |
|---|---|
| `no matching policy` | No OPA rule permits this (host, port, binary) combination |
| `binary integrity check failed` | Binary hash doesn't match the TOFU record |
| `ancestor integrity check failed` | An ancestor process in the call chain failed TOFU |
| `<host> resolves to internal address` | DNS resolved to a private/loopback IP (SSRF) |
| `not in allowed_ips` | Resolved IP is outside the policy's CIDR allowlist |
| `direct connection bypassed HTTP CONNECT proxy` | Traffic went around the proxy |
| `entrypoint process not yet spawned` | Connection attempted before sandbox fully started |
| `policy evaluation error` | OPA engine failed to evaluate the rule |
| (custom L7 reason) | Per-endpoint deny reason defined in L7 Rego policy |

---

## How Events Are Produced

### Structured Tracing (always active)

Every proxy decision emits a structured log event with a message label
and the fields listed above. The key labels are:

| Label | Meaning |
|---|---|
| `CONNECT` | L4 tunnel decision — connection allowed or denied |
| `CONNECT_L7` | L4 tunnel established with L7 inspection to follow |
| `FORWARD` | Plain HTTP forward proxy decision |
| `L7_REQUEST` | Per-request L7 policy evaluation result |
| `BYPASS_DETECT` | Direct connection attempt detected outside the proxy |
| `HTTP_REQUEST` | HTTP passthrough with optional credential injection |

These events go to stdout and (when available) to a rolling log file.
In the standalone systemd deployment, stdout is captured by journald.

### Denial Aggregator (always active when proxy is active)

The proxy feeds every denial into an in-process aggregator that
deduplicates by `(host, port, binary)`. It maintains running counters,
first/last seen timestamps, and samples of L7 requests. The aggregator
periodically flushes summaries upstream via gRPC (`SubmitPolicyAnalysis`).

This gives a compact, deduplicated view of denial patterns rather than
one event per blocked connection.

### LogPush gRPC (optional)

When configured with a sandbox ID and server endpoint, the sandbox
streams all tracing events as typed protobuf messages (`SandboxLogLine`)
to a gRPC server via client-streaming RPC. Each message carries the
same structured fields as the tracing events, but in a `map<string, string>`
rather than text.

This provides the most structured data available from the sandbox, but
requires a gRPC server on the receiving end. Not currently active in the
standalone deployment.

### OCSF Event Framework (not yet active)

OpenShell has a full OCSF v1.7.0 (Open Cybersecurity Schema Framework)
implementation with event classes for Network Activity, HTTP Activity,
Process Activity, Detection Finding, and more. The types, formatters, and
tracing layers are implemented but **not wired into the sandbox binary**.
When activated upstream, this would provide machine-parseable OCSF JSONL
output.

---

## Where Events Are Available

In the standalone systemd deployment:

| Source | What you get | Format |
|---|---|---|
| journald | All proxy events at info level and above | Human-readable key=value text |
| Log file (`/var/log/`) | Same content, daily rotation, 3 files | Same text format, no ANSI |
| LogPush gRPC | All events as typed protobuf messages | `SandboxLogLine` protobuf with `fields` map |
| SubmitPolicyAnalysis gRPC | Aggregated denial summaries | `DenialSummary` protobuf with counts and L7 samples |
| OCSF JSONL | Not yet available | Would be OCSF v1.7.0 JSONL |

The sandbox does **not** emit OpenTelemetry. OTel integration is the
responsibility of the consuming system.
