# Standalone Sandbox Mode: Issues for Node.js/TypeScript Workloads

This document catalogs known issues when running Node.js or TypeScript tooling (e.g., OpenClaw and its plugins) inside the standalone sandbox binary without the cluster-mode gateway. Each issue includes the relevant source locations and severity.

## 1. DNS: `getaddrinfo` Fails Inside Network Namespace

**Severity:** Critical

The network namespace created by the sandbox (`crates/openshell-sandbox/src/sandbox/linux/netns.rs`, lines 53-169) sets up a veth pair, assigns IP addresses, and adds a default route, but does not configure any DNS resolver infrastructure. There is no `/etc/resolv.conf` written or bind-mounted into the namespace.

Worse, iptables rules installed by `install_bypass_rules` (`netns.rs`, lines 398-440) actively REJECT all UDP traffic, which includes DNS queries on port 53.

Node.js calls libc `getaddrinfo` via `dns.lookup()` before making HTTP connections. Inside the namespace, the resolver has no nameserver to query and any attempt to send UDP is immediately rejected. This affects:

- The `http`/`https` core modules (they resolve hostnames before connecting)
- `fetch()` even with proxy env vars set
- Any npm package that performs DNS lookups (database drivers, gRPC clients, WebSocket libraries)
- Explicit `dns.lookup()` or `dns.resolve()` calls in plugin code

The design intent is that all DNS resolution happens on the proxy's host side via `tokio::net::lookup_host` in `resolve_and_reject_internal` (`crates/openshell-sandbox/src/proxy.rs`, lines 1266-1291). The proxy URL itself (`http://10.200.0.1:3128`) is an IP literal and does not require DNS. However, any code path that performs DNS resolution outside the HTTP CONNECT flow will fail.

## 2. Not All Node.js HTTP Libraries Honor Proxy Environment Variables

**Severity:** High

The sandbox sets `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `http_proxy`, `https_proxy`, `grpc_proxy`, `NO_PROXY`, `no_proxy`, and `NODE_USE_ENV_PROXY=1` on the child process (`crates/openshell-sandbox/src/child_env.rs`, lines 8-21; injected in `crates/openshell-sandbox/src/process.rs`, lines 126-147).

`NODE_USE_ENV_PROXY=1` was introduced in Node.js v22+ and only applies to Node's built-in `http.request`, `https.request`, and `fetch`. Many widely used Node.js HTTP client libraries do not honor standard proxy environment variables:

- **`node-fetch`** — ignores proxy env vars; requires explicit `agent` configuration.
- **`got`** — ignores proxy env vars; requires a `tunnel` agent.
- **`ws` (WebSocket)** — does not support HTTP CONNECT proxying.
- **`undici`** — only honors proxy env vars with `NODE_USE_ENV_PROXY=1` on Node 22+.
- **gRPC-js** — uses its own connection logic; behavior with lowercase `grpc_proxy` varies by version.
- **Database drivers** (pg, mysql2, mongodb) — make direct TCP connections that never go through HTTP CONNECT.

Any library that bypasses the proxy will hit the iptables REJECT rules and get `ECONNREFUSED`.

## 3. TLS MITM CA Trust Is Partial

**Severity:** High

The sandbox generates an ephemeral CA at startup (`crates/openshell-sandbox/src/l7/tls.rs`, lines 43-64) and writes it to `/etc/openshell-tls/` (`tls.rs`, lines 220-237). Trust store environment variables are set on the child process (`crates/openshell-sandbox/src/child_env.rs`, lines 24-36):

- `NODE_EXTRA_CA_CERTS` — path to the standalone CA cert PEM (additive for Node.js)
- `SSL_CERT_FILE` — combined system + sandbox CA bundle (replaces default for OpenSSL/Go/Python)
- `REQUESTS_CA_BUNDLE` — combined bundle for Python `requests`
- `CURL_CA_BUNDLE` — combined bundle for curl

Issues for Node.js:

- `NODE_EXTRA_CA_CERTS` is only read once at Node.js process startup. Child processes spawned without this env var inherit no CA trust.
- Some Node.js/TypeScript HTTPS clients ignore `NODE_EXTRA_CA_CERTS` and use their own bundled root CAs (Electron-based tools, some gRPC implementations). These will produce `UNABLE_TO_VERIFY_LEAF_SIGNATURE` errors for proxied HTTPS connections.
- The system CA bundle is constructed from well-known Linux paths (`tls.rs`, lines 26-31). If none exist (minimal container or unusual distro), the combined bundle contains only the sandbox CA and upstream connections to real servers will fail verification — though the proxy itself uses `webpki-roots` independently (`tls.rs`, lines 201-211).

## 4. `sandbox` User Must Exist on Host

**Severity:** Medium

The sandbox binary validates that a `sandbox` user exists in `/etc/passwd` at startup (`crates/openshell-sandbox/src/lib.rs`, lines 1131-1154). If this user is not found, the process exits with a hard error.

In cluster mode, container images include this user. In standalone mode on a bare host, you must create it manually (e.g., `useradd sandbox`) before the sandbox binary will start.

Additionally, the privilege-dropping logic (`crates/openshell-sandbox/src/process.rs`, lines 353-459) falls back to `sandbox:sandbox` when running as root with no explicit user configured (lines 368-375). If the user does not exist, the child process spawn fails.

## 5. Root Privileges and System Packages Required

**Severity:** Medium

Creating a network namespace requires `CAP_NET_ADMIN` and `CAP_SYS_ADMIN`. The sandbox binary must run as root or with these capabilities. Failure is a hard error (`crates/openshell-sandbox/src/lib.rs`, lines 280-286).

The following system packages must be installed:

- **iproute2** — the `ip` command is used for namespace creation, veth setup, and routing (`netns.rs`, lines 593-633).
- **iptables** — used for bypass detection rules. Absence is non-fatal (degrades gracefully with a warning, `netns.rs`, lines 246-257), but fast-fail UX and bypass diagnostics are lost.
- **conntrack** — the `conntrack` iptables module is used for stateful packet filtering (`netns.rs`, lines 336-349). If the kernel module is not loaded, rule installation fails.

## 6. No Provider Secrets in Standalone Mode

**Severity:** Medium

Provider environment variables (API keys for LLM services) are fetched via gRPC from the gateway server (`crates/openshell-sandbox/src/lib.rs`, lines 190-203; `crates/openshell-sandbox/src/grpc_client.rs`, lines 189-205). In standalone mode, neither `sandbox_id` nor `openshell_endpoint` is set, so the provider env is an empty map.

The `SecretResolver` (`crates/openshell-sandbox/src/secrets.rs`, lines 14-31) only exists when provider env is non-empty. Without it, the proxy cannot perform credential injection — the mechanism where placeholder values in HTTP headers (e.g., `openshell:resolve:env:ANTHROPIC_API_KEY`) are rewritten to real secrets before forwarding upstream.

OpenClaw plugins that depend on the sandbox credential injection flow will have no API keys. Users must manually pass credentials via environment variables to the sandbox command, and those credentials will be visible inside the sandboxed process (defeating the isolation the proxy provides in cluster mode).

## 7. No Policy Hot-Reload

**Severity:** Low-Medium

The policy poll loop that watches for OPA policy updates only runs in gRPC/cluster mode (`crates/openshell-sandbox/src/lib.rs`, lines 572-621). It requires both `sandbox_id` and `openshell_endpoint`.

In standalone mode, the OPA policy is loaded once from `--policy-rules` and `--policy-data` files and never refreshed. Policy changes require restarting the sandbox process.

## 8. No Denial Aggregation or Policy Proposals

**Severity:** Low-Medium

The denial aggregator channel is only created when `sandbox_id` is present (`crates/openshell-sandbox/src/lib.rs`, lines 335-341). Without it:

- Denied network requests are logged but not aggregated into summaries.
- No policy proposals are generated from denied requests (the mechanistic mapper, `crates/openshell-sandbox/src/mechanistic_mapper.rs`, never runs).
- The UX that tells users "this binary tried to access X, here's a policy rule to allow it" is absent.

Debugging policy issues in standalone mode requires manually reading proxy log output and writing policy rules by hand.

## 9. macOS: Identity Binding Returns Blanket Deny

**Severity:** Critical (macOS-only)

On non-Linux platforms, the `evaluate_opa_tcp` function (`crates/openshell-sandbox/src/proxy.rs`, lines 820-838) returns a blanket `Deny` with reason "identity binding unavailable on this platform" for every CONNECT request. Process identity binding depends on `/proc` filesystem features that only exist on Linux.

The proxy is effectively unusable on macOS — all outbound network traffic through the proxy is denied. Additionally, the sandbox enforcement module (`crates/openshell-sandbox/src/sandbox/mod.rs`, lines 26-31) is a no-op on non-Linux, meaning Landlock and seccomp restrictions are not applied.

## 10. Landlock May Restrict Node.js Module Resolution

**Severity:** Low-Medium

Landlock filesystem sandboxing (`crates/openshell-sandbox/src/sandbox/linux/landlock.rs`, lines 15-81) restricts file access to explicitly allowed paths. The baseline read-only paths for proxy mode are `/usr`, `/lib`, `/etc`, `/app`, `/var/log`, and the read-write paths are `/sandbox` and `/tmp` (`crates/openshell-sandbox/src/lib.rs`, lines 875-879).

Node.js module resolution may access paths outside this allow list:

- Global npm modules in `/home/<user>/.npm` or `/home/<user>/.nvm`.
- `node_modules` resolution walks up directory trees — if dependencies are installed outside `/sandbox` or `/app`, resolution fails with `EACCES`.
- Native addon compilation needs `node-gyp` paths that may be outside allowed directories.

The Landlock compatibility mode defaults to `BestEffort` (`crates/openshell-sandbox/src/policy.rs`, lines 87-92), so on kernels without Landlock support the restriction silently does not apply. On supported kernels (Linux 5.13+), unexpected `EACCES` errors may surface.

## 11. Seccomp Allows `AF_INET`/`AF_INET6` but Blocks Other Domains

**Severity:** Low

The seccomp filter (`crates/openshell-sandbox/src/sandbox/linux/seccomp.rs`, lines 37-65) in proxy mode allows `AF_INET` and `AF_INET6` sockets but blocks `AF_PACKET`, `AF_BLUETOOTH`, `AF_VSOCK`, and (in block mode) `AF_NETLINK`.

This is generally compatible with Node.js. However, `AF_NETLINK` is allowed in proxy mode (line 41-44 — it is only blocked when `allow_inet` is false). Node.js does not typically use netlink sockets, so this is not expected to cause issues.

## Summary

| # | Issue | Severity | Standalone Impact |
|---|-------|----------|-------------------|
| 1 | DNS `getaddrinfo` fails inside netns | Critical | All hostname resolution breaks |
| 9 | macOS blanket deny | Critical | Proxy unusable on macOS |
| 2 | Not all Node.js HTTP libs honor proxy env | High | Libraries making direct connections fail |
| 3 | TLS MITM CA partial trust | High | Some HTTPS clients reject proxy certs |
| 4 | `sandbox` user must exist | Medium | Startup fails without manual setup |
| 5 | Root + system packages required | Medium | Deployment friction on bare hosts |
| 6 | No provider secrets | Medium | No credential injection for API keys |
| 7 | No policy hot-reload | Low-Medium | Must restart to change policy |
| 8 | No denial aggregation | Low-Medium | No automated policy proposals |
| 10 | Landlock vs Node module paths | Low-Medium | Possible `EACCES` on module resolution |
| 11 | Seccomp socket domain filtering | Low | Unlikely to affect Node.js |
