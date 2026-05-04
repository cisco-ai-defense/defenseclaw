# Sandbox Security Analysis

> **Status:** IMPLEMENTED (analysis complete, findings documented)

## Purpose

This document analyzes the security implications of integrating DefenseClaw
with OpenShell's standalone sandbox. It covers two perspectives:

1. **Ideal-state analysis** — what our current integration compromises relative
   to the full isolation OpenShell is designed to provide.
2. **Comparative analysis** — whether the sandbox deployment (Scenario B) is
   more or less secure than a host-only deployment (Scenario A), despite the
   compromises.

---

## Deployment Scenarios

### Scenario A: Host-only (no sandbox)

```
┌──────────────────────────────────────┐
│  Host                                │
│                                      │
│  OpenClaw ──ws──► DefenseClaw        │
│    │                │                │
│    │                ├─ API (lo:18790) │
│    │                ├─ LiteLLM (:4000)│
│    │                └─ Watcher       │
│    │                                 │
│    └──► filesystem, network, procs   │
│         (full host access)           │
└──────────────────────────────────────┘
```

OpenClaw and DefenseClaw run as the same user on the same machine. No isolation
boundary exists between them. DefenseClaw is defense-in-depth: it catches
mistakes before the agent acts, but a determined attacker with host access can
circumvent it.

### Scenario B: OpenShell standalone sandbox

```
┌──────────────────────────────────────────────┐
│  Host                                        │
│                                              │
│  DefenseClaw sidecar                         │
│    ├─ API (0.0.0.0:18790) ◄────────────┐    │
│    ├─ LiteLLM (lo:4000) ◄──────────────┤    │
│    ├─ Watcher                          │    │
│    └─ WS ──────────────────────┐       │    │
│                                │       │    │
│   ┌── veth 10.200.0.1 ────┐   │       │    │
│   │       iptables         │   │       │    │
│   │  ┌── sandbox ns ────┐ │   │       │    │
│   │  │  10.200.0.2      │ │   │       │    │
│   │  │                  │ │   │       │    │
│   │  │  OpenClaw ───────┼─┼───┘       │    │
│   │  │   └─ plugin ─────┼─┼───────────┘    │
│   │  │                  │ │                 │
│   │  │  Landlock+seccomp│ │                 │
│   │  └──────────────────┘ │                 │
│   └────────────────────────┘                 │
└──────────────────────────────────────────────┘
```

OpenClaw runs inside a kernel-isolated namespace. DefenseClaw runs on the host.
Communication crosses the sandbox boundary via a veth pair.

---

## Part 1: Ideal-State Analysis

These are the changes required to integrate DefenseClaw with the sandbox,
and the security properties each change compromises.

### High Risk

#### 1. iptables bypass for direct port access

**Change**: Injected iptables rules in the sandbox namespace to allow direct
TCP connections from the sandbox to host ports 18790 (sidecar API) and 4000
(LiteLLM).

```bash
ip netns exec $NS iptables -I OUTPUT 1 -p tcp -d 10.200.0.1 --dport 18790 -j ACCEPT
ip netns exec $NS iptables -I OUTPUT 2 -p tcp -d 10.200.0.1 --dport 4000 -j ACCEPT
```

**What it undermines**: OpenShell's entire network security model routes all
sandbox traffic through its HTTP CONNECT proxy at port 3128 for inspection and
policy enforcement. These rules create unmonitored channels from the sandbox
to the host, bypassing the proxy enforcement point. A compromised agent could
use these ports to reach host services without OpenShell's knowledge.

#### 2. Sidecar API bound to all interfaces

**Change**: Set `api_bind: 0.0.0.0` so the sandbox namespace can reach the
sidecar API across the veth pair.

**What it undermines**: The API was designed for localhost-only access. Binding
to all interfaces exposes it to the sandbox and potentially to other hosts on
the network. The only authentication is a trivially spoofable
`X-DefenseClaw-Client` header. A compromised agent could probe the API to
learn what rules exist and craft evasion payloads.

#### 3. LiteLLM master key exposed in sandbox config

**Change**: The `defenseclaw setup guardrail` command wrote the LiteLLM master
key into `/home/sandbox/.openclaw/openclaw.json`, which is readable inside the
sandbox.

**What it undermines**: A compromised agent can read the key and call
`http://10.200.0.1:4000/v1/chat/completions` directly with the master key,
bypassing all guardrail hooks (`pre_call`, `during_call`, `post_call`). The
guardrail becomes optional rather than mandatory.

### Medium Risk

#### 4. TLS disabled for non-loopback connection

**Change**: Added `tls: false` to the gateway config and changed
`GatewayConfig.TLS` from `bool` to `*bool` to support explicit override.

**What it undermines**: WebSocket traffic between the sidecar and OpenClaw
(tool calls, session events, device tokens) travels unencrypted. On a
point-to-point veth within a single machine, the practical risk is low. The
concern is misconfiguration: if this config is copied to a multi-host
deployment, tokens travel in cleartext over the network.

#### 5. Plugin ownership changed to bypass trust check

**Change**: Set plugin files to `root:root` to pass OpenClaw's ownership
verification, which rejected `sandbox`-owned files as "suspicious."

**What it undermines**: OpenClaw's ownership check prevents untrusted code from
loading as plugins. Changing ownership to root bypasses this control. If an
attacker could later modify the plugin files, they would execute arbitrary code
in the OpenClaw process.

#### 6. API key stored in plaintext file

**Change**: Wrote the OpenAI API key to `/root/.defenseclaw/.openai_key`
(mode 0600) because daemonized processes don't inherit interactive shell
environment variables.

**What it undermines**: The key is in a well-known path. If the host is
compromised, it is trivially extractable. Production deployments should use OS
keychain or a secrets manager.

### Low Risk

#### 7. Guardrail module on host filesystem

**Change**: Copied `defenseclaw_guardrail.py` to `/root/.defenseclaw/`.

**What it undermines**: If an attacker could modify this file on the host, they
could disable all guardrail checks or exfiltrate data through the LLM proxy.
Low risk because it requires host-level access, not sandbox escape.

#### 8. Plugin sidecar config in sandbox home

**Change**: Created `/home/sandbox/.defenseclaw/config.yaml` pointing to
`10.200.0.1:18790`.

**What it undermines**: Provides a roadmap for a compromised agent to know
where to probe. The information (host + port) is discoverable via network
scanning anyway, so the incremental risk is minimal.

#### 9. OpenShell policy YAML widened

**Change**: Added ports 4000 and 18790 to the `allow_local` network policy
endpoints.

**What it undermines**: Widens the declared policy. In practice, this had no
effect because iptables was the real enforcement gate (the YAML policy alone
did not open ports). Signals intent that the policy should be permissive for
these ports.

### The Fundamental Tension

DefenseClaw needs to sit between the sandbox and the outside world, but
OpenShell's sandbox is designed to prevent exactly that kind of interception.
The current integration fights the sandbox to enable governance. The result is
an enforcement layer (DefenseClaw) that is accessible from an environment
(the sandbox) that was designed to have no such access.

### Ideal Architecture

The integration should work with OpenShell's proxy model, not around it:

```
Sandbox ──► OpenShell proxy (3128) ──► DefenseClaw proxy (host) ──► internet
                                           │
                                           ├─ LiteLLM (guardrail hooks)
                                           ├─ Tool inspection
                                           └─ Audit logging
```

| Current approach | Ideal approach |
|---|---|
| iptables bypass for ports 18790, 4000 | All traffic through proxy (3128). DefenseClaw as upstream proxy. |
| LiteLLM key in sandbox config | Sandbox authenticates to DefenseClaw via WebSocket. DefenseClaw proxies LLM calls. No keys in sandbox. |
| `api_bind: 0.0.0.0` + spoofable header | Plugin uses existing WebSocket channel for `before_tool_call`. API stays on localhost. |
| Plugin ownership hack | Plugin signing with verifiable signatures. |
| `tls: false` override | TLS by default. Sandbox-specific override requires explicit flag like `insecure_veth_only: true`. |
| API on `0.0.0.0` | API on veth IP only (`10.200.0.1`) if cross-namespace access is needed. |

---

## Part 2: Comparative Analysis (A vs. B)

The ideal-state analysis shows where B falls short of its potential. This
section asks the more practical question: is B actually more or less secure
than A?

### What a compromised agent can do in each scenario

| Capability | Scenario A (host) | Scenario B (sandbox) |
|---|---|---|
| Read host files (~/.ssh, ~/.aws, source code) | Yes | No (Landlock) |
| Read DefenseClaw config and guardrail module | Yes | No (host filesystem) |
| Read the real OpenAI API key | Yes | No (stored on host) |
| Read the LiteLLM master key | Yes | Yes (in sandbox config) |
| Kill or modify DefenseClaw sidecar | Yes | No (separate namespace/user) |
| Modify guardrail module to disable checks | Yes | No (host filesystem) |
| Disable DefenseClaw via config change | Yes | No (host filesystem) |
| Call OpenAI directly, bypassing everything | Yes | No (no API key, restricted network) |
| Bypass guardrail hooks via LiteLLM master key | Yes | Yes |
| Reach sidecar API | Yes (localhost) | Yes (iptables hole) |
| Make arbitrary network connections | Yes (any host, any port) | No (3 ports on host veth + proxy) |
| Install system-wide backdoors | Yes | No (unprivileged, Landlock, seccomp) |
| Escalate privileges | Yes (same user as everything) | No (sandbox user, seccomp) |
| Pivot to other services | Yes | No (network namespace) |
| Execute dangerous syscalls | Yes | No (seccomp) |

### Is anything in A more secure than B?

**One item: sidecar API network exposure to third parties.**

In A, the sidecar API binds to `127.0.0.1` — only the local machine can reach
it. In B, we bound to `0.0.0.0`, meaning other machines on the network could
reach the unauthenticated API. This is new attack surface from entities other
than the agent.

This is not fundamental. Binding to `10.200.0.1` instead of `0.0.0.0`
restricts exposure to just the veth pair. It is a one-line config fix:

```yaml
gateway:
  api_bind: 10.200.0.1   # instead of 0.0.0.0
```

Beyond this fixable issue, nothing in A is more secure than B.

### Why the holes in B don't make it worse than A

Every hole we punched in B gives the sandboxed agent access to something the
host-based agent in A already had unrestricted access to:

| Hole in B | What it gives the agent | Already had in A? |
|---|---|---|
| iptables port 18790 | Reach sidecar API | Yes (localhost) |
| iptables port 4000 | Reach LiteLLM proxy | Yes (localhost) |
| LiteLLM master key in sandbox | Bypass guardrail hooks | Yes — plus real API key, plus ability to kill sidecar |
| `api_bind: 0.0.0.0` | Reach API from sandbox | Yes (same machine) |
| Plugin ownership to root | Load plugin code | Yes — could also modify the plugin |

The worst a compromised agent can do in B is call LiteLLM directly with the
master key to skip guardrail hooks. In A, the agent can do that AND read the
real OpenAI API key AND disable DefenseClaw entirely AND read all host
credentials.

### What B provides over A

Even with every compromise, the sandbox delivers:

1. **DefenseClaw is tamper-proof.** The agent cannot kill the sidecar, modify
   its config, or alter the guardrail module. In A, the agent can trivially
   disable all defenses.

2. **Blast radius is contained.** SSH keys, AWS credentials, source code, and
   other host files are inaccessible. In A, everything the user owns is
   exposed.

3. **Network is restricted.** Three ports on one IP versus the entire internet.
   The iptables holes only reach DefenseClaw services, not arbitrary hosts.

4. **Guardrail bypass is limited.** The agent can skip guardrail hooks via the
   LiteLLM master key, but cannot obtain the real API key. All LLM calls still
   flow through DefenseClaw's proxy, which logs them. In A, the agent can call
   OpenAI directly with no logging.

5. **Lateral movement is blocked.** No arbitrary process execution, no
   privilege escalation, no pivoting to other services on the host or network.

6. **Syscall restrictions.** Seccomp prevents dangerous system calls that could
   be used for container escape or kernel exploitation.

### Conclusion

**Scenario B is strictly more secure than Scenario A in every dimension**,
with one fixable exception (API bind address). The holes we punched reduce
isolation from "full cage" to "cage with controlled openings," but that is
still far stronger than "no cage at all."

The ideal-state analysis (Part 1) describes the gap between current B and
optimal B. The comparative analysis (Part 2) confirms that even current B
is a clear improvement over A.

The priority for hardening B is:

1. Integrate with OpenShell's proxy instead of bypassing iptables.
2. Remove LiteLLM master key from the sandbox — proxy LLM calls through the
   WebSocket channel.
3. Add real authentication to the sidecar API (mTLS or signed tokens).
4. Bind API to veth IP (`10.200.0.1`), not `0.0.0.0`.
5. Implement plugin signing.
