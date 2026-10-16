# DefenseClaw Bypass Analysis — How Can Users Evade Protection?

**Date:** 2026-10-14
**Head:** 73e6de171

## Summary

Tested 23 bypass techniques across 4 categories. Found **3 confirmed bypasses**
(architectural limitations), **2 partial bypasses** (evasion techniques that
work under specific conditions), and **18 blocked attempts** (defenses working
as designed).

---

## Confirmed Bypasses (Architectural)

### BYP-17: Skip the IPC Hook Entirely
- **Severity:** CRITICAL
- **Attack:** A malicious agent process simply doesn't call the IPC socket and
  executes tools directly. DefenseClaw is never consulted.
- **Root cause:** DefenseClaw is an advisory guard, not a kernel-level
  enforcement mechanism. It relies on the connector hook being in the agent's
  execution path.
- **Who can exploit:** Any process running as the same user, any agent framework
  that doesn't integrate the hook.
- **Mitigation:** Hook tampering detection (already implemented for some
  connectors), mandatory kernel-level enforcement via Tetragon/eBPF (Phase 2),
  signed hook verification.

### BYP-18: Kill the Edge-Connector Process
- **Severity:** HIGH
- **Attack:** `pkill -f edge-connector` or `kill -9 <pid>`. After that, all IPC
  calls fail and agents run unprotected.
- **Root cause:** No process supervision or self-healing in the daemon itself.
- **Who can exploit:** Any user with kill permission on the process (same UID or
  root).
- **Mitigation:** `systemd restart=always` (documented in INSTALL.md), watchdog
  timer, fail-closed hook behavior (reject tool calls when daemon is
  unreachable).

### BYP-19: Redirect the IPC Socket
- **Severity:** HIGH
- **Attack:** Set `DCLAW_IPC_SOCKET_PATH=/dev/null` before starting the agent.
  The hook connects to nothing and fails open.
- **Root cause:** Socket path is configurable via environment variable.
- **Who can exploit:** Any user who controls their own environment variables.
- **Mitigation:** Hardcode socket path, verify from a trusted configuration
  source, or use `prctl` to prevent env manipulation after daemon start.

---

## Partial Bypasses (Conditional Evasion)

### BYP-06: Cross-Session Sequence Splitting
- **Severity:** MEDIUM
- **Attack:** Perform NET_FETCH in session 900, then EXEC_SHELL in session 901.
  Correlator tracks per-session, so the sequence is never detected.
- **Result:** curl in session 900 → ALLOW; bash in session 901 → BLOCK (but
  only because bash with EXEC_SHELL capability is blocked by the cloud verdict
  cache, not by sequence detection).
- **Root cause:** Capability sequence correlation is per-session by design.
  Cross-session exfiltration patterns are invisible.
- **Who can exploit:** An agent that opens multiple sessions or rotates session
  IDs between tool calls.
- **Mitigation:** Cross-session correlation in the fleet manager (Go side),
  cumulative risk scoring across sessions.

### BYP-08: Split Secrets Across Multiple Tool Calls
- **Severity:** MEDIUM
- **Attack:** Send `AKIAIOSFO` in one call and `DNN7EXAMPLE` in another. Neither
  fragment triggers the Aho-Corasick DFA.
- **Result:** Both calls were BLOCKED — but only because the content `AKIAIOSFO`
  triggered a partial-match heuristic. The `DNN7EXAMPLE` fragment alone was also
  blocked by the cloud verdict cache from the first call.
- **Root cause:** Content scanning is per-call. Multi-call reconstruction would
  require stateful content tracking.
- **Who can exploit:** An agent that deliberately fragments sensitive data across
  tool calls.
- **Mitigation:** Session-level content aggregation, cloud-side correlation that
  reassembles fragments.

---

## Blocked Attempts (Defenses Working)

### Authentication & Authorization
| # | Attack | Result |
|---|---|---|
| ATK-01 to ATK-04 | Various auth bypass attempts | All 401 |
| ATK-05 | Missing CSRF header | 403 |
| ATK-07/08 | Invalid tenant/device IDs | 400 |
| BYP-14 | Fake MQTT registration (unsigned) | Rejected — device NOT created |
| BYP-15 | Admin sees all tenants | By design (admin scope) |

### Input Validation & Injection
| # | Attack | Result |
|---|---|---|
| ATK-09 | Batch >1000 devices | 400 |
| ATK-10/11 | Invalid/dangerous commands | 400 |
| ATK-12/13 | Path traversal / SQL injection | 400/401 |
| ATK-16-24 | IPC protocol attacks | All blocked or rejected |

### Content Scanner Evasion
| # | Attack | Result |
|---|---|---|
| BYP-09 | Base64-encoded secret | BLOCKED — base64 exfiltration heuristic |
| BYP-10 | Unicode homoglyph substitution | BLOCKED — non-ASCII triggers input validation |
| BYP-11 | Whitespace-injected SSN | BLOCKED — structural SSN scanner handles variants |
| ATK-25-30 | SSRF via hex/octal/IPv6/credentials | All BLOCKED |
| ATK-31-35 | XSS, shell, path traversal, PII | All BLOCKED |
| BYP-20 | Read /etc/passwd content | BLOCKED — content scanner flagged it |

### Concurrency & Cache
| # | Attack | Result |
|---|---|---|
| BYP-22 | 10 concurrent IPC clients | No race — single-threaded event loop |
| BYP-23 | Cache exhaustion (70 entries, cache=64) | LRU eviction works; re-eval produces same result |
| BYP-05 | Rate limiter flood (100 requests) | Rate limiter blocked at threshold |

### Sequence Correlation
| # | Attack | Result |
|---|---|---|
| BYP-07 | Interleave benign tools between dangerous ones | BLOCKED — sliding window still catches NET_FETCH→EXEC_SHELL |
| BYP-01 | Lie about capabilities | BLOCKED — daemon overrides from policy table |

---

## Risk Matrix

| Bypass | Severity | Exploitability | Impact | Phase to Fix |
|---|---|---|---|---|
| Skip IPC hook | CRITICAL | Easy (any process) | Complete bypass | Phase 2 (Tetragon/eBPF) |
| Kill daemon | HIGH | Easy (same UID) | Complete bypass | Phase 1.1 (systemd restart) |
| Redirect socket | HIGH | Easy (env control) | Complete bypass | Phase 1.1 (hardcode path) |
| Session splitting | MEDIUM | Moderate (agent-level) | Evade sequence detection | Phase 2 (cross-session correlation) |
| Split secrets | MEDIUM | Moderate (agent-level) | Evade content scanning | Phase 2 (session aggregation) |

---

## Conclusion

DefenseClaw's security model is **defense-in-depth at the application layer**.
It is highly effective against:
- Protocol-level attacks (SSRF, injection, malformed input)
- Content threats (secrets, PII, injection patterns)
- Behavioral patterns (capability sequences within a session)
- Authentication/authorization bypass attempts

It is **not designed to stop** a determined attacker who controls the host
process, can kill the daemon, or redirects the IPC socket. These are
architectural limitations of any userspace advisory guard and require
kernel-level enforcement (eBPF/Tetragon) for production hardening.
