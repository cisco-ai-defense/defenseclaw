# Engineering specifications

This directory holds the engineering specifications that are part of the
repository. Each one has a `README.md` and, where written, `requirements.md`,
`design.md` and `tasks.md`. The code and its tests are the source of truth;
a spec records the intended contract and the open work.

| Spec | Scope | Status |
| --- | --- | --- |
| [001](001-windows-deterministic-build/README.md) | Windows deterministic-build support for the AVC packaging flow | Implemented |
| [002](002-windows-avc-packaging/README.md) | AVC-driven Windows enterprise packaging: the build kit, the closed eight-file payload, signing order and the outer Setup | Implemented |
| [003](003-windows-deferred-config/README.md) | Late config and target manifest for the Secure Client lifecycle: bounded gateway and guardian waits, and the health `configuration` state | Partly implemented: the waits and health ship; the lifecycle refuses `-DeferredConfig` |
| [004](004-windows-ui-ipc/README.md) | The Secure Client UI IPC socket on Windows: path, DACL, deferred peer authentication and the GA release gate | Implemented (beta posture) |
| [005](005-windows-per-user-hook-lifecycle/README.md) | The `DefenseClawHookEnumerator` service that keeps the Windows target manifest in step with user profiles | Implemented; cross-process health and targeted uninstall open |
| [006](006-windows-cursor-managed-lifecycle/README.md) | Cursor in the Windows managed-enterprise lifecycle through Cursor's machine-wide hook source | Proposal |

The operator-facing behavior of specs 003 to 005 is also documented in
[`WINDOWS-ENTERPRISE-THREAT-MODEL.md`](../WINDOWS-ENTERPRISE-THREAT-MODEL.md)
and on the docs site's
[Secure Client managed deployment](https://cisco-ai-defense.github.io/defenseclaw/docs/enterprise/secure-client/)
page.
