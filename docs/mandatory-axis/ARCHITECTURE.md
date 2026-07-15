# Mandatory AXIS on AMD Halo

The managed Codex launcher is a read-only control plane. It reaches DefenseClaw only through the Responses gateway and one required stdio MCP forwarder. The forwarder sends run, run_write, and apply_patch requests to the DefenseClaw broker; every command enters a fresh Bubblewrap plus standalone AXIS worker.

The broker commits RECEIVED and its outbox event before authorization. Both local rules and the local judge must explicitly allow. Authorization expires after five seconds and is bound to the canonical request digest. Results are inspected before release; raw command input and output are never stored.

The current repository package implements the wire contract and durable decision core. Deployment remains shadow-only until the real Qwen canary and live cgroup/network tests pass.
