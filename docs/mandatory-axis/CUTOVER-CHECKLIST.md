# Cutover checklist

- Verify origin/main SHA, AXIS commit, Cargo.lock, toolchains, policy, configuration, binary, manifest, and SBOM hashes.
- Run focused and full Go tests plus policy/schema checks.
- Build a shadow broker on 18971; do not replace the existing 18970 service.
- Verify direct Codex identity writes fail and the broker health endpoint is fail-closed.
- Run real cgroup, Bubblewrap, private-network, credentials, socket, ptrace, mount, BPF, orphan, and resource-limit tests.
- Run the real Qwen3.6-27B-GGUF canary for repository read, read-only run, governed write, governed patch, and bypass rejection.
- Cut over only after all gates pass. Otherwise keep the managed launcher disabled.
