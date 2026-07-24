# Tasks: Allow Private Upstream IPs

## Tasks

1. [ ] Add `AllowPrivateUpstreams []string` to config struct + YAML parsing + validation
   - File: `internal/config/config.go`
   - Validate each entry is a valid IP (not CIDR, not loopback/link-local/metadata)
   - Maps to: REQ-01, REQ-03, REQ-04

2. [ ] Register `DEFENSECLAW_ALLOW_PRIVATE_UPSTREAMS` env var in registry + parse logic
   - File: `internal/envvars/registry.json`, `internal/config/config.go`
   - Comma-separated IPs, merged with config.yaml entries
   - Maps to: REQ-02, REQ-03

3. [ ] Implement allowlist in `internal/netguard/netguard.go`
   - Add `SetAllowedPrivateIPs(ips []netip.Addr)` and `isAllowedPrivateIP(ip net.IP) bool`
   - Use `sync.RWMutex` + `map[netip.Addr]struct{}` for thread-safe O(1) lookup
   - `IsPrivateOrReserved` returns false for allowed IPs (after hardcoded deny check)
   - Maps to: REQ-01, REQ-04, REQ-08, REQ-09

4. [ ] Update `isUnsafeIP()` and `secureDialContext()` in `internal/gateway/provider.go`
   - Check `netguard.isAllowedPrivateIP()` before returning true/blocking
   - Maps to: REQ-08

5. [ ] Update `guardUpstreamTargetURL()` in `internal/gateway/proxy.go`
   - When IP is in allowlist: emit egress event with `reason=private-ip-allowed`, allow through
   - Maps to: REQ-01, REQ-05

6. [ ] Wire allowlist initialization in sidecar startup + config reload
   - File: `internal/gateway/sidecar.go`
   - Parse IPs from config, call `netguard.SetAllowedPrivateIPs()` at boot and on reload
   - Maps to: REQ-10

7. [ ] Update Python SSRF guard to honour allowlist
   - File: `cli/defenseclaw/registries/ssrf.py`
   - Read `DEFENSECLAW_ALLOW_PRIVATE_UPSTREAMS` env var at call time
   - Exempt listed IPs from `guard_url()` private-IP block
   - Maps to: REQ-07

8. [ ] Add `defenseclaw doctor` Security Overrides entry
   - File: `cli/defenseclaw/commands/cmd_doctor.py`
   - Show each allowed IP with HIGH impact warning
   - Maps to: REQ-06

9. [ ] Write Go unit tests
   - `internal/netguard/netguard_test.go` — allowlist set/get/exemption/hardcoded-deny
   - `internal/gateway/*_test.go` — isUnsafeIP with allowlist, guardUpstreamTargetURL with allowed IP
   - Integration test: full proxy request to private IP with allowlist configured
   - Maps to: AC-01, AC-02, AC-03, AC-04, AC-05

10. [ ] Write Python unit tests
    - `cli/tests/test_registry_ssrf.py` — guard_url with allowlist env var
    - Maps to: AC-08

11. [ ] Regenerate ENV-VARS.md + run CI coverage gate
    - `python3 scripts/gen_envvars_docs.py`
    - Ensure `cli/tests/test_envvars_codebase_coverage.py` passes
    - Maps to: REQ-02

12. [ ] Spec updates + CONTEXT.md
    - Mark tasks complete, update CONTEXT.md with implementation summary

## Test Plan

### Unit Tests

- `TestIsAllowedPrivateIP_EmptyList` — no allowlist configured, all private IPs blocked
- `TestIsAllowedPrivateIP_Allowed` — configured IP passes through
- `TestIsAllowedPrivateIP_NotInList` — different private IP still blocked
- `TestIsAllowedPrivateIP_HardcodedDeny` — loopback/link-local/metadata always blocked
- `TestIsAllowedPrivateIP_IPv6` — IPv6 ULA address in allowlist works
- `TestParseAllowPrivateUpstreams_Valid` — valid IPs parse correctly
- `TestParseAllowPrivateUpstreams_InvalidIP` — garbage rejected with error
- `TestParseAllowPrivateUpstreams_CIDR` — CIDR notation rejected with helpful error
- `TestParseAllowPrivateUpstreams_Loopback` — loopback IP rejected at parse time
- `TestGuardUpstreamTargetURL_AllowedPrivateIP` — request passes, audit event emitted
- `TestSecureDialContext_AllowedPrivateIP` — dial succeeds to allowed IP
- `test_guard_url_allowed_private_ips` — Python test with env var set

### Integration Tests

- E2E: Configure allowlist, start gateway, send chat completion to httptest server
  bound on a private IP (using the test seam), verify 200 response + audit event

### Performance Tests

- Benchmark `isAllowedPrivateIP` with 10-entry map: confirm < 100ns per call
