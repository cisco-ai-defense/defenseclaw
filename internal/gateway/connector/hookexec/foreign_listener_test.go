// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"strings"
	"testing"
)

// GAP-1343: when another account's process holds this account's gateway
// port, the per-user hook sends it nothing (no bearer, no payload) and the
// block names the holder instead of "possible token drift".
func TestForeignListenerGetsNoTokenAndIsNamed(t *testing.T) {
	old := foreignListenerPID
	t.Cleanup(func() { foreignListenerPID = old })
	foreignListenerPID = func(host string, port int, _ string) int {
		if host != "127.0.0.1" || port != 8787 {
			t.Errorf("checked %s:%d, want the hook's API address", host, port)
		}
		return 13496
	}
	rt := &stubRT{status: 401, body: "unauthorized"}
	r := run(t, "claudecode", rt, func(o *Options) { o.FailMode = "closed" })
	if rt.requests != 0 {
		t.Fatalf("hook sent %d request(s) to another account's listener", rt.requests)
	}
	if r.code == 0 && !strings.Contains(r.stdout, "deny") {
		t.Fatalf("code = %d stdout = %q, want a fail-closed block", r.code, r.stdout)
	}
	all := r.stdout + r.stderr
	if !strings.Contains(all, "another account's process (PID 13496)") || strings.Contains(all, "token drift") {
		t.Fatalf("block text = %q, want the holder named and no token-drift advice", all)
	}

	// A managed hook keeps its own service-listener verification.
	foreignListenerPID = func(string, int, string) int { t.Fatal("managed hook ran the per-user check"); return 0 }
	if pid := perUserForeignListener(Options{ManagedEnterprise: true, APIAddr: "127.0.0.1:8787"}); pid != 0 {
		t.Fatalf("managed pid = %d", pid)
	}
}
