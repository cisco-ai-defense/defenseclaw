// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/daemon"
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
	// GAP-1706: the port answers, so the lead does not say "unreachable" and
	// names the blocked event rather than a tool.
	if strings.Contains(r.stderr, "gateway unreachable") || !strings.Contains(r.stderr, "defenseclaw: blocking this ") {
		t.Fatalf("stderr = %q, want a lead naming the blocked event", r.stderr)
	}
	if lead := unreachableLead(Options{Event: "UserPromptSubmit"}, spec{subject: "claude-code tool"},
		foreignListenerReason("127.0.0.1:8787", 1), "blocking"); lead != "blocking this prompt" {
		t.Fatalf("prompt lead = %q", lead)
	}

	// A managed hook keeps its own service-listener verification.
	foreignListenerPID = func(string, int, string) int { t.Fatal("managed hook ran the per-user check"); return 0 }
	if pid := perUserForeignListener(Options{ManagedEnterprise: true, APIAddr: "127.0.0.1:8787"}); pid != 0 {
		t.Fatalf("managed pid = %d", pid)
	}
}

func TestPerUserHookNamesSameHomeRootListenerWithoutSending(t *testing.T) {
	oldPID, oldHolder, oldClass := foreignListenerPID, perUserPortHolder, perUserListenerClass
	t.Cleanup(func() {
		foreignListenerPID, perUserPortHolder, perUserListenerClass = oldPID, oldHolder, oldClass
	})
	foreignListenerPID = func(string, int, string) int { return 0 }
	perUserPortHolder = func(string, int) (daemon.PortHolder, error) {
		return daemon.PortHolder{PID: 1, UID: 0}, nil
	}
	perUserListenerClass = func(string, int, string, daemon.PortHolder, error, bool) daemon.PerUserListenerClass {
		return daemon.PerUserListenerOwnGatewayRunAsRoot
	}
	peer := newPeerListener(t, "127.0.0.1:0", false)
	addr := peer.addr()
	result := run(t, "claudecode", nil, func(opts *Options) {
		opts.APIAddr = addr
		opts.Home = t.TempDir()
		opts.HTTPClient = verifiedTestClient(addr, func(net.Conn) error {
			return errors.New("connected gateway socket belongs to another account")
		})
		opts.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo hi"}}`)
		opts.FailMode = "closed"
		opts.OutageFailModeNow = func() string { return "open" }
		opts.StartedAt = time.Now()
	})
	out := result.stdout + result.stderr
	if !nativeOutageBlocked(result) || !strings.Contains(out, daemon.RootGatewayListenerReason) ||
		!namesRootGatewayRemedy(runtime.GOOS, out) || strings.Contains(out, "--api-port") {
		t.Fatalf("root listener result: code=%d output=%q", result.code, out)
	}
	if peer.received.Load() != 0 {
		t.Fatalf("root listener received %d request bytes", peer.received.Load())
	}
	if got := perUserRootGatewayReason(Options{ManagedEnterprise: true, APIAddr: addr, Home: os.TempDir()}); got != "" {
		t.Fatalf("managed hook used per-user root diagnosis: %q", got)
	}
}

// namesRootGatewayRemedy reports whether text carries the remedy of the
// given OS (GAP-0706, GAP-0746): macOS and Linux name the privileged
// stop with the account's home (sudo env DEFENSECLAW_HOME=), Windows names
// the elevated PowerShell prompt and never sudo.
func namesRootGatewayRemedy(goos, text string) bool {
	if goos == "windows" {
		return strings.Contains(text, "elevated PowerShell prompt") && !strings.Contains(text, "sudo ")
	}
	return strings.Contains(text, "sudo env DEFENSECLAW_HOME=")
}

// GAP-0746: the root-gateway remedy check follows the OS. Each OS accepts its
// own remedy only: the Unix sudo form is not a Windows remedy, and the
// elevated PowerShell prompt is not a macOS or Linux one.
func TestGAP0746RootGatewayRemedyCheckFollowsTheOS(t *testing.T) {
	const unix = "Stop it, return its files to your account and start it as yourself with: sudo env DEFENSECLAW_HOME='/h' '/bin/defenseclaw-gateway' stop && defenseclaw-gateway start"
	const windows = "Stop it from an elevated PowerShell prompt (& 'C:\\Users\\a\\bin\\defenseclaw-gateway.exe' stop), then start it as yourself from a normal PowerShell prompt (& 'C:\\Users\\a\\bin\\defenseclaw-gateway.exe' start)"
	for _, tc := range []struct {
		goos, text string
		want       bool
	}{
		{"linux", unix, true}, {"darwin", unix, true}, {"windows", windows, true},
		{"windows", unix, false}, {"linux", windows, false}, {"darwin", windows, false},
	} {
		if got := namesRootGatewayRemedy(tc.goos, tc.text); got != tc.want {
			t.Errorf("%s remedy check on %q = %v, want %v", tc.goos, tc.text, got, tc.want)
		}
	}
}

// GAP-0711, GAP-0713: the hook's block text for a root-run gateway returns the
// moved store as well as the install home.
func TestPerUserHookRootGatewayRemedyCoversMovedStore(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Windows remedy has no ownership step")
	}
	home := t.TempDir()
	store := filepath.Join(t.TempDir(), "moved store")
	t.Setenv("DEFENSECLAW_CONFIG", "")
	if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte("data_dir: "+strconv.Quote(store)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldHolder, oldClass := perUserPortHolder, perUserListenerClass
	t.Cleanup(func() { perUserPortHolder, perUserListenerClass = oldHolder, oldClass })
	perUserPortHolder = func(string, int) (daemon.PortHolder, error) { return daemon.PortHolder{PID: 1, UID: 0}, nil }
	perUserListenerClass = func(string, int, string, daemon.PortHolder, error, bool) daemon.PerUserListenerClass {
		return daemon.PerUserListenerOwnGatewayRunAsRoot
	}
	reason := perUserRootGatewayReason(Options{APIAddr: "127.0.0.1:8787", Home: home})
	for _, dir := range []string{home, store} {
		if !strings.Contains(reason, "'"+dir+"'") {
			t.Errorf("hook remedy leaves %s root-owned: %q", dir, reason)
		}
	}
}
