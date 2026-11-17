// Scratch code-close probe, round 2 (S7 lane s7-probe1, test-only branch
// s7/ccprobes-1). Old API only (run, envvars.SetManagedStandalone): red at the
// pre-fix sha, green at rel. Self-contained: no file outside this package's
// own tree is read.

//go:build !windows

package hookuser

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/envvars"
)

// rel-1-0-10:GAP-0606 (P2): DEFENSECLAW_HOOK_MAX_BODY is managed: ignore in
// the env registry, so the per-user native hook reads it through the shared
// managed-policy lookup. Under the managed standalone policy a lowered cap is
// ignored and the call goes to the gateway; pre-fix hookuser read it with
// os.Getenv, so the managed-ignored value still refused the call. The per-user
// control (policy off) keeps the lowered cap at both shas.
func TestCCP1GAP0606ManagedIgnoredBodyCapIsReadThroughTheLookup(t *testing.T) {
	if managedRuntimePresent() {
		t.Skip("this box has a managed runtime file; the hook refuses before the cap read")
	}
	if envvars.ManagedPolicy("DEFENSECLAW_HOOK_MAX_BODY") != envvars.ManagedIgnore {
		t.Skip("control: the registry does not mark the body cap managed: ignore on this tree")
	}
	home := filepath.Join(t.TempDir(), ".defenseclaw")
	hooks := filepath.Join(home, "hooks")
	if err := os.MkdirAll(hooks, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hooks, ".hook-claudecode.token"), []byte("fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"action":"allow"}`)
	}))
	defer server.Close()
	addr := strings.TrimPrefix(server.URL, "http://")
	payload := []byte(`{"hook_event_name":"PreToolUse","session_id":"session","tool_name":"Bash","tool_input":{"command":"echo ok"}}`)
	t.Setenv("DEFENSECLAW_HOME", "")
	t.Setenv("DEFENSECLAW_HOOK_MAX_BODY", "16")
	call := func() (int, bool, string) {
		before := requests.Load()
		var out, errOut bytes.Buffer
		code := run(home, addr, bytes.NewReader(payload), &out, &errOut, time.Now())
		return code, requests.Load() != before, errOut.String()
	}
	defer envvars.SetManagedStandalone(false)
	envvars.SetManagedStandalone(false)
	if code, sent, _ := call(); code != 2 || sent {
		t.Skipf("control: per-user lowered cap 16 gives exit %d sent %v on this tree, want refused", code, sent)
	}
	envvars.SetManagedStandalone(true)
	if code, sent, stderr := call(); code != 0 || !sent {
		t.Errorf("managed-ignored cap 16 under the managed policy: exit %d sent %v stderr %q, want the call sent (cap ignored)", code, sent, stderr)
	}
}
