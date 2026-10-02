//go:build !windows

package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// The per-user worker carries the managed hook socket in its request, and an
// upgrade that configures the socket must move targets that an earlier
// release protected over TCP: the verify-or-repair pass reinstalls
// them once with the socket transport and then leaves them alone.
func TestWorkerVerifyOrRepairMovesPreUpgradeHooksToTheHookSocket(t *testing.T) {
	// The worker request carries the socket through its JSON round trip.
	in := enterprisehooks.InstallOptions{
		ConnectorName:     "opencode",
		ManagedHookSocket: "/run/defenseclaw-hook/hook.sock",
		ManagedServiceUID: 995,
	}
	out := enterpriseHookWorkerOptionsFrom(in).installOptions(nil)
	if out.ManagedHookSocket != in.ManagedHookSocket || out.ManagedServiceUID != in.ManagedServiceUID {
		t.Fatalf("worker round trip = %q/%d, want %q/%d", out.ManagedHookSocket, out.ManagedServiceUID, in.ManagedHookSocket, in.ManagedServiceUID)
	}

	if os.Getuid() == 0 {
		t.Skip("enterprise hook installer refuses uid 0 targets")
	}
	home := t.TempDir()
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	codexConfig := filepath.Join(home, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(codexConfig), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(codexConfig, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hookScript := filepath.Join(home, ".defenseclaw", "hooks", "codex-hook.sh")
	socketTransport := func() bool {
		t.Helper()
		data, err := os.ReadFile(hookScript)
		if err != nil {
			t.Fatalf("read codex hook: %v", err)
		}
		return strings.Contains(string(data), "--unix-socket")
	}
	apply := func(previouslyProtected bool, opts enterpriseHookWorkerOptions) enterpriseHookWorkerTargetResult {
		t.Helper()
		response := runEnterpriseHookWorkerApply(context.Background(), enterpriseHookWorkerRequest{
			Home: home, UID: os.Getuid(), GID: os.Getgid(), Standalone: true,
			Targets: []enterpriseHookWorkerTarget{{
				Index:               0,
				Mode:                enterpriseHookWorkerModeVerifyOrRepair,
				PreviouslyProtected: previouslyProtected,
				Options:             opts,
			}},
		})
		if len(response.Targets) != 1 || !response.Targets[0].OK {
			t.Fatalf("worker response %+v", response)
		}
		return response.Targets[0]
	}
	tcp := enterpriseHookWorkerOptions{
		ConnectorName: "codex",
		UserHome:      home,
		OwnerUID:      os.Getuid(),
		OwnerGID:      os.Getgid(),
		APIAddr:       "127.0.0.1:18970",
		ProxyAddr:     "127.0.0.1:4000",
		APIToken:      "test-token",
		OTLPPathToken: strings.Repeat("d", 64),
		GuardrailMode: "action",
		HookFailMode:  "closed",
		AgentVersion:  "codex-cli 0.142.0",
	}
	apply(false, tcp)
	if socketTransport() {
		t.Fatal("the pre-upgrade TCP install rendered the hook socket transport")
	}

	upgraded := tcp
	upgraded.AllowMissingHookConfigRepair = true
	upgraded.ManagedHookSocket = "/var/run/defenseclaw/hook.sock"
	upgraded.ManagedServiceUID = 461
	if outcome := apply(true, upgraded); !outcome.Repaired {
		t.Fatal("verify-or-repair accepted TCP hooks after the hook socket was configured")
	}
	if !socketTransport() {
		t.Fatal("the repair did not render the hook socket transport")
	}
	if outcome := apply(true, upgraded); outcome.Repaired {
		t.Fatal("verify-or-repair reinstalled hooks that already use the configured hook socket")
	}
}
