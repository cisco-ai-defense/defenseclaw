//go:build linux || darwin

package enterpriseunix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-1200: ensure --config applied a world-writable (0666) admin config,
// which any local account could have rewritten before the run.
func TestEnsureRefusesAConfigOtherAccountsCanWrite(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	cfg := writeChangedConfig(t, h, "mode: observe", "mode: action")
	if err := os.Chmod(cfg, 0o666); err != nil {
		t.Fatal(err)
	}
	r := h.run(Options{Action: ActionEnsure, ConfigFile: cfg})
	requireError(t, r, codeConfig)
	if msg := r.Errors[len(r.Errors)-1].Message; !strings.Contains(msg, "0666") || !strings.Contains(msg, "chmod 0600") {
		t.Fatalf("the refusal must name the mode and the fix: %q", msg)
	}
	if strings.Contains(h.read(h.env.Layout.ConfigPath), "mode: action") {
		t.Fatal("the untrusted config was installed")
	}

	// A folder other accounts can write (not sticky) lets them swap the file.
	open := filepath.Join(t.TempDir(), "open")
	if err := os.Mkdir(open, 0o777); err != nil || os.Chmod(open, 0o777) != nil {
		t.Fatal(err)
	}
	swapped := filepath.Join(open, "config.yaml")
	if err := os.Rename(writeChangedConfig(t, h, "mode: observe", "mode: action"), swapped); err != nil {
		t.Fatal(err)
	}
	requireError(t, h.run(Options{Action: ActionEnsure, ConfigFile: swapped}), codeConfig)

	if err := os.Chmod(cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	requireOK(t, h.run(Options{Action: ActionEnsure, ConfigFile: cfg}))
}
