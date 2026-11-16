//go:build linux || darwin

package enterpriseunix

import (
	"context"
	"fmt"
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

// GAP-1410, GAP-1426, GAP-1434: a symlinked or missing --config is refused
// with the reason and the next step, not "is a symlink" or raw lstat text.
func TestEnsureExplainsASymlinkedOrMissingConfig(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	link := filepath.Join(t.TempDir(), "link.yaml")
	if err := os.Symlink(writeChangedConfig(t, h, "mode: observe", "mode: action"), link); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "does-not-exist.yaml")
	for path, want := range map[string]string{
		link:    "is a symlink, so its target could be swapped after the check; pass the real file path",
		missing: "does not exist; check the path given to --config",
	} {
		r := h.run(Options{Action: ActionEnsure, ConfigFile: path})
		requireError(t, r, codeConfig)
		if msg := r.Errors[len(r.Errors)-1].Message; !strings.Contains(msg, want) || strings.Contains(msg, "lstat") || !strings.HasSuffix(msg, "then rerun") {
			t.Fatalf("--config %s: %q, want %q and a next step", path, msg, want)
		}
	}
	if strings.Contains(h.read(h.env.Layout.ConfigPath), "mode: action") {
		t.Fatal("the symlinked config was installed")
	}
}

// GAP-0937: macOS keeps the mode bits when an ACL entry is added, so ensure
// --config applied (and re-applied after the edit) an input file with a
// write,append entry for a standard user. The refusal names the ACL and how
// to remove it.
func TestEnsureRefusesAConfigWithAWriteACLEntry(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	cfg := writeChangedConfig(t, h, "mode: observe", "mode: action")
	restore := inputPathACL
	t.Cleanup(func() { inputPathACL = restore })
	inputPathACL = func(path string) error {
		if path == cfg {
			return fmt.Errorf("%s has write-capable macOS ACL entry", path)
		}
		return nil
	}
	r := h.run(Options{Action: ActionEnsure, ConfigFile: cfg})
	requireError(t, r, codeConfig)
	if msg := r.Errors[len(r.Errors)-1].Message; !strings.Contains(msg, "ACL entry") || !strings.Contains(msg, aclRemoveCommand(cfg)) {
		t.Fatalf("the refusal must name the ACL and how to remove it: %q", msg)
	}
	if strings.Contains(h.read(h.env.Layout.ConfigPath), "mode: action") {
		t.Fatal("the config with a write ACL entry was installed")
	}
}

// GAP-1139, GAP-1141: a macOS ACL grants write without changing mode bits.
// An apply run must not commit a policy edit made through that ACL.
func TestEnsureRefusesAnEditedInstalledConfigWithWriteACL(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	requireOK(t, h.run(Options{Action: ActionEnsure, ConfigFile: writeChangedConfig(t, h, "mode: observe", "mode: action")}))
	applied := h.read(h.env.Layout.ConfigPath)
	edited := editConfigInPlace(t, h, "mode: action", "mode: observe")
	h.runner.acls = map[string][]string{
		h.env.P(h.env.Layout.ConfigPath): {"user:standard allow write,append"},
	}
	r := h.run(Options{Action: ActionEnsure, Reason: "path"})
	requireError(t, r, codeConfig)
	if msg := messagesOf(r.Errors, codeConfig); !strings.Contains(msg, "ACL") {
		t.Fatalf("config refusal did not identify the write ACL: %s", msg)
	}
	if got := h.read(h.env.Layout.ConfigPath); got == edited || got != applied {
		t.Fatal("the policy edit made through the ACL was accepted")
	}
}

// GAP-1450: a folder ACL entry let a standard user replace config.yaml; the
// plain ensure refused the edit but left the entry in place, so verify kept
// naming it until a second ensure. The refusing ensure removes it.
func TestRefusedInPlaceEditRemovesTheConfigFolderACL(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	applied := h.read(h.env.Layout.ConfigPath)
	edited := editConfigInPlace(t, h, "mode: observe", "mode: action")
	etc := h.env.P(filepath.Dir(h.env.Layout.ConfigPath))
	h.runner.acls = map[string][]string{etc: {"user:standard allow list,add_file,search,delete_child,writeattr"}}
	r := h.run(Options{Action: ActionEnsure, Reason: "path"})
	requireError(t, r, codeConfig)
	if got := h.runner.acls[etc]; len(got) != 0 {
		t.Fatalf("the refused ensure left the config folder ACL entries %v", got)
	}
	if got := h.read(h.env.Layout.ConfigPath); got == edited || got != applied {
		t.Fatal("the refused edit is in place")
	}
}

// chmodHookRunner calls onChmod with the path before the fake removes its ACL.
type chmodHookRunner struct {
	*fakeRunner
	onChmod func(path string)
}

func (r *chmodHookRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	if name == "chmod" && len(args) > 0 {
		r.onChmod(args[len(args)-1])
	}
	return r.fakeRunner.Run(ctx, name, args...)
}

// GAP-1441: a folder ACL entry let a standard user put another config.yaml
// in place after the run replaced the file and before the transaction
// removed the entry; the follow-up transaction applied it.
func TestEnsureDoesNotApplyAConfigSwappedBeforeTheFolderACLIsRemoved(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	requireOK(t, h.run(Options{Action: ActionEnsure, ConfigFile: writeChangedConfig(t, h, "mode: observe", "mode: action")}))
	applied := h.read(h.env.Layout.ConfigPath)
	before, _ := h.env.loadDeployment()
	dir := h.env.P(filepath.Dir(h.env.Layout.ConfigPath))
	h.runner.acls = map[string][]string{dir: {"user:standard allow add_file,delete_child"}}
	weaker := strings.Replace(applied, "mode: action", "mode: observe", 1)
	h.env.Runner = &chmodHookRunner{fakeRunner: h.runner, onChmod: func(path string) {
		swap := filepath.Join(dir, "swap.yaml")
		if path == dir && os.WriteFile(swap, []byte(weaker), 0o640) == nil {
			_ = os.Rename(swap, h.env.P(h.env.Layout.ConfigPath))
		}
	}}
	r := h.run(Options{Action: ActionEnsure, Reason: "path"})
	after, _ := h.env.loadDeployment()
	if got := h.read(h.env.Layout.ConfigPath); got != applied || after.ConfigSHA256 != before.ConfigSHA256 {
		t.Fatalf("the config swapped in through the folder ACL was applied (errors %+v):\n%s", r.Errors, got)
	}
	if len(r.Errors) > 0 {
		requireError(t, r, codeConfig)
	}
}
