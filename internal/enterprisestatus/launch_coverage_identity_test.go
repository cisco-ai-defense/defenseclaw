// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// linkLaunchDir makes link name target: a symlink, or on Windows without the
// symlink privilege a directory junction, which the agent follows the same way.
func linkLaunchDir(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err == nil {
		return
	} else if runtime.GOOS != "windows" {
		t.Fatalf("symlink %s: %v", link, err)
	}
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("junction %s: %v: %s", link, err, out)
	}
}

// An enrolled user's launch directory may be spelled through a link to the
// directory the managed install uses (a symlinked or bind-mounted home, a
// junction, macOS /etc -> /private/etc). The agent then loads the managed
// hooks, so health must stay complete. A spelling that cannot be shown to name
// that directory (another target, a dangling link, a relative or network path,
// or on Unix a ".." after a link) is still reported.
func TestPluginLaunchCoverageResolvesEquivalentDirectories(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home", "alice")
	other := filepath.Join(root, "other")
	for _, dir := range []string{filepath.Join(home, ".config"), filepath.Join(home, ".hermes"), filepath.Join(home, "escape-target"), other} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	alias := filepath.Join(root, "alias")
	linkLaunchDir(t, home, alias)
	otherAlias := filepath.Join(root, "other-alias")
	linkLaunchDir(t, other, otherAlias)
	dangling := filepath.Join(root, "dangling")
	linkLaunchDir(t, filepath.Join(root, "gone"), dangling)
	// Unix resolves ".." after a link: escape/../.config is <root>/other/../.config, i.e. <root>/.config.
	escape := filepath.Join(home, "escape")
	linkLaunchDir(t, other, escape)
	resolvedHome, err := filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatal(err)
	}
	sep := string(filepath.Separator)
	dotDotEscape, dotDotMissing := "amp_plugin_config_relocated", "kiro_hook_config_relocated"
	if runtime.GOOS == "windows" {
		// Win32 removes ".." from the spelling before it follows a link.
		dotDotEscape, dotDotMissing = "", ""
	}

	for _, tc := range []struct {
		name, connector, accountHome string
		env                          map[string]string
		want                         string
	}{
		{"symlinked HOME", "amp", home, map[string]string{"HOME": alias}, ""},
		{"symlinked account home", "amp", alias, map[string]string{"HOME": home}, ""},
		{"resolved temp home", "amp", home, map[string]string{"HOME": resolvedHome}, ""},
		{"XDG through a linked home", "amp", home, map[string]string{"HOME": home, "XDG_CONFIG_HOME": filepath.Join(alias, ".config")}, ""},
		{"OpenCode through a linked home", "opencode", home, map[string]string{"HOME": alias, "XDG_CONFIG_HOME": filepath.Join(alias, ".config")}, ""},
		{"Devin through a linked home", "devin", home, map[string]string{"HOME": alias}, ""},
		{"Antigravity through a linked home", "antigravity", home, map[string]string{"HOME": alias}, ""},
		{"Hermes home through a link", "hermes", home, map[string]string{"HOME": alias, "HERMES_HOME": filepath.Join(alias, ".hermes")}, ""},
		{"Kiro home not created yet through a link", "kiro", home, map[string]string{"KIRO_HOME": filepath.Join(alias, ".kiro")}, ""},
		{"dot-dot to the same directory", "hermes", home, map[string]string{"HOME": home, "HERMES_HOME": home + sep + ".config" + sep + ".." + sep + ".hermes"}, ""},
		{"link to another directory", "amp", home, map[string]string{"HOME": otherAlias}, "amp_plugin_config_relocated"},
		{"missing child of another directory", "kiro", home, map[string]string{"KIRO_HOME": filepath.Join(otherAlias, ".kiro")}, "kiro_hook_config_relocated"},
		{"dangling link", "kiro", home, map[string]string{"KIRO_HOME": filepath.Join(dangling, ".kiro")}, "kiro_hook_config_relocated"},
		{"relative HOME", "amp", home, map[string]string{"HOME": "alias"}, "amp_plugin_config_relocated"},
		{"dot-dot after a link", "amp", home, map[string]string{"HOME": home, "XDG_CONFIG_HOME": escape + sep + ".." + sep + ".config"}, dotDotEscape},
		{"dot-dot to a missing directory", "kiro", home, map[string]string{"KIRO_HOME": home + sep + ".config" + sep + ".." + sep + ".kiro"}, dotDotMissing},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := PluginLaunchCoverage(tc.connector, []string{tc.connector}, tc.env, true, tc.accountHome); got != tc.want {
				t.Fatalf("coverage = %q, want %q", got, tc.want)
			}
		})
	}

	if runtime.GOOS == "windows" {
		// A network spelling is never resolved: status runs elevated, and a
		// lookup would send the machine's credentials to the named server.
		unc := `\\127.0.0.1\` + strings.Replace(home, ":", "$", 1)
		if got := PluginLaunchCoverage("amp", []string{"amp"}, map[string]string{"HOME": unc}, true, home); got != "amp_plugin_config_relocated" {
			t.Fatalf("network HOME coverage = %q, want amp_plugin_config_relocated", got)
		}
		// A local link to that share is not resolved either: following it
		// would contact the server just the same. A local junction still is.
		shareLink := filepath.Join(root, "share-link")
		if err := os.Symlink(unc, shareLink); err != nil {
			t.Logf("no symlink privilege for the share link case: %v", err)
		} else {
			for _, env := range []map[string]string{{"HOME": shareLink}, {"HOME": home, "XDG_CONFIG_HOME": filepath.Join(shareLink, ".config")}} {
				if got := PluginLaunchCoverage("amp", []string{"amp"}, env, true, home); got != "amp_plugin_config_relocated" {
					t.Fatalf("HOME through a link to a share (%v) coverage = %q, want amp_plugin_config_relocated", env, got)
				}
			}
		}
	}
}

// macOS /etc is a link to /private/etc, so Hermes reads one managed directory
// through either spelling, whether or not /etc/hermes exists yet.
func TestPluginLaunchCoverageHermesManagedDirThroughPrivateEtc(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS /etc link")
	}
	env := map[string]string{"HERMES_MANAGED_DIR": "/private/etc/hermes", "HOME": "/Users/alice"}
	if got := PluginLaunchCoverage("hermes", []string{"hermes"}, env, true, "/Users/alice"); got != "" {
		t.Fatalf("coverage = %q, want complete", got)
	}
	env["HERMES_MANAGED_DIR"] = "/private/etc/hermes-other"
	if got := PluginLaunchCoverage("hermes", []string{"hermes"}, env, true, "/Users/alice"); got != "hermes_config_relocated" {
		t.Fatalf("other managed dir coverage = %q, want hermes_config_relocated", got)
	}
}
