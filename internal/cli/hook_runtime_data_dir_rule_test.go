// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
)

// oss-outage-open round i (lock path class): hook-outage-mode (may a hook
// let an outage through) and hook-data-dir (which folder install.sh locks)
// decide the runtime's data directory with one rule, loadHookRuntimeConfig.
// Every spelling of a data_dir that names the config's own folder (none, a
// relative one taken from the config's folder, quoted, tagged, flow style,
// absolute with a trailing slash) gives the hooks there the outage mode of
// their tier whatever DEFENSECLAW_CONFIG or DEFENSECLAW_HOME the agent
// passes, and install.sh, started from another directory with an absolute
// or a relative DEFENSECLAW_CONFIG or DEFENSECLAW_HOME, holds that folder.
// The lock it holds closes the outage while its installer runs, and a stale
// one (installer gone) is no lock. During a live install, --install-window
// keeps the tier's mode for a call the gateway answered.
func TestHookOutageModeAndHookDataDirShareOneDataDirRule(t *testing.T) {
	const tier = "config_version: 9\nobservability: {}\nguardrail:\n  mode: observe\n"
	spellings := []struct {
		name string
		body func(data string) string
	}{
		{"no data_dir", func(string) string { return tier }},
		{"relative dot", func(string) string { return "data_dir: .\n" + tier }},
		{"quoted dot-slash", func(string) string { return "data_dir: \"./\"\n" + tier }},
		{"quoted key and value", func(string) string { return "'data_dir': '.'\n" + tier }},
		{"tagged relative", func(string) string { return "data_dir: !!str sub/..\n" + tier }},
		{"absolute with a trailing slash", func(d string) string {
			return "data_dir: '" + filepath.ToSlash(d) + "/'\n" + tier
		}},
		{"flow mapping", func(string) string {
			return "{config_version: 9, observability: {}, guardrail: {mode: observe}, data_dir: .}\n"
		}},
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	exited := exec.Command(self, "-test.run=^$")
	if err := exited.Run(); err != nil {
		t.Fatal(err)
	}
	dead := strconv.Itoa(exited.ProcessState.Pid())
	for _, spelling := range spellings {
		t.Run(spelling.name, func(t *testing.T) {
			base := t.TempDir()
			if resolved, err := filepath.EvalSymlinks(base); err == nil {
				base = resolved
			}
			data := filepath.Join(base, "srv", "dc-data")
			other := filepath.Join(base, "installer-home")
			project := filepath.Join(base, "agent-project")
			for _, dir := range []string{filepath.Join(data, "hooks"), other, project} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			writeOutageNowConfig(t, data, spelling.body(data))
			config := filepath.Join(data, "config.yaml")
			hooks := filepath.Join(data, "hooks")
			isolateOutageHostMarkers(t)
			stubOutageInstallFolders(t, func() string { return "" }, func() (string, bool) { return "", false })
			t.Setenv("HOME", filepath.Join(base, "agent-home"))
			t.Setenv("USERPROFILE", filepath.Join(base, "agent-home"))

			// The hook, from the agent's project, with what the agent passes.
			t.Chdir(project)
			for _, env := range []struct{ label, config, home string }{
				{"no override", "", ""},
				{"DEFENSECLAW_CONFIG names this config", config, ""},
				{"DEFENSECLAW_CONFIG names this config, DEFENSECLAW_HOME elsewhere", config, other},
				{"relative DEFENSECLAW_CONFIG from the agent's directory", filepath.Join("..", "srv", "dc-data", "config.yaml"), ""},
				{"DEFENSECLAW_HOME elsewhere", "", other},
			} {
				t.Setenv("DEFENSECLAW_CONFIG", env.config)
				t.Setenv("DEFENSECLAW_HOME", env.home)
				if got := hookOutageFailModeNow("opencode", hooks); got != "open" {
					t.Fatalf("%s: hook-outage-mode = %q, want the default tier's open", env.label, got)
				}
				if got := os.Getenv("DEFENSECLAW_CONFIG"); got != env.config {
					t.Fatalf("%s: hook-outage-mode left DEFENSECLAW_CONFIG = %q", env.label, got)
				}
			}

			// install.sh, started from base, with absolute and relative paths.
			t.Chdir(base)
			for _, env := range []struct{ label, config, home string }{
				{"absolute DEFENSECLAW_CONFIG", config, other},
				{"relative DEFENSECLAW_CONFIG", filepath.Join("srv", "dc-data", "config.yaml"), other},
				{"relative DEFENSECLAW_CONFIG and DEFENSECLAW_HOME", filepath.Join(".", "srv", "dc-data", "config.yaml"), "installer-home"},
				{"DEFENSECLAW_HOME is the data folder", "", data},
				{"relative DEFENSECLAW_HOME is the data folder", "", filepath.Join("srv", "dc-data")},
			} {
				t.Setenv("DEFENSECLAW_CONFIG", env.config)
				t.Setenv("DEFENSECLAW_HOME", env.home)
				named, err := hookDataDirNow()
				if err != nil {
					t.Fatalf("%s: hook-data-dir: %v", env.label, err)
				}
				lockHome := env.home
				if !filepath.IsAbs(lockHome) {
					lockHome = filepath.Join(base, lockHome)
				}
				if !pathidentity.Same(named, data) && !pathidentity.Same(lockHome, data) {
					t.Fatalf("%s: install.sh holds %q and %q, not the hooks' data folder %q", env.label, lockHome, named, data)
				}
			}

			// The lock install.sh holds there, live and stale.
			t.Chdir(project)
			t.Setenv("DEFENSECLAW_CONFIG", "")
			t.Setenv("DEFENSECLAW_HOME", "")
			lock := filepath.Join(data, ".install.lock")
			for _, owner := range []struct {
				label, pid string
				want       string
			}{
				{"running installer", strconv.Itoa(os.Getppid()), "closed"},
				{"installer that has not written its pid yet", "", "closed"},
				{"installer that is gone", dead, "open"},
			} {
				if err := os.Mkdir(lock, 0o700); err != nil {
					t.Fatal(err)
				}
				if owner.pid != "" {
					if err := os.WriteFile(filepath.Join(lock, "pid"), []byte(owner.pid+"\n"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if got := hookOutageFailModeNow("opencode", hooks); got != owner.want {
					t.Fatalf("lock of a %s: hook-outage-mode = %q, want %q", owner.label, got, owner.want)
				}
				if got := hookOutageFailModeFor("opencode", hooks, true); got != "open" {
					t.Fatalf("lock of a %s: --install-window = %q, want the default tier's open", owner.label, got)
				}
				if err := os.RemoveAll(lock); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	t.Run("strict tier keeps an install window closed", func(t *testing.T) {
		data := t.TempDir()
		writeOutageNowConfig(t, data, tier+"  rule_pack: strict\n")
		isolateOutageHostMarkers(t)
		stubOutageInstallFolders(t, func() string { return "" }, func() (string, bool) { return "", false })
		t.Setenv("DEFENSECLAW_CONFIG", "")
		t.Setenv("DEFENSECLAW_HOME", "")
		if got := hookOutageFailModeFor("opencode", filepath.Join(data, "hooks"), true); got != "closed" {
			t.Fatalf("strict --install-window = %q, want closed", got)
		}
	})
	t.Run("a relative config path names no folder", func(t *testing.T) {
		if _, dir, err := loadHookRuntimeConfig(filepath.Join("srv", "config.yaml")); err == nil || dir != "" {
			t.Fatalf("loadHookRuntimeConfig(relative) = %q, %v", dir, err)
		}
		if got := configDataDir(filepath.Join(string(filepath.Separator)+"x", "config.yaml"), strings.Repeat(" ", 2)); got != "" {
			t.Fatalf("configDataDir(blank) = %q", got)
		}
	})
}
