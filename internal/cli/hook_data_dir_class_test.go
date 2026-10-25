// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// oss-outage-open round h, review of 0fa1b66d (the class of the quoted
// data_dir lock bypass): one parser, the gateway's own loader, decides the
// folder install.sh locks. For every spelling of the config, whenever a hook
// of a data directory can let an outage through there without a lock, the
// installer's answer (hookDataDirNow, with install.sh's environment) names
// exactly that directory, so its lock closes the outage. A spelling the
// runtime does not take as that directory's config never opens there, so it
// needs no lock. Covers YAML anchors and aliases, merge keys, explicit tags,
// a byte order mark, CRLF line ends, a flow mapping, a home-relative value,
// an external config without data_dir and a data directory that comes only
// from DEFENSECLAW_HOME.
func TestHookDataDirNowLocksEveryDataDirAHookCanOpenIn(t *testing.T) {
	for _, tc := range []struct {
		name string
		body func(data string) string
		// homeOnly: no data_dir; install.sh's DEFENSECLAW_HOME is the folder.
		homeOnly bool
	}{
		{name: "anchor and alias", body: func(d string) string {
			return "paths: &dir " + d + "\ndata_dir: *dir\n" + outageNowDefaultConfig
		}},
		{name: "merge key", body: func(d string) string {
			return "base: &base\n  data_dir: " + d + "\n<<: *base\n" + outageNowDefaultConfig
		}},
		{name: "explicit string tag", body: func(d string) string { return "data_dir: !!str " + d + "\n" + outageNowDefaultConfig }},
		{name: "tagged key", body: func(d string) string { return "!!str data_dir: " + d + "\n" + outageNowDefaultConfig }},
		{name: "byte order mark", body: func(d string) string { return "\ufeffdata_dir: " + d + "\n" + outageNowDefaultConfig }},
		{name: "CRLF line ends", body: func(d string) string {
			return strings.ReplaceAll("data_dir: "+d+"\n"+outageNowDefaultConfig, "\n", "\r\n")
		}},
		{name: "flow mapping", body: func(d string) string {
			return "{config_version: 9, observability: {}, guardrail: {mode: observe}, data_dir: '" + d + "'}\n"
		}},
		{name: "home-relative value", body: func(string) string {
			return "data_dir: ~/srv/dc-data\n" + outageNowDefaultConfig
		}},
		{name: "external config without data_dir", body: func(string) string { return outageNowDefaultConfig }},
		{name: "data dir from DEFENSECLAW_HOME only", homeOnly: true, body: func(string) string { return outageNowDefaultConfig }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			data := filepath.Join(base, "srv", "dc-data")
			installer := filepath.Join(base, "installer-home")
			if tc.homeOnly {
				installer = data
			}
			writeOutageNowConfig(t, data, tc.body(data))
			// The hooks a runtime rendered in that folder.
			if err := os.MkdirAll(filepath.Join(data, "hooks"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(installer, 0o700); err != nil {
				t.Fatal(err)
			}
			isolateOutageHostMarkers(t)
			stubOutageInstallFolders(t, func() string { return "" }, func() (string, bool) { return "", false })
			// install.sh's environment (DEFENSECLAW_CONFIG names the
			// runtime's config, HOME is the account's).
			t.Setenv("HOME", base)
			t.Setenv("USERPROFILE", base)
			t.Setenv("DEFENSECLAW_HOME", installer)
			if tc.homeOnly {
				t.Setenv("DEFENSECLAW_CONFIG", "")
			} else {
				t.Setenv("DEFENSECLAW_CONFIG", filepath.Join(data, "config.yaml"))
			}
			named, nameErr := hookDataDirNow()
			// The hooks of that folder, with the gateway's environment
			// (the same account HOME and DEFENSECLAW_HOME), and with an
			// agent's environment that inherits none of it.
			hooks := filepath.Join(data, "hooks")
			for _, env := range []struct {
				label        string
				home, dcHome string
			}{
				{"gateway environment", base, installer},
				{"agent environment", filepath.Join(base, "agent-home"), ""},
			} {
				t.Setenv("DEFENSECLAW_CONFIG", "")
				t.Setenv("DEFENSECLAW_HOME", env.dcHome)
				t.Setenv("HOME", env.home)
				t.Setenv("USERPROFILE", env.home)
				if hookOutageFailModeNow("opencode", hooks) != "open" {
					t.Logf("%s: the runtime does not take this spelling as %s config; no outage opens there", env.label, data)
					continue
				}
				t.Logf("%s: a hook opens an outage in %s without a lock", env.label, data)
				if nameErr != nil || named != data {
					t.Fatalf("%s: a hook in %s opens an outage, but install.sh would lock %q (err %v)", env.label, data, named, nameErr)
				}
				lock := filepath.Join(named, ".install.lock")
				if err := os.MkdirAll(lock, 0o700); err != nil {
					t.Fatal(err)
				}
				if mode := hookOutageFailModeNow("opencode", hooks); mode != "closed" {
					t.Fatalf("%s: hook-outage-mode with the lock install.sh holds = %q, want closed", env.label, mode)
				}
				if err := os.Remove(lock); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
