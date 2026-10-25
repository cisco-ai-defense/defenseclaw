// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// oss-outage-open review (round g, loop round 2): install.sh found the
// config's data_dir with a line reader (awk '^data_dir:'), so a valid config
// whose key is quoted ("data_dir": ...) or in any other YAML form the gateway
// takes named no folder. The installer then held only its DEFENSECLAW_HOME
// while the gateway was stopped, and the hooks of that data_dir, which look
// for .install.lock there, let an unset default-tier outage through.
// install.sh now asks the runtime (hook-data-dir), which reads the config
// with the gateway's own loader. Every form below is one the runtime takes as
// its data directory (hook-outage-mode opens there without a lock), and the
// resolver names exactly that folder.
func TestHookDataDirNowNamesTheRuntimesDataDirInEveryYAMLForm(t *testing.T) {
	for _, tc := range []struct {
		name string
		body func(data string) string
	}{
		{"plain key", func(d string) string { return "data_dir: " + d + "\n" + outageNowDefaultConfig }},
		{"double-quoted key", func(d string) string {
			return `"data_dir": "` + filepath.ToSlash(d) + "\"\n" + outageNowDefaultConfig
		}},
		{"single-quoted key", func(d string) string { return "'data_dir': '" + d + "'\n" + outageNowDefaultConfig }},
		{"space before the colon", func(d string) string { return "data_dir : " + d + "\n" + outageNowDefaultConfig }},
		{"value on the next line", func(d string) string { return "data_dir:\n  " + d + "\n" + outageNowDefaultConfig }},
		{"folded block scalar", func(d string) string { return "data_dir: >-\n  " + d + "\n" + outageNowDefaultConfig }},
		{"explicit key", func(d string) string { return "? data_dir\n: " + d + "\n" + outageNowDefaultConfig }},
		{"escaped double-quoted value", func(d string) string {
			return `data_dir: "\x2f` + strings.TrimPrefix(filepath.ToSlash(d), "/") + "\"\n" + outageNowDefaultConfig
		}},
		{"document marker and comments", func(d string) string {
			return "---\n# where the hooks live\n" + outageNowDefaultConfig + "data_dir: " + d + "   # custom\n"
		}},
		{"JSON document", func(d string) string {
			return `{"config_version": 9, "observability": {}, "guardrail": {"mode": "observe"}, "data_dir": "` +
				filepath.ToSlash(d) + `"}` + "\n"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if strings.Contains(tc.name, "escaped") && filepath.Separator != '/' {
				t.Skip("a POSIX absolute path")
			}
			base := t.TempDir()
			data := filepath.Join(base, "srv", "dc-data")
			installer := filepath.Join(base, "installer-home")
			writeOutageNowConfig(t, data, tc.body(data))
			if err := os.MkdirAll(installer, 0o700); err != nil {
				t.Fatal(err)
			}
			isolateOutageHostMarkers(t)
			stubOutageInstallFolders(t, func() string { return "" }, func() (string, bool) { return "", false })
			// install.sh's environment: DEFENSECLAW_CONFIG names the config in
			// the data_dir, DEFENSECLAW_HOME is the installer's own folder.
			t.Setenv("DEFENSECLAW_CONFIG", filepath.Join(data, "config.yaml"))
			t.Setenv("DEFENSECLAW_HOME", installer)
			got, err := hookDataDirNow()
			if err != nil {
				t.Fatalf("hookDataDirNow: %v", err)
			}
			if got != data {
				t.Fatalf("hookDataDirNow = %q, want the runtime's data_dir %q", got, data)
			}
			// The hooks of that folder, which inherit nothing of the
			// installer, open the outage there until its lock exists.
			t.Setenv("DEFENSECLAW_CONFIG", "")
			t.Setenv("DEFENSECLAW_HOME", "")
			t.Setenv("HOME", filepath.Join(base, "agent-home"))
			t.Setenv("USERPROFILE", filepath.Join(base, "agent-home"))
			hooks := filepath.Join(data, "hooks")
			if mode := hookOutageFailModeNow("opencode", hooks); mode != "open" {
				t.Fatalf("hook-outage-mode without a lock = %q; the runtime does not take this form, so the case proves nothing", mode)
			}
			if err := os.MkdirAll(filepath.Join(got, ".install.lock"), 0o700); err != nil {
				t.Fatal(err)
			}
			if mode := hookOutageFailModeNow("opencode", hooks); mode != "closed" {
				t.Fatalf("hook-outage-mode with the lock install.sh holds = %q, want closed", mode)
			}
		})
	}
}

func TestHookDataDirNowDefaultsAndRefusals(t *testing.T) {
	base := t.TempDir()
	home := filepath.Join(base, "installer-home")
	data := filepath.Join(base, "dc-data")
	for _, tc := range []struct {
		name    string
		body    string // "" leaves no config
		want    string
		wantErr bool
	}{
		{name: "no config yet", want: home},
		{name: "no data_dir", body: outageNowDefaultConfig, want: home},
		// The runtime takes an empty value as it is: no absolute folder, so
		// its hooks never open an outage (hookOutageFailModeNow).
		{name: "empty data_dir", body: "data_dir: \"\"\n" + outageNowDefaultConfig, want: ""},
		// A relative value is taken from the config's folder, as
		// hook-outage-mode takes it (loadHookRuntimeConfig).
		{name: "relative data_dir", body: "data_dir: relative/data\n" + outageNowDefaultConfig, want: filepath.Join(home, "relative", "data")},
		// An older release's config this one loads only after migrate.
		{name: "older config with a quoted key", body: "config_version: 7\n\"data_dir\": \"" + filepath.ToSlash(data) + "\"\n", want: data},
		{name: "data_dir that is not a string", body: "config_version: 7\ndata_dir: [a, b]\n", wantErr: true},
		{name: "config that is not YAML", body: "data_dir: \"unterminated\n  - [\n", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.RemoveAll(home); err != nil {
				t.Fatal(err)
			}
			writeOutageNowConfig(t, home, tc.body)
			t.Setenv("DEFENSECLAW_CONFIG", "")
			t.Setenv("DEFENSECLAW_HOME", home)
			got, err := hookDataDirNow()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("hookDataDirNow = %q, want an error", got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("hookDataDirNow = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestHookDataDirCommandPrintsTheFolder(t *testing.T) {
	base := t.TempDir()
	data := filepath.Join(base, "dc-data")
	writeOutageNowConfig(t, data, `"data_dir": "`+filepath.ToSlash(data)+"\"\n"+outageNowDefaultConfig)
	t.Setenv("DEFENSECLAW_CONFIG", filepath.Join(data, "config.yaml"))
	t.Setenv("DEFENSECLAW_HOME", filepath.Join(base, "installer-home"))
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs([]string{"hook-data-dir"})
	t.Cleanup(func() { rootCmd.SetOut(nil); rootCmd.SetErr(nil); rootCmd.SetArgs(nil) })
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("hook-data-dir: %v (%s)", err, out.String())
	}
	if got := strings.TrimSpace(out.String()); got != data {
		t.Fatalf("hook-data-dir printed %q, want %q", got, data)
	}
}

// hookDataDirNow is the first folder hook-data-dir names (the hooks' own
// folder when one qualifies, else the data directory), "" for none.
func hookDataDirNow() (string, error) {
	dirs, err := hookDataDirsNow()
	if err != nil || len(dirs) == 0 {
		return "", err
	}
	return dirs[0], nil
}
