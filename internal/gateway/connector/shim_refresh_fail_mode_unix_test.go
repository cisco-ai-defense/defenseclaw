// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0038: a PATH shim cannot ask the config at call time when the
// account's home is writable by its group (or ~/.local, ~/.local/bin is a
// symlink): it follows the mode it was installed with. `guardrail use-pack
// strict` and `guardrail fail-mode` run refresh-fail-modes, which now sets
// that installed mode from the config, so strict refuses there too and a
// later open runs again.
func TestRefreshHookFailModesSetsTheShimsInstalledMode(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq is required by the shim templates")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := SetupSubprocessEnforcement(SubprocessShims, SetupOpts{DataDir: dataDir, APIAddr: freeLoopbackAddrForOutageTest(t), HookFailMode: "open"}, "zeptoclaw"); err != nil {
		t.Fatal(err)
	}
	hookDir := filepath.Join(dataDir, "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// A gateway that would answer closed; the shim must not run it from an
	// unsafe home, so only the installed mode decides.
	gateway := "#!/bin/sh\nif [ \"$1\" = hook-outage-mode ]; then printf 'closed\\n'; exit 0; fi\ncat >/dev/null\nexit 7\n"
	if err := os.WriteFile(filepath.Join(binDir, "defenseclaw-gateway"), []byte(gateway), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(home, 0o770); err != nil {
		t.Fatal(err)
	}
	realDir := filepath.Join(root, "real-tools")
	if err := os.MkdirAll(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "curl.ran")
	if err := os.WriteFile(filepath.Join(realDir, "curl"), []byte("#!/bin/sh\n: > \"$DC_SHIM_REAL_RAN\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	runCurl := func() (bool, string) {
		_ = os.Remove(marker)
		cmd := exec.Command(systemBashForTest(t), filepath.Join(dataDir, "shims", "curl"), "--version")
		cmd.Env = append(sanitizedTestEnv(), "HOME="+home,
			"PATH="+filepath.Join(dataDir, "shims")+":"+realDir+":/usr/bin:/bin", "DC_SHIM_REAL_RAN="+marker)
		out, err := cmd.CombinedOutput()
		_, ranErr := os.Stat(marker)
		return err == nil && ranErr == nil, string(out)
	}
	if ran, out := runCurl(); !ran {
		t.Fatalf("installed open did not run curl from an unsafe home: %s", out)
	}

	asked := []string{}
	result, err := RefreshHookFailModes(hookDir, func(name string) string {
		asked = append(asked, name)
		if name == "zeptoclaw" {
			return "closed"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(result.Shims, ",") != strings.Join(shimBinaries, ",") {
		t.Fatalf("refreshed shims = %v, want %v (asked %v)", result.Shims, shimBinaries, asked)
	}
	if ran, out := runCurl(); ran || !strings.Contains(out, "refusing to exec curl") {
		t.Fatalf("strict saved after setup: curl ran=%v from an unsafe home: %s", ran, out)
	}

	result, err = RefreshHookFailModes(hookDir, func(string) string { return "open" })
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Shims) != len(shimBinaries) {
		t.Fatalf("open again refreshed %v", result.Shims)
	}
	if ran, out := runCurl(); !ran {
		t.Fatalf("open saved again: curl did not run: %s", out)
	}
	// Unchanged modes rewrite nothing; an unresolved connector is left as it is.
	if result, err = RefreshHookFailModes(hookDir, func(string) string { return "open" }); err != nil || len(result.Shims) != 0 {
		t.Fatalf("no-op refresh changed %v (%v)", result.Shims, err)
	}
	if result, err = RefreshHookFailModes(hookDir, func(string) string { return "" }); err != nil || len(result.Shims) != 0 {
		t.Fatalf("unresolved connector refresh changed %v (%v)", result.Shims, err)
	}
}
