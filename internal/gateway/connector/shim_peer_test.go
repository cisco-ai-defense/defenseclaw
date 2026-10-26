// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// A per-user balanced PATH shim must leave normal tool use available when
// the gateway peer cannot be checked. It warns and journals one failure for
// the gateway's later degraded-audit report. Strict keeps the old refusal.
func TestPathShimsPeerFailureFollowsInstalledTier(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq is required by the shim templates")
	}
	for _, mode := range []string{"open", "closed"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			dataDir := filepath.Join(root, "data")
			if err := SetupSubprocessEnforcement(SubprocessShims, SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:1", HookFailMode: mode}); err != nil {
				t.Fatal(err)
			}
			home := filepath.Join(root, "home")
			outside := filepath.Join(root, "outside")
			binDir := filepath.Join(root, "real-tools")
			for _, dir := range []string{home, outside, binDir} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(outside, filepath.Join(home, ".local")); err != nil {
				t.Fatal(err)
			}
			for _, name := range shimBinaries {
				marker := filepath.Join(root, name+".ran")
				tool := filepath.Join(binDir, name)
				if err := os.WriteFile(tool, []byte("#!/bin/sh\n: > \"$DC_SHIM_REAL_RAN\"\n"), 0o700); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command(systemBashForTest(t), filepath.Join(dataDir, "shims", name), "--version")
				cmd.Env = append(sanitizedTestEnv(), "HOME="+home,
					"PATH="+filepath.Join(dataDir, "shims")+":"+binDir+":/usr/bin:/bin", "DC_SHIM_REAL_RAN="+marker)
				out, err := cmd.CombinedOutput()
				_, ranErr := os.Stat(marker)
				if mode == "open" {
					if err != nil || ranErr != nil || !strings.Contains(string(out), "warning") {
						t.Fatalf("%s: exit %v, real tool %v, output %q; want allow with warning", name, err, ranErr, out)
					}
				} else if err == nil || ranErr == nil {
					t.Fatalf("%s: strict exit %v, real tool %v; want refusal", name, err, ranErr)
				}
			}
			if mode == "open" {
				log, err := os.ReadFile(filepath.Join(dataDir, "logs", "hook-failures.jsonl"))
				if err != nil {
					t.Fatal(err)
				}
				lines := strings.Split(strings.TrimSpace(string(log)), "\n")
				if len(lines) != len(shimBinaries) {
					t.Fatalf("failure audit has %d rows, want %d", len(lines), len(shimBinaries))
				}
				for _, line := range lines {
					var row struct {
						Outcome  string `json:"outcome"`
						FailMode string `json:"fail_mode"`
					}
					if err := json.Unmarshal([]byte(line), &row); err != nil || row.Outcome != "fail_open" || row.FailMode != "open" {
						t.Fatalf("failure audit row %q: %v", line, err)
					}
				}
			}
		})
	}
}

func TestPathShimsDoNotOpenNonOutageNativeFailures(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq is required by the shim templates")
	}
	for _, response := range []struct{ name, helper string }{
		{"local validation", "#!/bin/sh\ncat >/dev/null\nexit 1\n"},
		{"malformed gateway answer", "#!/bin/sh\ncat >/dev/null\nprintf 'not-json\\n200'\n"},
	} {
		t.Run(response.name, func(t *testing.T) {
			root := t.TempDir()
			dataDir := filepath.Join(root, "data")
			if err := SetupSubprocessEnforcement(SubprocessShims, SetupOpts{DataDir: dataDir, HookFailMode: "open"}); err != nil {
				t.Fatal(err)
			}
			home := filepath.Join(root, "home")
			binDir := filepath.Join(home, ".local", "bin")
			if err := os.MkdirAll(binDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(binDir, "defenseclaw-gateway"), []byte(response.helper), 0o700); err != nil {
				t.Fatal(err)
			}
			for _, name := range shimBinaries {
				marker := filepath.Join(root, name+".ran")
				tool := filepath.Join(root, name)
				if err := os.WriteFile(tool, []byte("#!/bin/sh\n: > \"$DC_SHIM_REAL_RAN\"\n"), 0o700); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command(systemBashForTest(t), filepath.Join(dataDir, "shims", name), "--version")
				cmd.Env = append(sanitizedTestEnv(), "HOME="+home,
					"PATH="+filepath.Join(dataDir, "shims")+":"+root+":/usr/bin:/bin", "DC_SHIM_REAL_RAN="+marker)
				if out, err := cmd.CombinedOutput(); err == nil {
					t.Fatalf("%s: non-outage response ran the tool: %q", name, out)
				}
				if _, err := os.Stat(marker); err == nil {
					t.Fatalf("%s: non-outage response reached real tool", name)
				}
			}
		})
	}
}

func TestPerUserShimsKeepTokenAndArgumentsOffAnUnverifiedGateway(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq is required by the shim templates")
	}
	var received atomic.Int32
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			received.Add(1)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	}))
	defer peer.Close()
	shimDir := t.TempDir()
	if err := WriteShimScriptsWithToken(shimDir, strings.TrimPrefix(peer.URL, "http://"), "private-shim-token"); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	binDir := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(home, "native-called")
	stub := "#!/bin/sh\nprintf '%s' x > \"$DC_NATIVE_MARKER\"\ncat >/dev/null\nexit 1\n"
	if err := os.WriteFile(filepath.Join(binDir, "defenseclaw-gateway"), []byte(stub), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range shimBinaries {
		t.Run(name, func(t *testing.T) {
			before := received.Load()
			_ = os.Remove(marker)
			cmd := exec.Command(systemBashForTest(t), filepath.Join(shimDir, name), "--version", "private-tool-arguments")
			cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "PATH="+shimDir+":/usr/local/bin:/usr/bin:/bin", "DC_NATIVE_MARKER="+marker)
			_, runErr := cmd.CombinedOutput()
			if runErr == nil {
				t.Fatal("unverified gateway let the shim start its real tool")
			}
			if received.Load() != before {
				t.Fatal("unverified gateway received the shim bearer")
			}
			if _, err := os.Stat(marker); err != nil {
				t.Fatalf("shim skipped the native connected-peer post: %v", err)
			}
		})
	}
}

func TestPerUserShimsRejectSymlinkedNativeHelperPath(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq is required by the shim templates")
	}
	var received atomic.Int32
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	}))
	defer peer.Close()
	shimDir := t.TempDir()
	if err := WriteShimScriptsWithToken(shimDir, strings.TrimPrefix(peer.URL, "http://"), "private-shim-token"); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	outside := t.TempDir()
	binDir := filepath.Join(outside, "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(home, ".local")); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(home, "native-called")
	stub := "#!/bin/sh\nprintf '%s' x > \"$DC_NATIVE_MARKER\"\ncat >/dev/null\nexit 1\n"
	if err := os.WriteFile(filepath.Join(binDir, "defenseclaw-gateway"), []byte(stub), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range shimBinaries {
		t.Run(name, func(t *testing.T) {
			before := received.Load()
			cmd := exec.Command(systemBashForTest(t), filepath.Join(shimDir, name), "--version", "private-tool-arguments")
			cmd.Env = append(sanitizedTestEnv(), "HOME="+home, "PATH="+shimDir+":/usr/local/bin:/usr/bin:/bin", "DC_NATIVE_MARKER="+marker)
			_, runErr := cmd.CombinedOutput()
			if runErr == nil || received.Load() != before {
				t.Fatalf("shim ran the tool or sent %d requests through an untrusted helper path: %v", received.Load()-before, runErr)
			}
			if _, err := os.Stat(marker); err == nil {
				t.Fatal("shim invoked a native helper through a symlinked path")
			}
		})
	}
}
