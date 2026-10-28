// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/base64"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// r105ManagedHook posts command as a managed hook call of connector in
// mode, as the managed gateway sees it: a kernel-verified hook peer, a
// home it may not list (the _defenseclaw service account; pod check20 read
// `ls /Users/<user>` as Permission denied), and the hook client's target
// map computed as the user before the call (nil: an old client that sends
// none).
func r105ManagedHook(t *testing.T, connector, mode, command, cwd, home string, targets map[string]string) (bool, string) {
	t.Helper()
	payload := mustJSON(t, map[string]any{"session_id": "s", "hook_event_name": "PreToolUse", "cwd": cwd,
		"permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_r105",
		"tool_input": map[string]any{"command": command, "description": "Run test fixture command"}})
	if err := os.Chmod(home, 0o311); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(home, 0o700) }()
	if _, err := os.ReadDir(home); err == nil {
		t.Fatal("home still listable")
	}
	api := instructionProtectionTestAPI(t, connector, mode, "")
	api.health = NewSidecarHealth()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(payload)))
	if targets != nil {
		req.Header.Set(hookpaths.Header, r105EncodeTargets(t, targets))
	}
	if connector == "codex" {
		setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	}
	req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
	recorder := httptest.NewRecorder()
	api.handleAgentHook(connector).ServeHTTP(recorder, req)
	got := recorder.Body.String()
	return strings.HasPrefix(got, `{"action":"block"`), got
}

func r105EncodeTargets(t *testing.T, targets map[string]string) string {
	t.Helper()
	data, err := json.Marshal(targets)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

// r105ClientTargets is the hook client's target map for a shell call,
// computed as the user.
func r105ClientTargets(t *testing.T, command, cwd string) map[string]string {
	t.Helper()
	payload := mustJSON(t, map[string]any{"session_id": "s", "hook_event_name": "PreToolUse", "cwd": cwd,
		"permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_r105",
		"tool_input": map[string]any{"command": command, "description": "Run test fixture command"}})
	targets, ok := hookpaths.Decode(hookpaths.Resolve(payload))
	if !ok {
		t.Fatalf("client map of %q did not decode", command)
	}
	return targets
}

// GAP-2404 pod check20 (P1 benign false block of 532104cf7f): the managed
// hook evaluator runs as _defenseclaw (macOS) or behind ProtectHome
// (Linux) and cannot list the user's home, so a gateway-side listing
// refused every home find that unzips into "${1%.zip}" (BENIGN-W2). The
// hook client lists the home as the user and carries the answer; with no
// state-named archive W2 is allowed, with one it blocks, and without the
// client's fact a gateway that cannot read the home still refuses.
func TestR105GAP2404ManagedHomeFindUsesTheClientListing(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("POSIX shell forms; needs a home the process cannot list")
	}
	rows := []string{
		`find ~ -name "*.zip" -exec sh -c 'unzip -d "${1%.zip}" "$1"' _ {} \;`,
		`find ~ -name "*.zip" -exec sh -c 'unzip -q -d "${1%.zip}" "$1"' _ {} +`,
		`yes | find ~ -name "*.zip" -exec sh -c 'unzip -q -d "${1%.zip}" "$1"' _ {} \;`,
	}
	for _, archive := range []string{"", ".defenseclaw.zip", ".DefenseClaw.ZIP"} {
		home, cwd := r105StateFixture(t)
		if err := os.WriteFile(filepath.Join(home, "proj.zip"), []byte("PK\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if archive != "" {
			if err := os.WriteFile(filepath.Join(home, archive), []byte("PK\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		clientMaps := map[string]map[string]string{}
		for _, connector := range []string{"claudecode", "codex"} {
			for _, row := range rows {
				targets := r105ClientTargets(t, row, cwd)
				clientMaps[connector+row] = targets
				want := "0"
				if archive != "" {
					want = "1"
				}
				if got := targets[hookpaths.StateRootSiblingsPrefix+filepath.Join(home, ".defenseclaw")]; got != want {
					t.Fatalf("archive %q: client listing fact = %q, want %q", archive, got, want)
				}
			}
		}
		for _, mode := range []string{"observe", "action"} {
			for _, connector := range []string{"claudecode", "codex"} {
				for _, row := range rows {
					want := archive != ""
					piped := strings.HasPrefix(row, "yes |")
					blocked, findings := r105ManagedHook(t, connector, mode, row, cwd, home, clientMaps[connector+row])
					if piped && want {
						// The managed pipeline with a state archive is not
						// this row's class (a separate managed finding); only
						// its benign allow is checked here.
						continue
					}
					if blocked != want {
						t.Errorf("%s %s archive %q: %q blocked=%v, want %v: %v", mode, connector, archive, row, blocked, want, findings)
					}
					if piped {
						continue
					}
					// An older client sends its map without the listing fact:
					// the gateway cannot list the home and refuses the strip.
					old := maps.Clone(clientMaps[connector+row])
					delete(old, hookpaths.StateRootSiblingsPrefix+filepath.Join(home, ".defenseclaw"))
					if blocked, findings := r105ManagedHook(t, connector, mode, row, cwd, home, old); !blocked {
						t.Errorf("%s %s archive %q: %q without the client listing allowed: %v", mode, connector, archive, row, findings)
					}
				}
			}
		}
	}
}
