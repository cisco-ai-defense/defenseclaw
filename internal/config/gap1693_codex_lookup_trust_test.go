// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

const (
	gap1693UserURL    = "http://127.0.0.1:28601/user"
	gap1693ProjectURL = "http://127.0.0.1:28602/project"

	// gap1693ErrorPrivilegeNotHeld is Windows ERROR_PRIVILEGE_NOT_HELD (1314).
	gap1693ErrorPrivilegeNotHeld = 1314
)

// gap1693Layout writes a Codex user config that defines notes at the user
// URL (and trusts the repo when trusted is set) and a repo whose
// .codex/config.toml defines notes at the project URL and docs, written by
// project (a plain file, a symlink, too large).
func gap1693Layout(t *testing.T, trusted bool, project func(path, body string)) (workspace string) {
	t.Helper()
	home := t.TempDir()
	testenv.SetHome(t, home)
	t.Setenv("CODEX_HOME", filepath.Join(home, ".codex"))
	workspace = filepath.Join(home, "repo")
	user := "[mcp_servers.notes]\nurl = \"" + gap1693UserURL + "\"\n[mcp_servers.calendar]\ncommand = \"cal-mcp\"\n"
	if trusted {
		user += "[projects." + strconv.Quote(workspace) + "]\ntrust_level = \"trusted\"\n"
	}
	gap1692Write(t, filepath.Join(home, ".codex", "config.toml"), user)
	if err := os.MkdirAll(filepath.Join(workspace, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	project(filepath.Join(workspace, ".codex", "config.toml"),
		"[mcp_servers.notes]\nurl = \""+gap1693ProjectURL+"\"\n[mcp_servers.docs]\ncommand = \"docs-mcp\"\n")
	return workspace
}

func gap1693Plain(t *testing.T) func(path, body string) {
	return func(path, body string) { gap1692Write(t, path, body) }
}

// TestGAP1693CodexPerCallLookupFollowsProjectTrust: the per-call Codex
// lookups of the per-user gateway (LookupMCPToolServerForConnector,
// LookupMCPServerForConnector, CodexMCPToolServerAmbiguous) read every
// project layer, trusted or not, and skipped one they could not read: (a) an
// untrusted project's .codex/config.toml that Codex never loads named the
// server, so a deny rule on the user's notes URL did not match; (b) a
// trusted project file DefenseClaw refuses (symlink, too large) was skipped
// and the lookup took the user's notes, not the one Codex runs
// (rel-1-0-10:GAP-1693). Now the lookups read the layers a session runs, and
// a trusted layer that cannot be read leaves the names it may define
// unproven; GAP-1692 stays fixed for an untrusted bad file.
func TestGAP1693CodexPerCallLookupFollowsProjectTrust(t *testing.T) {
	cfg := &Config{}
	lookups := map[string]func(workspace, name string) (MCPServerEntry, bool){
		"LookupMCPToolServerForConnector": func(w, n string) (MCPServerEntry, bool) {
			return cfg.LookupMCPToolServerForConnector("codex", w, n)
		},
		"nil LookupMCPToolServerForConnector": func(w, n string) (MCPServerEntry, bool) {
			return (*Config)(nil).LookupMCPToolServerForConnector("codex", w, n)
		},
		"LookupMCPServerForConnector": func(w, n string) (MCPServerEntry, bool) {
			return cfg.LookupMCPServerForConnector("codex", w, n)
		},
		"LookupEffectiveCodexMCPToolServer": LookupEffectiveCodexMCPToolServer,
	}
	want := func(t *testing.T, workspace, name, url string, found bool) {
		t.Helper()
		for how, lookup := range lookups {
			entry, ok := lookup(workspace, name)
			if ok != found || found && entry.URL != url {
				t.Errorf("%s(%s): ok=%v url=%q, want ok=%v url=%q", how, name, ok, entry.URL, found, url)
			}
		}
	}
	t.Run("untrusted project does not shadow the user server", func(t *testing.T) {
		workspace := gap1693Layout(t, false, gap1693Plain(t))
		want(t, workspace, "notes", gap1693UserURL, true)
		want(t, workspace, "docs", "", false)
	})
	t.Run("trusted project server wins", func(t *testing.T) {
		workspace := gap1693Layout(t, true, gap1693Plain(t))
		want(t, workspace, "notes", gap1693ProjectURL, true)
		want(t, workspace, "calendar", "", true)
	})
	t.Run("trusted project too large", func(t *testing.T) {
		workspace := gap1693Layout(t, true, func(path, body string) {
			gap1692Write(t, path, body+"# "+strings.Repeat("x", maxCodexInventoryConfigBytes)+"\n")
		})
		want(t, workspace, "notes", "", false)
		want(t, workspace, "calendar", "", false)
	})
	t.Run("trusted project symlink", func(t *testing.T) {
		workspace := gap1693Layout(t, true, func(path, body string) {
			real := filepath.Join(filepath.Dir(filepath.Dir(path)), "real.toml")
			gap1692Write(t, real, body)
			if err := os.Symlink(real, path); err != nil {
				// Windows creates a symlink only with SeCreateSymbolicLinkPrivilege (an
				// elevated token or Developer Mode). Skip only for that error; the native
				// run runs this test as an elevated row, and a skip there is NAT14_SKIPPED.
				if runtime.GOOS == "windows" && errors.Is(err, syscall.Errno(gap1693ErrorPrivilegeNotHeld)) {
					t.Skipf("symlink creation needs a privilege this token lacks: %v", err)
				}
				t.Fatal(err)
			}
		})
		want(t, workspace, "notes", "", false)
	})
	t.Run("untrusted bad project keeps the user servers (GAP-1692)", func(t *testing.T) {
		workspace := gap1693Layout(t, false, func(path, _ string) { gap1692Write(t, path, "not = [toml") })
		want(t, workspace, "notes", gap1693UserURL, true)
	})
	t.Run("ambiguity reads the effective layers", func(t *testing.T) {
		workspace := gap1693Layout(t, false, func(path, _ string) {
			gap1692Write(t, path, "[mcp_servers.cal-endar]\ncommand = \"x\"\n[mcp_servers.cal_endar]\ncommand = \"y\"\n")
		})
		if cfg.CodexMCPToolServerAmbiguous(workspace, "cal_endar") {
			t.Error("names of an untrusted project read as ambiguous")
		}
	})
}
