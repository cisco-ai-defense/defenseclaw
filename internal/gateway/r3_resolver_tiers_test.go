// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// DET111 step 4, class R3 (one path resolver, one protected-set classifier):
// verdict-level rows for the R3 gaps whose live verdict changes once the
// effects lane raises. Each row is a gap's own spelling on the hook path of
// two connectors in all five tiers. A "maybe" row must reach at least the
// unknown tier (alert in default, permissive and managed; block in strict
// and managed strict); a row with a control must be at least as strict as
// the control spelling; an "allow" row is a false-positive guard. Red at
// a64bfdb931 (the effects lane was shadow), green with the raise-only lane.

type r3TierRow struct {
	gap, command string
	// want: "maybe", "allow", or "ctl:<control command>"
	want string
	// cwd relative to the test home ("" = proj)
	cwd string
	// needsHome: the row names the account's profile relatively (Windows
	// rows read only where the gateway knows that profile).
	needsHome bool
}

type r3TierRoute struct {
	name, connector string
	decide          func(t *testing.T, api *APIServer, ctx context.Context, cwd, command string) (string, []string)
}

func r3PosixRoutes() []r3TierRoute {
	return []r3TierRoute{
		{"claudecode Bash", "claudecode", func(t *testing.T, api *APIServer, ctx context.Context, cwd, command string) (string, []string) {
			resp := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
				HookEventName: "PreToolUse", SessionID: "det111-r3", CWD: cwd, ToolName: "Bash",
				ToolInput: map[string]interface{}{"command": command},
			})
			return resp.Action, resp.Findings
		}},
		{"codex shell", "codex", func(t *testing.T, api *APIServer, ctx context.Context, cwd, command string) (string, []string) {
			resp := api.evaluateCodexHook(ctx, codexHookRequest{
				HookEventName: "PreToolUse", ToolName: "shell", CWD: cwd,
				ToolInput: map[string]interface{}{"command": command},
			})
			return resp.Action, resp.Findings
		}},
	}
}

func r3TierHome(t *testing.T) (home, login string) {
	t.Helper()
	home = t.TempDir()
	for _, f := range []string{".ssh/authorized_keys", ".ssh/id_rsa", ".aws/credentials", ".claude/settings.json",
		".defenseclaw/config.yaml", "proj/notes.txt", "proj/src/a.py"} {
		p := filepath.Join(home, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	if u, err := user.Current(); err == nil {
		login = u.Username
	}
	return home, login
}

func r3PosixTierRows(home, login string) []r3TierRow {
	rows := []r3TierRow{
		// home spellings
		{gap: "GAP-1677 ~other/../login keys", command: `echo k >> ~root/../` + login + `/.ssh/authorized_keys`, want: "maybe"},
		{gap: "GAP-0948 fp: ~.. is a literal folder", command: `echo k >> ~../x`, want: "allow"},
		{gap: "GAP-0898 other account credential", command: `cat /srv/homes/bob/.aws/credentials`, want: "maybe"},
		{gap: "GAP-0899 mounted home credential", command: `cat /mnt/home/bob/.ssh/id_rsa`, want: "maybe"},
		// dot-dot and links
		{gap: "GAP-1648 find $HOME/.. -delete", command: `find $HOME/.. -type f -delete`, want: "maybe"},
		{gap: "GAP-1020 x/../ glob", command: `cat proj/../.ss*/id_*`, cwd: ".", want: "maybe"},
		{gap: "GAP-0443 .. after a wildcard", command: `echo k > u*/../keydir/authorized_keys`, want: "maybe"},
		{gap: "GAP-1573 find -name [s]ettings.json", command: `find ~/.claude -name '[s]ettings.json' -delete`, want: "maybe"},
		{gap: "GAP-1573c in-call link find root", command: `ln -s ~/.claude d && find d/ -name '*.json' -delete`, want: "maybe"},
		// working folder
		// GAP-1244: the effects lane reaches the unknown tier for a credential
		// read; the plain spelling's PATH-SSH-KEY block is a legacy rule.
		{gap: "GAP-1244 ${PWD%suffix}", command: `cat ${PWD%/proj}/.ssh/id_rsa`, want: "maybe"},
		{gap: "GAP-1244 ${PWD/proj/}", command: `cat ${PWD/proj/}/.aws/credentials`, want: "maybe"},
		{gap: "GAP-1037 lastpipe cd", command: `shopt -s lastpipe; echo x | cd ~/.ssh; cat id_rsa`, want: "ctl:cat ~/.ssh/id_rsa"},
		{gap: "GAP-1043 pwd function", command: `pwd() { echo /tmp; }; cat $(pwd)/.ssh/id_rsa`, cwd: ".", want: "maybe"},
		{gap: "GAP-1608 $(pwd)/../ glob", command: `cat $(pwd)/../.ssh/id_*`, want: "maybe"},
		{gap: "GAP-1573c fp: in-call link to a project folder", command: `ln -s ~/proj/src d && find d/ -name '*.pyc' -delete`, want: "allow"},
	}
	if login != "" {
		// GAP-1678's hook-config row joins when the effects lane fills
		// Options.Login from the trusted identity; the keys row is a guard.
		rows = append(rows,
			r3TierRow{gap: "GAP-1678 ~login keys", command: `cp proj/notes.txt ~` + login + `/.ssh/authorized_keys`, cwd: ".", want: "ctl:cp proj/notes.txt ~/.ssh/authorized_keys"})
	}
	return rows
}

func TestDET111R3ResolverVerdictFiveTiers(t *testing.T) {
	useDefaultEffectsLane(t) // the shipped configuration: the effects lane is live
	home, login := r3TierHome(t)
	probe := os.Getenv("DET111_R3_PROBE") != ""
	for _, tier := range boundedTestTiers {
		floor := bounded.Unknown(tier.tier)
		for _, route := range r3PosixRoutes() {
			api := gap0589TierAPI(t, route.connector, tier.posture, tier.managed, tier.tier)
			for _, row := range r3PosixTierRows(home, login) {
				cwd := filepath.Join(home, "proj")
				if row.cwd == "." {
					cwd = home
				}
				action, findings := route.decide(t, api, t.Context(), cwd, row.command)
				got := boundedParse(action)
				var want bounded.Action
				switch {
				case row.want == "maybe":
					want = floor
				case row.want == "allow":
					want = bounded.Allow
				case strings.HasPrefix(row.want, "ctl:"):
					ca, _ := route.decide(t, api, t.Context(), cwd, strings.TrimPrefix(row.want, "ctl:"))
					want = boundedParse(ca)
					if want == bounded.Allow && tier.name == "default" {
						t.Fatalf("%s %s %s: control %q allows, the control is void", tier.name, route.name, row.gap, row.want)
					}
				}
				if probe {
					t.Logf("ROW\t%s\t%s\t%s\t%s\twant>=%s\t%s", tier.name, route.name, row.gap, action, want, strings.Join(findings, "; "))
				}
				if row.want == "allow" {
					if got != bounded.Allow {
						t.Errorf("%s %s %s: %s, want allow (false-positive guard); findings %v", tier.name, route.name, row.gap, action, findings)
					}
					continue
				}
				if bounded.Stricter(got, want) != got {
					t.Errorf("%s %s %s %q: %s, want at least %s; findings %v", tier.name, route.name, row.gap, row.command, action, want, findings)
				}
			}
		}
	}
}

// r3WindowsRoutes are the PowerShell routes of two connectors on a Windows
// hook host, each in the row's working folder.
func r3WindowsRoutes() []r3TierRoute {
	return []r3TierRoute{
		{"claudecode PowerShell", "claudecode", func(t *testing.T, api *APIServer, ctx context.Context, cwd, command string) (string, []string) {
			resp := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
				HookEventName: "PreToolUse", SessionID: "det111-r3w", CWD: cwd, ToolName: "PowerShell",
				ToolInput: map[string]interface{}{"command": command},
			})
			return resp.Action, resp.Findings
		}},
		{"codex shell", "codex", func(t *testing.T, api *APIServer, ctx context.Context, cwd, command string) (string, []string) {
			resp := api.evaluateCodexHook(ctx, codexHookRequest{
				HookEventName: "PreToolUse", ToolName: "shell", CWD: cwd,
				ToolInput: map[string]interface{}{"command": command},
			})
			return resp.Action, resp.Findings
		}},
	}
}

// Windows hook host rows, read on the PowerShell route of two connectors.
func r3WindowsTierRows() []r3TierRow {
	return []r3TierRow{
		{gap: "GAP-1553 SSH~1 short name", command: `Add-Content SSH~1\authorized_keys x`, cwd: `C:\Users\alice`, want: "maybe", needsHome: true},
		{gap: "GAP-1553 AUTHOR~1 short name", command: `cd .ssh; Add-Content AUTHOR~1 x`, cwd: `C:\Users\alice`, want: "maybe", needsHome: true},
		{gap: "GAP-1191 dot-dot state write", command: `Set-Content -Path ..\.defenseclaw\config.yaml -Value x`, cwd: `C:\Users\alice\project`,
			want: `ctl:Set-Content -Path C:\Users\alice\.defenseclaw\config.yaml -Value x`},
		{gap: "GAP-1556 $env:X folder, keys", command: `Set-Location $env:X; Set-Content -Path authorized_keys -Value x`, cwd: `C:\Users\alice\project`, want: "maybe"},
		{gap: "GAP-1156 cd in a function body", command: `function g { cd .defenseclaw }; g; Set-Content -Path config.yaml -Value x`, cwd: `C:\Users\alice`, want: "maybe"},
		// PowerShell reads localhost: as a drive name; the effects reading of
		// the key file behind it is maybe (was allow).
		{gap: "GAP-1671 localhost:/// key write", command: `Set-Content -Path localhost:///C:/Users/alice/.ssh/authorized_keys -Value k`, cwd: `C:\Users\alice\project`,
			want: "maybe"},
		{gap: "GAP-1556 fp: unknown folder, ordinary name", command: `Set-Location $env:X; Set-Content -Path notes.txt -Value x`, cwd: `C:\Users\alice\project`, want: "allow"},
	}
}

func TestDET111R3ResolverVerdictFiveTiersWindowsHost(t *testing.T) {
	useDefaultEffectsLane(t)
	gap0589WindowsHost(t)
	probe := os.Getenv("DET111_R3_PROBE") != ""
	for _, tier := range boundedTestTiers {
		floor := bounded.Unknown(tier.tier)
		for _, route := range r3WindowsRoutes() {
			api := gap0589TierAPI(t, route.connector, tier.posture, tier.managed, tier.tier)
			// A Linux test gateway has no Windows profile of its own: the
			// managed hook peer carries the account's home. A per-user cell
			// reads rows that need no home; the rest run natively (s7-winslot).
			ctx := t.Context()
			if tier.managed {
				ctx = withManagedHookPeer(ctx, managedHookPeer{Home: `C:\Users\alice`})
			}
			for _, row := range r3WindowsTierRows() {
				if row.needsHome && !tier.managed {
					continue
				}
				action, findings := route.decide(t, api, ctx, row.cwd, row.command)
				got := boundedParse(action)
				want := floor
				switch {
				case row.want == "allow":
					want = bounded.Allow
				case strings.HasPrefix(row.want, "ctl:"):
					ca, _ := route.decide(t, api, ctx, row.cwd, strings.TrimPrefix(row.want, "ctl:"))
					want = boundedParse(ca)
					if want == bounded.Allow && tier.name == "default" {
						t.Fatalf("%s %s %s: control %q allows, the control is void", tier.name, route.name, row.gap, row.want)
					}
				}
				if probe {
					t.Logf("ROW\t%s\t%s\t%s\t%s\twant>=%s\t%s", tier.name, route.name, row.gap, action, want, strings.Join(findings, "; "))
				}
				if row.want == "allow" {
					if got != bounded.Allow {
						t.Errorf("%s %s %s: %s, want allow (false-positive guard); findings %v", tier.name, route.name, row.gap, action, findings)
					}
					continue
				}
				if bounded.Stricter(got, want) != got {
					t.Errorf("%s %s %s %q: %s, want at least %s; findings %v", tier.name, route.name, row.gap, row.command, action, want, findings)
				}
			}
		}
	}
}
