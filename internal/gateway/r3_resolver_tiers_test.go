// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/effects"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// DET111 step 4, class R3 (one path resolver, one protected-set classifier):
// verdict-level rows for the R3 gaps whose live verdict changes once the
// effects lane raises. Each row is a gap's own spelling on the hook path of
// two connectors in all five tiers. A "maybe" row must reach at least the
// unknown tier (alert in default, permissive and managed; block in strict
// and managed strict); a row with a control must be at least as strict as
// the control spelling; an "allow" row is a false-positive guard. Every row
// is held to its lane-off (1.0.10) verdict, and rows that do not reach their
// target yet are listed in r3VerdictPending (a ratchet).

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

// r3VerdictPending are rows whose verdict does not reach their target yet
// (DET111 ruling 2026-11-22 04:21Z: the verdict tests are ratchets; a Maybe
// never raises live, so these rows close only when the effect becomes KNOWN).
// Keyed by gap id, with the lane that closes each. Every row, pending or
// not, is held to at least its lane-off (1.0.10) verdict; a pending row that
// reaches its target in every cell of a run fails the run (r3Ratchet.finish).
var r3VerdictPending = map[string]string{
	"GAP-0898": "peer and mounted-home credential reads need resolver passwd-home facts (S4-R3; read row in Decide, S1-MECH)",
	"GAP-1553": "an 8.3 short name stays Maybe until the resolver reads it (S4-R3)",
	"GAP-1556": "an unknown PowerShell environment folder stays Maybe (S4-R3)",
}

// r3Ratchet judges R3 rows cell by cell: the lane-off floor, the target, and
// the pending table.
type r3Ratchet struct {
	failed, pending map[string]bool
}

func newR3Ratchet() *r3Ratchet {
	return &r3Ratchet{failed: map[string]bool{}, pending: map[string]bool{}}
}

// judge holds an attack row (want is its target) to its lane-off verdict and
// to its target unless the row is pending.
func (r *r3Ratchet) judge(t *testing.T, where string, row r3TierRow, got, off, want bounded.Action, action string, findings []string) {
	t.Helper()
	if bounded.Stricter(got, off) != got {
		t.Errorf("%s %q: %s is below its lane-off (1.0.10) verdict %s; findings %v", where, row.command, action, off, findings)
	}
	gapID := strings.Fields(row.gap)[0]
	_, pending := r3VerdictPending[gapID]
	if pending {
		r.pending[gapID] = true
	}
	if bounded.Stricter(got, want) != got {
		r.failed[gapID] = true
		if !pending {
			t.Errorf("%s %q: %s, want at least %s; findings %v", where, row.command, action, want, findings)
		}
	}
}

func (r *r3Ratchet) finish(t *testing.T) {
	t.Helper()
	for gap := range r.pending {
		if !r.failed[gap] {
			t.Errorf("%s reaches its target in every cell now: remove it from r3VerdictPending (%s)", gap, r3VerdictPending[gap])
		}
	}
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
		".codex/hooks.json", ".defenseclaw/config.yaml", "proj/notes.txt", "proj/src/a.py"} {
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
		// GAP-1677: ~root/.. is / here (the test home is a temp folder),
		// so the word names /<login>/.ssh/authorized_keys, a Known path that
		// is no account's home: it keeps its 1.0.10 cell. The reach of the
		// gap (~other/.. a sibling of the active home) is Known and blocks
		// in TestDET111R3AccountTildeFiveTiers.
		{gap: "GAP-1677 fp: ~root/.. is not the active home", command: `echo k >> ~root/../` + login + `/.ssh/authorized_keys`, want: "allow"},
		{gap: "GAP-0948 fp: ~.. is a literal folder", command: `echo k >> ~../x`, want: "allow"},
		{gap: "GAP-0898 other account credential", command: `cat /srv/homes/bob/.aws/credentials`, want: "maybe"},
		// GAP-0899: a mounted home the passwd lookup names is
		// TestDET111R3KnownResolverFactsFiveTiers; one it does not name stays
		// at its 1.0.10 verdict there (an unknown home never raises).
		// dot-dot and links
		{gap: "GAP-1648 find $HOME/.. -delete", command: `find $HOME/.. -type f -delete`, want: "maybe"},
		{gap: "GAP-1020 x/../ glob", command: `cat proj/../.ss*/id_*`, cwd: ".", want: "maybe"},
		// GAP-0443: nothing in proj matches u*, so the shell keeps the word
		// and the write fails; the gap's link tree is
		// TestDET111R3GlobDotDotFiveTiers.
		{gap: "GAP-0443 fp: .. after a wildcard that matches nothing", command: `echo k > u*/../keydir/authorized_keys`, want: "allow"},
		{gap: "GAP-1573 find -name [s]ettings.json", command: `find ~/.claude -name '[s]ettings.json' -delete`, want: "maybe"},
		{gap: "GAP-1573c in-call link find root", command: `ln -s ~/.claude d && find d/ -name '*.json' -delete`, want: "maybe"},
		// working folder
		// GAP-1244: a read through a PWD parameter operator (suffix or prefix
		// removal, literal or anchored replacement, substring with a negative
		// offset or length) is a known credential read and takes the cell of
		// its plain spelling.
		{gap: "GAP-1244 ${PWD%suffix}", command: `cat ${PWD%/proj}/.ssh/id_rsa`, want: "ctl:cat ~/.ssh/id_rsa"},
		// (${PWD/proj/}/x spells a // in the path, which the resolver keeps
		// non-canonical by review N4-4: that spelling stays at its 1.0.10 cell.)
		{gap: "GAP-1244 ${PWD/proj/}", command: `cat ${PWD/proj/}.aws/credentials`, want: "ctl:cat ~/.aws/credentials"},
		{gap: "GAP-1244 ${PWD%/*}", command: `cat ${PWD%/*}/.aws/credentials`, want: "ctl:cat ~/.aws/credentials"},
		{gap: "GAP-1244 ${PWD/proj/.ssh}", command: `cat ${PWD/proj/.ssh}/id_rsa`, want: "ctl:cat ~/.ssh/id_rsa"},
		{gap: "GAP-1244 ${PWD:0:-5}", command: `cat ${PWD:0:-5}/.ssh/id_rsa`, want: "ctl:cat ~/.ssh/id_rsa"},
		{gap: "GAP-1244 ${PWD::-5}", command: `cat ${PWD::-5}/.ssh/id_rsa`, want: "ctl:cat ~/.ssh/id_rsa"},
		{gap: "GAP-1244 anchored suffix", command: `cat "${PWD/%\/proj/}/.ssh/id_rsa"`, want: "ctl:cat ~/.ssh/id_rsa"},
		{gap: "GAP-1244 fp: ${PWD:0:-5} project file", command: `cat ${PWD:0:-5}/proj/notes.txt`, want: "allow"},
		{gap: "GAP-1037 lastpipe cd", command: `shopt -s lastpipe; echo x | cd ~/.ssh; cat id_rsa`, want: "ctl:cat ~/.ssh/id_rsa"},
		// GAP-1748: a cd in a middle pipeline stage runs in a subshell, so
		// the later read is of the project file; the plain spelling allows.
		// The last-stage cd and a keys write after a cd keep their control.
		{gap: "GAP-1748 fp: lastpipe, cd in a middle stage", command: `shopt -s lastpipe; cd ~/.ssh | cat; cat notes.txt`, want: "allow"},
		{gap: "GAP-1748 fp: set -euo pipefail, cd in a middle stage", command: `set -euo pipefail; cd ~/.ssh | cat; ls`, want: "allow"},
		{gap: "GAP-1748 lastpipe cd, then a keys write", command: `shopt -s lastpipe; echo x | cd ~/.ssh; echo k >> authorized_keys`, want: "ctl:echo k >> ~/.ssh/authorized_keys"},
		{gap: "GAP-1748 set -e, cd, then a keys write", command: `set -e; cd ~/.ssh; echo k >> authorized_keys`, want: "ctl:echo k >> ~/.ssh/authorized_keys"},
		{gap: "GAP-1043 pwd function", command: `pwd() { echo /tmp; }; cat $(pwd)/.ssh/id_rsa`, cwd: ".", want: "maybe"},
		{gap: "GAP-1608 $(pwd)/../ glob", command: `cat $(pwd)/../.ssh/id_*`, want: "maybe"},
		{gap: "GAP-1573c fp: in-call link to a project folder", command: `ln -s ~/proj/src d && find d/ -name '*.pyc' -delete`, want: "allow"},
		{gap: "GAP-1573c fp: in-call link to the hook folder, no member matches", command: `ln -s ~/.claude d && find d/ -name '*.log' -delete`, want: "allow"},
	}
	if login != "" {
		// GAP-1678: ~<login> is the active home for the hook config write as
		// for the keys (the lane's Options.Login, from the trusted identity),
		// in any case and whatever HOME the call sets (bash reads ~login from
		// the password database).
		up := strings.ToUpper(login)
		rows = append(rows,
			r3TierRow{gap: "GAP-1678 ~login keys", command: `cp proj/notes.txt ~` + login + `/.ssh/authorized_keys`, cwd: ".", want: "ctl:cp proj/notes.txt ~/.ssh/authorized_keys"},
			r3TierRow{gap: "GAP-1678 ~login claude hook config", command: `echo k >> ~` + login + `/.claude/settings.json`, cwd: ".", want: "ctl:echo k >> ~/.claude/settings.json"},
			r3TierRow{gap: "GAP-1678 ~LOGIN claude hook config", command: `echo k >> ~` + up + `/.claude/settings.json`, cwd: ".", want: "ctl:echo k >> ~/.claude/settings.json"},
			r3TierRow{gap: "GAP-1678 ~login cp operand", command: `cp proj/notes.txt ~` + login + `/.claude/settings.json`, cwd: ".", want: "ctl:cp proj/notes.txt ~/.claude/settings.json"},
			r3TierRow{gap: "GAP-1678 ~login codex hooks", command: `echo k >> ~` + login + `/.codex/hooks.json`, cwd: ".", want: "ctl:echo k >> ~/.codex/hooks.json"},
			r3TierRow{gap: "GAP-1678 HOME set, ~login", command: `HOME=/tmp/x; echo k >> ~` + login + `/.claude/settings.json`, cwd: ".", want: "ctl:echo k >> ~/.claude/settings.json"},
			r3TierRow{gap: "GAP-1678 fp: ~login project file", command: `echo k >> ~` + login + `/proj/notes.txt`, cwd: ".", want: "allow"},
		)
	}
	return rows
}

func TestDET111R3ResolverVerdictFiveTiers(t *testing.T) {
	useDefaultEffectsLane(t) // the shipped configuration: the effects lane is live
	home, login := r3TierHome(t)
	r3CheckPosixTierRows(t, home, r3PosixTierRows(home, login))
}

// GAP-1677/GAP-1678 with another account the passwd lookup finds: ~peer/..
// climbs out of peer's home into the active home (the lane's
// Options.Accounts, a bounded lookup), and peer's own plain files stay allowed.
func TestDET111R3AccountTildeFiveTiers(t *testing.T) {
	useDefaultEffectsLane(t)
	home, _ := r3TierHome(t)
	peer := filepath.Join(filepath.Dir(home), "peer")
	if err := os.MkdirAll(peer, 0o700); err != nil { // .. is walked on disk
		t.Fatal(err)
	}
	// dcr3alias is a second login of the active home (an AD short name
	// beside the user@domain login): its ~ spelling is the home itself.
	pinEffectAccounts(t, map[string]string{"dcr3peer": peer, "dcr3alias": home})
	base := filepath.Base(home)
	r3CheckPosixTierRows(t, home, []r3TierRow{
		{gap: "GAP-1677 ~alias keys", command: `echo k >> ~dcr3alias/.ssh/authorized_keys`, cwd: ".", want: "ctl:echo k >> ~/.ssh/authorized_keys"},
		{gap: "GAP-1677 ~alias hook config", command: `cp proj/notes.txt ~dcr3alias/.claude/settings.json`, cwd: ".", want: "ctl:cp proj/notes.txt ~/.claude/settings.json"},
		{gap: "GAP-1677 ~peer/../login hook config", command: `echo k >> ~dcr3peer/../` + base + `/.claude/settings.json`, cwd: ".", want: "ctl:echo k >> ~/.claude/settings.json"},
		// a .. below another account's home is a maybe (the folder may be a link)
		{gap: "GAP-1677 ~peer/../login keys", command: `echo k >> ~dcr3peer/../` + base + `/.ssh/authorized_keys`, cwd: ".", want: "maybe"},
		// another account's credential stays the other-home credential read
		// once the lookup places it (GAP-0898)
		{gap: "GAP-0898 ~peer credential", command: `cat ~dcr3peer/.ssh/id_rsa`, cwd: ".", want: "maybe"},
		{gap: "GAP-0898 ~peer aws credential", command: `cat ~dcr3peer/.aws/credentials`, cwd: ".", want: "maybe"},
		{gap: "GAP-1677 fp: ~peer plain file", command: `echo k >> ~dcr3peer/notes.txt`, cwd: ".", want: "allow"},
		{gap: "GAP-1677 fp: ~peer/../login project file", command: `echo k >> ~dcr3peer/../` + base + `/proj/notes.txt`, cwd: ".", want: "allow"},
	})
}

// GAP-0443: '..' after a wildcard component that matches a link ascends
// from the link's target, as the kernel walks it. The gap's tree: an
// outside folder whose up is a link into proj/sub, and proj/keydir a link
// to ~/.ssh, so u*/../keydir/authorized_keys from out is the account's keys
// file (the literal up/../keydir spelling is GAP-0400).
func TestDET111R3GlobDotDotFiveTiers(t *testing.T) {
	useDefaultEffectsLane(t)
	home, _ := r3TierHome(t)
	for _, d := range []string{"out", "proj/sub"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(home, "proj", "sub"), filepath.Join(home, "out", "up")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, ".ssh"), filepath.Join(home, "proj", "keydir")); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(home, "out")
	r3CheckPosixTierRows(t, home, []r3TierRow{
		{gap: "GAP-0443 u*/.. through a link, relative", command: `echo k > u*/../keydir/authorized_keys`, cwd: "out",
			want: "ctl:echo k > ~/.ssh/authorized_keys"},
		{gap: "GAP-0443 u*/.. through a link, absolute", command: `echo k > ` + out + `/u*/../keydir/authorized_keys`, cwd: "out",
			want: "ctl:echo k > ~/.ssh/authorized_keys"},
		{gap: "GAP-0443 u*/.. through a link, append", command: `echo k >> u*/../keydir/authorized_keys`, cwd: "out",
			want: "ctl:echo k >> ~/.ssh/authorized_keys"},
		// the link's target folder holds only project files
		{gap: "GAP-0443 fp: u*/.. to a project file", command: `echo k > u*/../notes.txt`, cwd: "out", want: "allow"},
		{gap: "GAP-0443 fp: u*/.. to a new project file", command: `echo k > u*/../new.txt`, cwd: "out", want: "allow"},
	})
}

// pinEffectAccounts makes the lane's passwd lookup read accounts.
func pinEffectAccounts(t *testing.T, accounts map[string]string) {
	t.Helper()
	old := effectLookupAccountHome
	effectLookupAccountHome = func(name string) (string, bool) {
		home, ok := accounts[name]
		return home, ok
	}
	t.Cleanup(func() { effectLookupAccountHome = old })
}

// The lane looks up at most maxEffectAccountLookups ~names per call, counts
// each lookup and each name past the cap, never looks up the active login,
// and leaves a name past the cap unknown.
func TestDET111R3AccountLookupBudget(t *testing.T) {
	var asked []string
	old := effectLookupAccountHome
	effectLookupAccountHome = func(name string) (string, bool) {
		asked = append(asked, name)
		return "/home/" + name, true
	}
	t.Cleanup(func() { effectLookupAccountHome = old })
	lookups, over := effectAccountLookups.Load(), effectAccountLookupsOver.Load()
	call := effects.Call{Surface: effects.SurfaceShell, Command: "cat ~DCKU/a ~a1/x ~a2/x ~a3/x ~a4/x ~a5/x ~a6/x"}
	opts := effectAccountOptions(call, effects.Options{Flavor: effects.FlavorPOSIX, Home: "/home/dcku"}, "dcku")
	if opts.Login != "dcku" {
		t.Fatalf("Login = %q", opts.Login)
	}
	if want := []string{"a1", "a2", "a3", "a4"}; !slices.Equal(asked, want) {
		t.Fatalf("looked up %q, want %q", asked, want)
	}
	if _, ok := opts.Accounts["a5"]; ok || len(opts.Accounts) != maxEffectAccountLookups {
		t.Fatalf("Accounts = %v", opts.Accounts)
	}
	if d := effectAccountLookups.Load() - lookups; d != 4 {
		t.Fatalf("lookups counted %d, want 4", d)
	}
	if d := effectAccountLookupsOver.Load() - over; d != 2 {
		t.Fatalf("over-cap counted %d, want 2", d)
	}
	win := effectAccountOptions(call, effects.Options{Flavor: effects.FlavorWindows}, "dcku")
	if win.Login != "" || win.Accounts != nil {
		t.Fatalf("Windows flavor got account options: %+v", win)
	}
}

func r3CheckPosixTierRows(t *testing.T, home string, rows []r3TierRow) {
	t.Helper()
	probe := os.Getenv("DET111_R3_PROBE") != ""
	ratchet := newR3Ratchet()
	defer ratchet.finish(t)
	for _, tier := range boundedTestTiers {
		floor := bounded.Unknown(tier.tier)
		for _, route := range r3PosixRoutes() {
			api := gap0589TierAPI(t, route.connector, tier.posture, tier.managed, tier.tier)
			for _, row := range rows {
				cwd := filepath.Join(home, "proj")
				switch row.cwd {
				case "":
				case ".":
					cwd = home
				default:
					cwd = filepath.Join(home, row.cwd)
				}
				useEffectsRulesMode(t, "off")
				offAction, _ := route.decide(t, api, t.Context(), cwd, row.command)
				useDefaultEffectsLane(t)
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
				ratchet.judge(t, tier.name+" "+route.name+" "+row.gap, row, got, boundedParse(offAction), want, action, findings)
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
		{gap: "GAP-1156 cd in a function body", command: `function g { cd .defenseclaw }; g; Set-Content -Path config.yaml -Value x`, cwd: `C:\Users\alice`, want: "maybe", needsHome: true},
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
	r3CheckWindowsTierRows(t, r3WindowsRoutes(), r3WindowsTierRows())
}

// GAP-1156: the folder a function body or a newline-separated statement
// leaves is read on every route, the Codex argv form included: a cd to a
// folder that does not exist fails, so the write lands in the home's
// .defenseclaw folder (the cd's failure reading), the cell of the plain
// spelling; a project file keeps allow. The attack rows read the profile
// (needsHome): on a Linux test gateway only the managed hook peer carries
// it; the per-user cells are the native Windows readings.
func TestDET111R3PowerShellFolderMovesFiveTiersWindowsHost(t *testing.T) {
	useDefaultEffectsLane(t)
	gap0589WindowsHost(t)
	routes := append(r3WindowsRoutes(), r3TierRoute{"codex argv powershell", "codex",
		func(t *testing.T, api *APIServer, ctx context.Context, cwd, command string) (string, []string) {
			resp := api.evaluateCodexHook(ctx, codexHookRequest{
				HookEventName: "PreToolUse", ToolName: "shell", CWD: cwd,
				ToolInput: map[string]interface{}{"command": []interface{}{"powershell.exe", "-NoProfile", "-Command", command}},
			})
			return resp.Action, resp.Findings
		}})
	const home, project = `C:\Users\alice`, `C:\Users\alice\project`
	ctl := `ctl:Set-Content -Path C:\Users\alice\.defenseclaw\config.yaml -Value x`
	r3CheckWindowsTierRows(t, routes, []r3TierRow{
		{gap: "GAP-1156 f11-fn: cd to a missing folder in a function body", command: "Set-Location " + home + "; function g { cd C:\\zz\\missing }; g; Set-Content -Path .defenseclaw\\config.yaml -Value x",
			cwd: project, want: ctl, needsHome: true},
		{gap: "GAP-1156 f3-nl: newline-separated moves", command: "Set-Location " + home + "\ncd C:\\zz\\missing\nSet-Content -Path .defenseclaw\\config.yaml -Value x",
			cwd: project, want: ctl, needsHome: true},
		{gap: "GAP-1156 f3-nl: newline-separated moves, type nul >>", command: "Set-Location " + home + "\ncd C:\\zz\\missing\ntype nul >> .defenseclaw\\config.yaml",
			cwd: project, want: "maybe", needsHome: true},
		{gap: "GAP-1156 fp: function body cd, then a project file", command: "function g { cd C:\\zz\\missing }; g; Set-Content -Path notes.txt -Value x",
			cwd: project, want: "allow"},
		{gap: "GAP-1156 fp: a function never called", command: "function g { cd .defenseclaw }; Set-Content -Path config.yaml -Value x",
			cwd: home, want: "allow"},
	})
}

// r3CheckWindowsTierRows judges Windows hook host rows on routes in every
// tier (the ratchet of r3CheckPosixTierRows).
func r3CheckWindowsTierRows(t *testing.T, routes []r3TierRoute, rows []r3TierRow) {
	t.Helper()
	probe := os.Getenv("DET111_R3_PROBE") != ""
	ratchet := newR3Ratchet()
	defer ratchet.finish(t)
	for _, tier := range boundedTestTiers {
		floor := bounded.Unknown(tier.tier)
		for _, route := range routes {
			api := gap0589TierAPI(t, route.connector, tier.posture, tier.managed, tier.tier)
			// A Linux test gateway has no Windows profile of its own: the
			// managed hook peer carries the account's home. A per-user cell
			// reads rows that need no home; the rest run natively (s7-winslot).
			ctx := t.Context()
			if tier.managed {
				ctx = withManagedHookPeer(ctx, managedHookPeer{Home: `C:\Users\alice`})
			}
			for _, row := range rows {
				if row.needsHome && !tier.managed {
					continue
				}
				useEffectsRulesMode(t, "off")
				offAction, _ := route.decide(t, api, ctx, row.cwd, row.command)
				useDefaultEffectsLane(t)
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
				ratchet.judge(t, tier.name+" "+route.name+" "+row.gap, row, got, boundedParse(offAction), want, action, findings)
			}
		}
	}
}
