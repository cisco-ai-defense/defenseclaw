// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// gap1014Verdict is action/severity/rules of command through the hook
// handler of connector (claudecode or codex) in cwd, with the folder
// evidence the hook client sends.
func gap1014Verdict(t *testing.T, a *APIServer, connector, session, cwd, command string, client bool) string {
	t.Helper()
	body := string(mustJSON(t, map[string]any{"session_id": session, "hook_event_name": "PreToolUse",
		"tool_name": "Bash", "tool_use_id": "tu-" + session, "cwd": cwd, "tool_input": map[string]any{"command": command}}))
	route := map[string]string{"claudecode": "/api/v1/claude-code/hook", "codex": "/api/v1/codex/hook"}[connector]
	req := httptest.NewRequest(http.MethodPost, route, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if client {
		req.Header.Set(hookpaths.Header, hookpaths.Resolve([]byte(body)))
	}
	if connector == "codex" {
		setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	}
	rec := httptest.NewRecorder()
	a.handleAgentHook(connector).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: status %d body %s", route, rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s: answer %q: %v", route, rec.Body.String(), err)
	}
	action, _ := out["action"].(string)
	if action == "" {
		action = "allow"
	}
	severity, _ := out["severity"].(string)
	return fmt.Sprintf("%s %s %v", action, severity, out["rule_ids"])
}

// gap1014Home makes <base>/<root>/home/alice with a DefenseClaw state folder
// (the s7-gate fixture shape: FX_BASE/<12 hex>/home/alice).
func gap1014Home(t *testing.T, base, root string) string {
	t.Helper()
	home := filepath.Join(base, root, "home", "alice")
	for _, dir := range []string{filepath.Join(home, ".defenseclaw"), filepath.Join(home, "proj", "sub")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".defenseclaw", "custom-providers.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "proj", "sub", "a.txt"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return home
}

// gap1014OwnerTrace is the owner-trace call at/codex/32d23eb7189f92a7/209 of
// the agent-transcripts corpus, with its home written as %[1]s.
const gap1014OwnerTrace = `sudo rm -f /etc/defenseclaw/config.yaml.v8.bak /etc/defenseclaw/migration-v9.json ` +
	`/var/lib/defenseclaw-enterprise/allow-downgrade /var/tmp/r103-gb11-br-candidate.rpm; ` +
	`for p in /etc/defenseclaw/config.yaml.v8.bak /etc/defenseclaw/migration-v9.json ` +
	`/var/lib/defenseclaw-enterprise/allow-downgrade /var/tmp/r103-gb11-br-candidate.rpm %[1]s/.defenseclaw/custom-providers.json; ` +
	`do if sudo test -e "$p"; then echo "PRESENT:$p"; else echo "ABSENT:$p"; fi; done; ` +
	`sudo find %[1]s/.defenseclaw -maxdepth 1 -name "custom-providers.json.migrated-v9*" -printf "%%p\n" > ` +
	`~/dc-eh/evidence/rel-1-0-3/groups/B-11/BR/G-B-11-BR-05/lane-artifacts-removed.raw printf 12. Remove only ` +
	`recorded lane-created migration backup/record, downgrade marker and candidate RPM; snapshot restore already ` +
	`removed overlay; verify all absent and no migrated suffix.\n >> ~/dc-eh/evidence/rel-1-0-3/groups/B-11/BR/G-B-11-BR-05/cmd.txt ` +
	`cat ~/dc-eh/evidence/rel-1-0-3/groups/B-11/BR/G-B-11-BR-05/lane-artifacts-removed.raw`

// TestGAP1014VerdictIgnoresTheLettersOfAPathOrWord is rel-1-0-10:GAP-1014.
// The gateway reads each statement of a ; / && / || list alone, in the
// folder a cd, pushd or popd of the list leads to, when the whole list is
// not proven (placedStatementStateWrite, GAP-2574). It turned that reading
// on when the letters cd, pushd or popd stood anywhere in the call text, so
// the owner-trace call 209 answered block CRITICAL with the s7-gate fixture
// root 1cd7970ba0a3 in its paths and block HIGH with 31e8ac4c00ed. The
// reading now needs a cd, pushd or popd program word (hookpaths.
// ChangesDirectory), so in the five tiers on the Claude Code and Codex hooks
// the call answers the same with every root, and a real directory change
// before the write keeps the verdict it has on rel.
func TestGAP1014VerdictIgnoresTheLettersOfAPathOrWord(t *testing.T) {
	base := t.TempDir()
	if strings.Contains(base, "cd") || strings.Contains(base, "pushd") || strings.Contains(base, "popd") {
		t.Fatalf("temp folder %s holds the letters under test; the cd-free oracle would not be cd-free", base)
	}
	// The oracle root holds none of the letters; every other root does.
	oracleRoot := "31e8ac4c00ed"
	roots := []string{"1cd7970ba0a3", "31e8acdc00ed", "31e8ac4c00cd", "fcd8a940d50d", "x-pushd-1", "x-popd-1"}
	homes := map[string]string{oracleRoot: gap1014Home(t, base, oracleRoot)}
	for _, root := range roots {
		homes[root] = gap1014Home(t, base, root)
	}
	// Real directory changes before the write: the placed reading is on.
	// want is the verdict on rel 22db7a8362 (the same in every root).
	type control struct {
		name, form, cwd string
		want            string
	}
	controls := []control{
		{"pushd-missing", "pushd /missing-gap1014; cp a.txt ../../.defenseclaw/config.yaml", "proj/sub", ""},
		{"cd-home-list", "cd %[1]s; cp proj/sub/a.txt .defenseclaw/config.yaml; ls", "proj", ""},
		{"cd-up-and", "cd .. && cp sub/a.txt ../.defenseclaw/config.yaml; true", "proj/sub", ""},
	}
	calls := 0
	for _, p := range gap0437Packs {
		for _, connector := range []string{"claudecode", "codex"} {
			a := gap0437Server(t, p, connector, "action")
			verdict := func(root, form, cwd string) string {
				t.Helper()
				home := homes[root]
				t.Setenv("HOME", home)
				calls++
				session := fmt.Sprintf("gap1014-%s-%s-%d", p.name, connector, calls)
				return gap1014Verdict(t, a, connector, session, filepath.Join(home, cwd), fmt.Sprintf(form, home), false)
			}
			oracle := verdict(oracleRoot, gap1014OwnerTrace, "")
			t.Logf("%s %s owner trace oracle: %s", p.name, connector, oracle)
			for _, root := range roots {
				if got := verdict(root, gap1014OwnerTrace, ""); got != oracle {
					t.Errorf("%s %s owner trace 209 in root %s: %s, want %s (root %s)", p.name, connector, root, got, oracle, oracleRoot)
				}
			}
			for _, c := range controls {
				want := verdict(oracleRoot, c.form, c.cwd)
				t.Logf("%s %s control %s: %s", p.name, connector, c.name, want)
				for _, root := range roots {
					if got := verdict(root, c.form, c.cwd); got != want {
						t.Errorf("%s %s control %s in root %s: %s, want %s", p.name, connector, c.name, root, got, want)
					}
				}
			}
		}
	}
}

// TestGAP1014PlacedStatementReadingNeedsADirectoryChange is the gate itself:
// placedStatementStateWrite reads the owner-trace call 209 the same in every
// fixture root (on rel 22db7a8362 it proved the state write only in a root
// holding the letters cd, pushd or popd), and a real cd, pushd or popd before
// the write still turns the placed reading on.
func TestGAP1014PlacedStatementReadingNeedsADirectoryChange(t *testing.T) {
	base := t.TempDir()
	if strings.Contains(base, "cd") || strings.Contains(base, "pushd") || strings.Contains(base, "popd") {
		t.Fatalf("temp folder %s holds the letters under test", base)
	}
	placed := func(root, form, cwd string) bool {
		t.Helper()
		home := gap1014Home(t, base, root)
		input := actionfacts.Input{Tool: "Bash", Command: fmt.Sprintf(form, home), CWD: filepath.Join(home, cwd), ActiveHome: home}
		return placedStatementStateWrite(actionfacts.Analyze(input), trustedActionRequest{Input: input})
	}
	oracle := placed("31e8ac4c00ed", gap1014OwnerTrace, "")
	for _, root := range []string{"1cd7970ba0a3", "31e8acdc00ed", "31e8ac4c00cd", "fcd8a940d50d", "x-pushd-1", "x-popd-1"} {
		if got := placed(root, gap1014OwnerTrace, ""); got != oracle {
			t.Errorf("owner trace 209 in root %s: placed state write %t, want %t (root 31e8ac4c00ed)", root, got, oracle)
		}
	}
	// A word that only holds the letters is no directory change either.
	for _, form := range []string{
		"echo abcd; cp %[1]s/proj/sub/a.txt %[1]s/.defenseclaw/config.yaml; ls",
		"ls xpushd.txt popdir; cp %[1]s/proj/sub/a.txt %[1]s/.defenseclaw/config.yaml",
	} {
		if got, want := placed("31e8ac4c00ed", form, ""), placed("31e8ac4c00ed", strings.NewReplacer("abcd", "abxy", "xpushd.txt", "xpu.txt", "popdir", "podir").Replace(form), ""); got != want {
			t.Errorf("%q: placed state write %t, want %t like the same call without the letters", form, got, want)
		}
	}
	// A real directory change before the write keeps the placed reading.
	for _, c := range []struct{ form, cwd string }{
		{"cd %[1]s; cp proj/sub/a.txt .defenseclaw/config.yaml; ls", "proj"},
		{"pushd %[1]s/proj; cp sub/a.txt ../.defenseclaw/config.yaml; popd", "proj/sub"},
		{"cd %[1]s/proj && cp sub/a.txt ../.defenseclaw/config.yaml; true", "proj/sub"},
	} {
		for _, root := range []string{"31e8ac4c00ed", "1cd7970ba0a3"} {
			if !placed(root, c.form, c.cwd) {
				t.Errorf("%q in root %s (cwd %s): no placed state write, want one (a real directory change)", c.form, root, c.cwd)
			}
		}
	}
}

// TestGAP1014TopLevelWriteIsReadWhenTheStatementsAreNotPlaced is the rv1014
// regression of the first GAP-1014 fix (3a4a3ef867): the hook-config guard
// skipped the whole command whenever it held a directory change and the
// reading had more than one entry, but that second entry can come from a
// nested bash -c body alone. When TopLevelStatements does not place the
// statements (popd;, cd; or popd on its own line, a cd inside { ...; }), the
// whole command is the only reading of a top-level write, and skipping it let
// popd; bash -c true; echo x > ~/.codex/hooks.json through (rel 22db7a8362:
// alert or block HIGH tamper.agent_hook_config_write; 3a4a3ef867: allow).
// The { cd /tmp; } form was the same hole on rel. Every form must keep the
// finding of the same write with no directory change at all (stronger is
// fine, weaker is the regression).
func TestGAP1014TopLevelWriteIsReadWhenTheStatementsAreNotPlaced(t *testing.T) {
	base := t.TempDir()
	home := gap1014Home(t, base, "31e8ac4c00ed")
	for _, dir := range []string{".codex", ".claude"} {
		if err := os.MkdirAll(filepath.Join(home, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".codex", "hooks.json"), []byte("{\"hooks\":{}}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// %[1]s is the home, %[2]s the written file under it (absolute or ~).
	oracleForm := "bash -c true; echo x > %[2]s"
	forms := []string{
		"popd; bash -c true; echo x > %[2]s",
		"cd; bash -c true; echo x > %[2]s",
		"popd\nbash -c true\necho x > %[2]s",
		"cd\nbash -c true\necho x > %[2]s",
		"popd; sh -c 'true'; echo x > %[2]s",
		"{ cd /tmp; }; bash -c true; echo x > %[2]s",
		"{ popd; }; bash -c true; echo x > %[2]s",
		// Placed forms: TopLevelStatements reads them, and only then is the
		// whole command skipped.
		"cd /tmp; bash -c true; echo x > %[2]s",
		"pushd %[1]s; bash -c true; echo x > %[2]s",
	}
	targets := []string{"%[1]s/.codex/hooks.json", "~/.codex/hooks.json", "%[1]s/.claude/settings.json", "~/.claude/settings.json"}
	const rule = "tamper.agent_hook_config_write"
	calls := 0
	for _, p := range gap0437Packs {
		for _, connector := range []string{"claudecode", "codex"} {
			a := gap0437Server(t, p, connector, "action")
			t.Setenv("HOME", home)
			verdict := func(form, target string) string {
				t.Helper()
				calls++
				session := fmt.Sprintf("gap1014-top-%s-%s-%d", p.name, connector, calls)
				command := fmt.Sprintf(form, home, strings.ReplaceAll(target, "%[1]s", home))
				return gap1014Verdict(t, a, connector, session, filepath.Join(home, "proj"), command, false)
			}
			for _, target := range targets {
				want := verdict(oracleForm, target)
				if strings.HasPrefix(want, "allow") || !strings.Contains(want, rule) {
					t.Fatalf("%s %s oracle %q on %s: %s, want a %s verdict", p.name, connector, oracleForm, target, want, rule)
				}
				for _, form := range forms {
					if got := verdict(form, target); strings.HasPrefix(got, "allow") || !strings.Contains(got, rule) {
						t.Errorf("%s %s %q on %s: %s, want %s or stronger (the same write with no directory change)", p.name, connector, form, target, got, want)
					}
				}
			}
		}
	}
}
