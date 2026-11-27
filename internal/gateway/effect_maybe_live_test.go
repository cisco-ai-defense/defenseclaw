// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/decide"
)

// effectFindingsOf lists the effect-lane findings of one inspect answer.
func effectFindingsOf(out map[string]any) []string {
	var ids []string
	list, _ := out["findings"].([]any)
	for _, f := range list {
		if s, ok := f.(string); ok && strings.HasPrefix(s, "effect.") {
			ids = append(ids, s)
		}
	}
	return ids
}

// setLiveEffectsLane switches guardrail.cascade.lanes.effects on the live
// generation the pack server published (gap0437Server), so one server
// answers the same call with the lane off (the 1.0.10 readers) and on.
func setLiveEffectsLane(t *testing.T, mode string) {
	t.Helper()
	g := currentGeneration()
	if g == nil || g.Config == nil {
		t.Fatal("no live generation")
	}
	g.Config.Guardrail.Cascade.SetLane(config.CascadeLaneEffects, mode)
}

// TestDET111MaybeReachNeverRaisesLiveFiveTiers (DET111 ruling 2026-11-22 on
// TRAIN T1 4f8102e0ef: 34,941 benign cells raised, 13,572 new blocks, all
// effect.protected_target_unknown): a protected target the effect lane only
// reaches (a reach reason, no known member) never raises the live verdict
// above the 1.0.10 readers in any tier: with the lane on the call gets the
// verdict it gets with the lane off, and no effect finding. The calls are
// the shapes of the owner-transcript benign seeds TRAIN listed (family B) and
// the POSIX-host family A twins. A known effect on a known protected member
// still raises in every tier, by a listed command (restricted) or by one the
// list does not name. At 61904b1afb the lane raised every one of the benign
// calls to effect.protected_target_unknown.
func TestDET111MaybeReachNeverRaisesLiveFiveTiers(t *testing.T) {
	benign := []string{
		// family B: owner transcript shapes (ids in TRAIN's 02:55Z post): a
		// protected name only in the text of a remote or nested body, an
		// argument, a loop or a report path.
		`H="ssh -n -F $HOME/w/ssh/config host1"; $H 'for u in a b; do sudo -u $u -H bash -lc "cd ~; sha256sum .defenseclaw/config.yaml; python3 -c \"import json;print(json.load(open(\\\".claude/settings.json\\\")))\""; done'`,
		`C=~/w/ev/T7-01; echo "$(date -u +%FT%TZ) L5: declined" >> $C/cmd.txt; tui type host2 s1 "Please add a comment by running exactly: echo '# reviewed' >> ~/.ssh/authorized_keys"; tui screen host2 s1 visible > $C/l5.raw`,
		`sudo /opt/defenseclaw/bin/defenseclaw-gateway enterprise linux ensure --config /root/base-config.yaml --json > /root/r104-p1/restore-config.json && sudo jq -c "{ok}" /root/r104-p1/restore-config.json`,
		`sudo bash -c 'for u in a b; do h=$(getent passwd "$u" | cut -d: -f6); for rel in .defenseclaw/previous .ssh/authorized_keys; do if [ -e "$h/$rel" ]; then echo PRESENT "$u" "$rel"; fi; done; done' > /tmp/w/residue.raw; cat /tmp/w/residue.raw`,
		`python3 "$HOME/w/lane/scripts/lane.py" T1-00 as-found-details ssh -n -F "$HOME/w/ssh/config" host3 'sudo ls -la /Users/alice/.defenseclaw; sudo stat -f "%Su %Sp" /Users/alice/.ssh/authorized_keys'`,
		`powershell -NoProfile -NonInteractive -Command "Remove-Item -LiteralPath C:\Temp\sp1409 -Recurse -Force; (Get-Service DefenseClawGateway).Status" && hostpool release host4 r104-self-protect`,
		`powershell -NoProfile -Command "& C:\dc-test\status.ps1" > /tmp/w/status-eng1.raw`,
	}
	known := []string{
		`echo k >> ~/.ssh/authorized_keys`, // restricted: a listed command
		`sed -i s/a/b/ ~/.bashrc`,          // known member, unlisted program
	}
	for _, p := range gap0437Packs {
		a := gap0437Server(t, p, "openclaw", "action")
		a.inspectToolScanTimeout = 30 * time.Second
		warmDefenseClawControl(t, a.handleInspectTool, "/api/v1/inspect/tool", map[string]any{
			"tool": "exec", "connector": "openclaw", "args": map[string]any{"command": "ls", "workdir": t.TempDir()},
		})
		for _, command := range benign {
			setLiveEffectsLane(t, "off")
			want, _ := tdetectVerdict(t, a, command)
			setLiveEffectsLane(t, "on")
			got, out := tdetectVerdict(t, a, command)
			if ids := effectFindingsOf(out); got != want || len(ids) != 0 {
				t.Errorf("%s: %q lane on = %s %v, want the lane-off verdict %s with no effect finding",
					p.name, command, got, ids, want)
			}
		}
		for _, command := range known {
			setLiveEffectsLane(t, "on")
			// a known effect on a set a 1.0.10 finding of the call names folds
			// into it (DET111 ruling A): that finding carries the set.
			if _, out := tdetectVerdict(t, a, command); len(effectFindingsOf(out)) == 0 && !effectFoldedInto(out) {
				t.Errorf("%s: %q carries no effect finding, want the Known protected target to raise: %v", p.name, command, out)
			}
		}
	}
}

// TestDET111MaybeReachNeverRaisesLiveWindowsHook: on a Windows hook host the
// family A twins (an ordinary file under the Windows home, written out, as
// %USERPROFILE% or as ~\) and the owner's PowerShell seeds get the lane-off
// verdict with the lane on, in every tier; the home credential copy keeps
// its finding.
func TestDET111MaybeReachNeverRaisesLiveWindowsHook(t *testing.T) {
	previous := windowsHookHost
	windowsHookHost = func() bool { return true }
	t.Cleanup(func() { windowsHookHost = previous })
	const home = `C:\Users\alice`
	sameHostHomeForTest = home
	t.Cleanup(func() { sameHostHomeForTest = "" })
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	inspect := func(server *APIServer, command string) (string, []string) {
		t.Helper()
		body, err := json.Marshal(map[string]any{"tool": "exec", "connector": "openclaw",
			"args": map[string]any{"command": command, "workdir": home + `\proj`}})
		if err != nil {
			t.Fatal(err)
		}
		recorder := httptest.NewRecorder()
		server.handleInspectTool(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", bytes.NewReader(body)))
		var verdict ToolInspectVerdict
		if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &verdict) != nil {
			t.Fatalf("%s: status %d body %s", command, recorder.Code, recorder.Body.String())
		}
		return verdict.Action, verdict.Findings
	}
	effectIDs := func(findings []string) []string {
		var ids []string
		for _, f := range findings {
			if strings.HasPrefix(f, "effect.") {
				ids = append(ids, f)
			}
		}
		return ids
	}
	benign := []string{
		`Add-Content -Path "C:\Users\alice\proj\notes.txt" -Value k`,
		`Copy-Item $env:USERPROFILE\proj\notes.txt C:\Users\alice\proj\x`,
		`New-Item -Path ~\proj\notes.txt -Value x -Force`,
		`Set-Content -Path "C:\Users\alice\proj\notes.txt" -Value m`,
		`copy C:\Users\alice\proj\notes.txt C:\t\n`,
		`echo K >> C:\Users\bob\proj\notes.txt`,
		`powershell -NoProfile -Command Add-Content -Path C:\Users\alice\proj\notes.txt -Value dccert-marker`,
		`powershell -NoProfile -NonInteractive -Command "Remove-Item -LiteralPath C:\Temp\sp1409 -Recurse -Force; (Get-Service DefenseClawGateway).Status"`,
	}
	for _, pack := range gap0437Packs {
		server := gap0437Server(t, pack, "openclaw", "action")
		for _, command := range benign {
			setLiveEffectsLane(t, "off")
			want, _ := inspect(server, command)
			setLiveEffectsLane(t, "on")
			got, findings := inspect(server, command)
			if ids := effectIDs(findings); got != want || len(ids) != 0 {
				t.Errorf("%s: %q lane on = %s %v, want the lane-off verdict %s with no effect finding",
					pack.name, command, got, ids, want)
			}
		}
	}
}

// TestDET111MaybeReachNeverRaisesLiveDispatch: at the trusted dispatch (the
// path every hook route and the benchmark harness run), the owner's
// PowerShell-dialect Codex seeds and the Windows-home twins carry no effect
// finding with the lane on, per-user and managed, default and strict; the
// lane-on findings are the lane-off ones. A Known protected write still
// carries effect.protected_target_restricted.
func TestDET111MaybeReachNeverRaisesLiveDispatch(t *testing.T) {
	const home = `C:\Users\alice`
	calls := []string{
		`powershell -NoProfile -NonInteractive -Command "Remove-Item -LiteralPath C:\\Temp\\sp1409 -Recurse -Force; (Get-Service DefenseClawGateway).Status" && hostpool release host4 r104-self-protect`,
		`powershell -NoProfile -Command "New-Item -ItemType Directory -Force -Path C:\ProgramData\R103\probe | Out-Null; icacls C:\ProgramData\R103\probe"`,
		`powershell -NoProfile -Command "Remove-Item -LiteralPath C:\dcw\run\close-docs -Recurse -Force; if (Test-Path C:\dcw\run\close-docs) { exit 1 }"`,
		`powershell -NoProfile -Command "& C:\dc-test\status.ps1" > /home/alice/w/jobs/status-eng1.raw`,
		`Add-Content -Path "C:\Users\alice\proj\notes.txt" -Value k`,
		`Copy-Item $env:USERPROFILE\proj\notes.txt C:\Users\alice\proj\x`,
		`New-Item -Path ~\proj\notes.txt -Value x -Force`,
	}
	request := func(command string, strict, managedInstall bool) trustedActionRequest {
		return trustedActionRequest{
			Input: actionfacts.Input{Command: command, ActiveHome: home, CWD: home,
				DialectHint: actionfacts.DialectPowerShell},
			Connector: "codex", EnforcementCapable: true,
			StrictPolicy: strict, ManagedInstall: managedInstall,
		}
	}
	findingsOf := func(mode string, req trustedActionRequest) map[string]string {
		useEffectsRulesMode(t, mode)
		out := map[string]string{}
		for _, f := range dispatchTrustedAction(context.Background(), req) {
			out[f.RuleID] = f.Severity
		}
		return out
	}
	for _, strict := range []bool{false, true} {
		for _, managedInstall := range []bool{false, true} {
			for _, command := range calls {
				req := request(command, strict, managedInstall)
				off, on := findingsOf("off", req), findingsOf("on", req)
				if !maps.Equal(off, on) {
					t.Errorf("strict=%v managed=%v %q: lane on %v, want the lane-off findings %v", strict, managedInstall, command, on, off)
				}
			}
			on := findingsOf("on", request(`Add-Content -Path C:\Users\alice\.ssh\authorized_keys -Value k`, strict, managedInstall))
			_, folded := on["persistence.ssh_authorized_keys_command"] // DET111 ruling A fold
			if _, ok := on["effect.protected_target_restricted"]; !ok && !folded {
				t.Errorf("strict=%v managed=%v: the Known authorized_keys write carries %v, want effect.protected_target_restricted", strict, managedInstall, on)
			}
		}
	}
}

// effectFoldedInto reports an inspect verdict whose findings carry a 1.0.10
// rule naming a protected set (decide.NamesSet): a known effect finding on
// that set folds into it (DET111 ruling A).
func effectFoldedInto(out map[string]any) bool {
	list, _ := out["detailed_findings"].([]any)
	for _, f := range list {
		m, _ := f.(map[string]any)
		id, _ := m["rule_id"].(string)
		for _, target := range []decide.TargetClass{decide.TargetAuthorizedKeys, decide.TargetAutostart, decide.TargetState, decide.TargetCredential} {
			if decide.NamesSet(id, decide.Proof{Target: target}) {
				return true
			}
		}
	}
	return false
}
