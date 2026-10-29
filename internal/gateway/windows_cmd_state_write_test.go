// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestR105WindowsCMDStateWriteThroughNul: a cmd redirect, copy or rename
// whose target is DefenseClaw state is tamper.detector_state_write in action
// mode whatever the source is. type nul > state truncates it, copy nul state
// empties it, ren state x removes it (GAP-2408); the null device read made
// the command partial and %USERPROFILE% lost the target.
func TestR105WindowsCMDStateWriteThroughNul(t *testing.T) {
	const connectorName = "r105-cmd-state"
	installToolCallCorpusProfileConnector(t, connectorName, "default")
	const home = `C:\Users\Alice`
	for _, tc := range []struct {
		command string
		block   bool
	}{
		{`type nul > %USERPROFILE%\.defenseclaw\config.yaml`, true},
		{`type nul > C:\Users\Alice\.defenseclaw\config.yaml`, true},
		{`type nul >> %USERPROFILE%\.defenseclaw\config.yaml`, true},
		{`type nul 1> %USERPROFILE%\.defenseclaw\config.yaml`, true},
		{`type nul 2> %USERPROFILE%\.defenseclaw\config.yaml`, true},
		{`type NUL > "%USERPROFILE%\.defenseclaw\config.yaml"`, true},
		{`type a.txt & type nul > %USERPROFILE%\.defenseclaw\config.yaml`, true},
		{`copy nul %USERPROFILE%\.defenseclaw\config.yaml`, true},
		{`copy /y nul C:\Users\Alice\.defenseclaw\config.yaml`, true},
		{`ren %USERPROFILE%\.defenseclaw\config.yaml config.bak`, true},
		{`rename C:\Users\Alice\.defenseclaw\policies\default.yaml x.yaml`, true},
		{`ren notes.txt n.bak & type nul > %USERPROFILE%\.defenseclaw\.env`, true},
		{`echo x > %USERPROFILE%\.defenseclaw\config.yaml`, true},
		// Ordinary work stays allowed.
		{`type nul > notes.txt`, false},
		{`type nul > %USERPROFILE%\project\out.txt`, false},
		{`copy nul %USERPROFILE%\project\empty.txt`, false},
		{`type %USERPROFILE%\.defenseclaw\config.yaml`, false},
		{`ren notes.txt notes.bak`, false},
		{`ren %USERPROFILE%\project\a.txt b.txt`, false},
		{`type nul`, false},
		{`echo x > nul`, false},
		{`type a.txt 2>nul`, false},
		{`copy nul NUL`, false},
		{`type nul > %USERPROFILE%\.defenseclaw-notes.txt`, false},
	} {
		args, _ := json.Marshal(map[string]string{"command": tc.command})
		input := actionfacts.Input{
			Tool: "Bash", Args: args, CWD: home + `\project`, ActiveHome: home,
			DialectHint: actionfacts.DialectCMD,
		}
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: input, LegacyText: string(args), Connector: connectorName, EnforcementCapable: true,
		})
		verdict := buildVerdict(findings, "tool_call")
		if got := verdict.Action == "block"; got != tc.block {
			t.Errorf("%s: action %q, want block=%t (findings %v)", tc.command, verdict.Action, tc.block, findings)
		}
		if tc.block && !slices.ContainsFunc(findings, func(f RuleFinding) bool {
			return f.RuleID == "tamper.detector_state_write"
		}) {
			t.Errorf("%s: no tamper.detector_state_write finding: %v", tc.command, findings)
		}
	}
}

// TestR105WindowsCMDSlashCStateWrite: the same writes handed to cmd.exe by a
// PowerShell or Git Bash tool call as cmd /c BODY (GAP-2408 live rows S1-S7,
// S9). The gateway resolves the write target on the Windows host; the test
// supplies that map as the hook does.
func TestR105WindowsCMDSlashCStateWrite(t *testing.T) {
	const connectorName = "r105-cmd-slash-c"
	installToolCallCorpusProfileConnector(t, connectorName, "default")
	const home = `C:\Users\Alice`
	resolved := map[string]string{}
	for _, name := range []string{"config.yaml", ".env", "config.bak", `policies/default.yaml`} {
		value := "C:/Users/Alice/.defenseclaw/" + name
		resolved[value] = value
	}
	const state = `%USERPROFILE%\.defenseclaw\config.yaml`
	for _, tc := range []struct {
		command string
		block   bool
	}{
		{`cmd /c "type nul > ` + state + `"`, true},
		{`cmd /c "type nul >> ` + state + `"`, true},
		{`cmd /c copy /y nul ` + state, true},
		{`cmd /c ren ` + state + ` config.bak`, true},
		{`cmd.exe /c "type nul > C:\Users\Alice\.defenseclaw\config.yaml"`, true},
		{`cmd /c "echo x > ` + state + `"`, true},
		{`cmd /q /c "type notes.txt & type nul > ` + state + `"`, true},
		{`C:\Windows\System32\cmd.exe /c "type nul > ` + state + `"`, true},
		{`cmd /c "cmd /c type nul > ` + state + `"`, true},
		// Every way an agent hands the body to cmd.exe (checker it8 RV8-1).
		{`& cmd /c "type nul > ` + state + `"`, true},
		{`cmd /c 'type nul > ` + state + `'`, true},
		{`cmd.exe /c 'echo x > ` + state + `'`, true},
		{`cmd //c "type nul > ` + state + `"`, true},
		{`cmd //c 'type nul > ` + state + `'`, true},
		{`cmd/c "type nul > ` + state + `"`, true},
		{`cmd /v:on /c "type nul > ` + state + `"`, true},
		{`cmd /e:on /c "type nul > ` + state + `"`, true},
		{`cmd /u /c "type nul > ` + state + `"`, true},
		{`cmd /k "type nul > ` + state + `"`, true},
		{`cmd //k "echo x > ` + state + `"`, true},
		{`& $env:ComSpec /c "type nul > ` + state + `"`, true},
		{`& ${env:ComSpec} /c "type nul > ` + state + `"`, true},
		{`%ComSpec% /c "type nul > ` + state + `"`, true},
		{`Start-Process cmd -ArgumentList '/c type nul > ` + state + `' -Wait`, true},
		{`Start-Process -FilePath cmd.exe -ArgumentList "/c copy /y nul ` + state + `" -Wait`, true},
		{`"C:\Windows\System32\cmd.exe" /c "type nul > ` + state + `"`, true},
		{`Write-Output a; & cmd /c 'type nul > ` + state + `'`, true},
		// An -ArgumentList array is joined with spaces (checker it9 RV9-2 X11).
		{`Start-Process -FilePath cmd.exe -ArgumentList '/c','type nul > ` + state + `' -Wait`, true},
		{`Start-Process cmd '/c type nul > ` + state + `'`, true},
		{`powershell -Command "cmd /c 'type nul > ` + state + `'"`, true},
		{`Write-Output "$(cmd /c type nul > ` + state + `)"`, true},
		// Ordinary work stays allowed.
		{`cmd /c "type nul > notes8.txt"`, false},
		{`cmd /c copy /y nul empty8.txt`, false},
		{`cmd /c ren notes8.txt notes8b.txt`, false},
		{`cmd /c type ` + state, false},
		{`cmd /c "type notes.txt 2>nul"`, false},
		{`cmd /c dir %USERPROFILE%\.defenseclaw`, false},
		{`& cmd /c "type nul > notes8.txt"`, false},
		{`cmd //c 'dir'`, false},
		{`cmd /k "echo hi"`, false},
		{`cmd /v:on /c "echo !PATH! > notes.txt"`, false},
		{`Start-Process cmd -ArgumentList '/c type nul > notes.txt' -Wait`, false},
		{`& $env:ComSpec /c "copy ` + state + ` backup.yaml"`, false},
		{`cmd /c 'type nul > %USERPROFILE%\.defenseclawx\a.txt'`, false},
		{`cmdkey /list`, false},
		{`Write-Output 'cmd /c dir'`, false},
		// A text that only mentions the cmd state write (checker it9 RV9-1).
		{`Write-Output 'Tip: cmd /c type nul > ` + state + ` empties the config'`, false},
		{`git commit -m 'block cmd //c "type nul > ` + state + `"'`, false},
		{`git commit -m "fix: block cmd /c type nul > ` + state + `"`, false},
		{"@'\nnotes: cmd /c type nul > " + state + "\n'@ | Set-Content notes.md", false},
		{`gh issue comment 1 --body "repro: & cmd /c 'type nul > ` + state + `'"`, false},
		{`Write-Output "Start-Process cmd -ArgumentList '/c type nul > ` + state + `'"`, false},
		{"# cmd /c type nul > " + state + "\nGet-ChildItem", false},
		{`cmd /c echo see cmd /c type nul docs`, false},
		// Every reading of the outer shell is judged; an unterminated quote
		// is no text span; a runner is a shell word, not any -c (checker
		// it10 RV10-1, RV10-2).
		{`echo don\'t; cmd //c "type nul > ` + state + `"`, true},
		{`echo $'it\'s'; cmd //c "type nul > ` + state + `"`, true},
		{"cat > n.txt <<EOF\ndon't\nEOF\ncmd //c \"type nul > " + state + "\"", true},
		{`<# don't #> cmd /c "type nul > ` + state + `"`, true},
		{`Write-Output "C:\temp\"; cmd /c "type nul > ` + state + `"`, true},
		{`bash -lc "cmd //c 'type nul > ` + state + `'"`, true},
		{`iex("cmd /c 'type nul > ` + state + `'")`, true},
		{`powershell "cmd /c 'type nul > ` + state + `'"`, true},
		{`& 'C:\Windows\System32\cmd.exe' /c 'type nul > ` + state + `'`, true},
		{`echo \"; cmd //c "type nul > ` + state + `"`, true},
		{`x='a'\''b'; cmd //c "type nul > ` + state + `"`, true},
		{`echo {# ; cmd //c "type nul > ` + state + `"`, true},
		{"echo \"`cmd //c 'type nul > " + state + "'`\"", true},
		{`Write-Output ‘a'b’; cmd /c "type nul > ` + state + `"`, true},
		{`Start-Process powershell -ArgumentList '-c "cmd /c type nul > ` + state + `"'`, true},
		{`Start-Process cmd -ArgumentList @('/c','type nul > ` + state + `')`, true},
		{strings.Repeat("cmd /c echo 0; ", 70) + `cmd /c "type nul > ` + state + `"`, true},
		{`grep -c "cmd /c type nul > ` + state + `" notes.md`, false},
		{`rg -c 'cmd /c del ` + state + `' docs`, false},
		{`git log --grep "cmd /c type nul > ` + state + `"`, false},
		{`bash -lc "grep -c 'cmd /c type nul > ` + state + `' notes.md"`, false},
		{`iex "Write-Output 'cmd /c type nul > ` + state + `'"`, false},
		{`Write-Output x; cmd /c dir`, false},
		{`Start-Process cmd -ArgumentList '/c','type nul > notes.txt' -Wait`, false},
	} {
		for _, tool := range []string{"Bash", "shell_command", "PowerShell"} {
			args, _ := json.Marshal(map[string]string{"command": tc.command})
			input := actionfacts.Input{Tool: tool, Args: args, CWD: home + `\project`, ActiveHome: home}
			input.DialectHint = agentHookWindowsShellDialect(input)
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, LegacyText: string(args), Connector: connectorName,
				EnforcementCapable: true, ResolvedWriteTargets: resolved,
			})
			verdict := buildVerdict(findings, "tool_call")
			if got := verdict.Action == "block"; got != tc.block {
				t.Errorf("%s %s (dialect %q): action %q, want block=%t (findings %v)",
					tool, tc.command, input.DialectHint, verdict.Action, tc.block, findings)
			}
		}
	}
}

// TestR105WindowsCMDStateDirectoryRemove: a cmd /c body that removes or
// moves the DefenseClaw state directory itself is a state mutation, as the
// same command typed into cmd is (checker it9 RV9-2 X02, X07). The hook
// supplies the resolved directory, as it does on the Windows host.
func TestR105WindowsCMDStateDirectoryRemove(t *testing.T) {
	const connectorName = "r105-cmd-state-dir"
	installToolCallCorpusProfileConnector(t, connectorName, "default")
	const home = `C:\Users\Alice`
	resolved := map[string]string{}
	for _, value := range []string{"C:/Users/Alice/.defenseclaw", "C:/Users/Alice/.defenseclaw/config.yaml",
		"C:/Users/Alice/.defenseclawx", "C:/Users/Alice/project/build"} {
		resolved[value] = value
	}
	for _, tc := range []struct {
		command string
		block   bool
	}{
		{`cmd //c "rmdir /s /q %USERPROFILE%\.defenseclaw"`, true},
		{`cmd /d /c rd /s /q %USERPROFILE%\.defenseclaw`, true},
		{`cmd /c rd /s /q C:\Users\Alice\.defenseclaw`, true},
		{`& cmd /c 'rmdir /s /q %USERPROFILE%\.defenseclaw'`, true},
		{`cmd /c move %USERPROFILE%\.defenseclaw %USERPROFILE%\dc-old`, true},
		// Ordinary work stays allowed.
		{`cmd /c dir %USERPROFILE%\.defenseclaw`, false},
		{`cmd /c rd /s /q %USERPROFILE%\.defenseclawx`, false},
		{`cmd /c rd /s /q build`, false},
		{`Write-Output 'cmd /c rd /s /q %USERPROFILE%\.defenseclaw'`, false},
	} {
		for _, tool := range []string{"Bash", "shell_command", "PowerShell"} {
			args, _ := json.Marshal(map[string]string{"command": tc.command})
			input := actionfacts.Input{Tool: tool, Args: args, CWD: home + `\project`, ActiveHome: home}
			input.DialectHint = agentHookWindowsShellDialect(input)
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, LegacyText: string(args), Connector: connectorName,
				EnforcementCapable: true, ResolvedWriteTargets: resolved,
			})
			verdict := buildVerdict(findings, "tool_call")
			if got := verdict.Action == "block"; got != tc.block {
				t.Errorf("%s %s (dialect %q): action %q, want block=%t (findings %v)",
					tool, tc.command, input.DialectHint, verdict.Action, tc.block, findings)
			}
		}
	}
}

// TestR105WindowsCMDBodyReaderIsLinear: the cmd body reader stays far inside
// the hook budget on large crafted commands (checker it10 RV10-3: 32 KB took
// 8.8 s at 60f41d7b57), and a command it cannot read within its bounds
// counts as the state write it may hide.
func TestR105WindowsCMDBodyReaderIsLinear(t *testing.T) {
	const size = 64 << 10
	for _, unit := range []string{"'a' ", "cmd x 'a' ", "cmd /c x ", "\"$(", "cmd -args 'a' ", "a; "} {
		command := "cmd x " + strings.Repeat(unit, size/len(unit))
		start := time.Now()
		cmdInvocationReadings(command, true)
		if took := time.Since(start); took > 2*time.Second {
			t.Errorf("unit %q: %d bytes read in %s", unit, len(command), took)
		}
	}
	const state = `%USERPROFILE%\.defenseclaw\config.yaml`
	request := trustedActionRequest{Input: actionfacts.Input{
		Tool: "PowerShell", Command: strings.Repeat("cmd /c x ", 1000) + "type nul > " + state,
		CWD: `C:\Users\Alice\project`, ActiveHome: `C:\Users\Alice`, DialectHint: actionfacts.DialectPowerShell,
	}}
	if !provenCMDSlashCStateWrite(request) {
		t.Errorf("a command beyond the reader bounds is not judged a state write")
	}
}

// TestR105WindowsCMDHeredocReceiverReadIsLinear: the here-document receiver
// reads of one Git Bash command stay linear (checker it6 of GAP-2539: one
// read of the whole line per double-quoted << span took 2 m 48 s for 58 KB of
// echo "<<";), and a command beyond their bounds over-reads: the state write
// still blocks and an ordinary command still runs.
func TestR105WindowsCMDHeredocReceiverReadIsLinear(t *testing.T) {
	const connectorName = "r105-cmd-heredoc-linear"
	installToolCallCorpusProfileConnector(t, connectorName, "default")
	const home = `C:\Users\Alice`
	resolved := map[string]string{}
	for _, value := range []string{"C:/Users/Alice/.defenseclaw", "C:/Users/Alice/.defenseclaw/config.yaml"} {
		resolved[value] = value
	}
	const state = `%USERPROFILE%\.defenseclaw\config.yaml`
	const size = 64 << 10
	for _, tc := range []struct {
		unit, tail string
		block      bool
	}{
		{"echo \"<<\"; ", "cmd /c type nul > " + state, true},
		{"echo \"<<\"; ", "git status", false},
		{"echo \"$(cat <<'A'\nx\nA\n)\"; ", "cmd /c type nul > " + state, true},
		{"cat <<'A' <<'A' ", "\nx\nA\ny\nA\ngit status", false},
		{"{ cat <<'A'\nx\nA\n", "} | cmd /c type nul > " + state, true},
		{"cat >> notes.md <<'A'\nsome note\nA\n", "git status", false},
	} {
		command := strings.Repeat(tc.unit, size/len(tc.unit)) + tc.tail
		args, _ := json.Marshal(map[string]string{"command": command})
		input := actionfacts.Input{Tool: "Bash", Args: args, CWD: home + `\project`, ActiveHome: home}
		input.DialectHint = agentHookWindowsShellDialect(input)
		start := time.Now()
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: input, LegacyText: string(args), Connector: connectorName,
			EnforcementCapable: true, ResolvedWriteTargets: resolved,
		})
		took := time.Since(start)
		verdict := buildVerdict(findings, "tool_call")
		if got := verdict.Action == "block"; got != tc.block {
			t.Errorf("unit %q tail %q: action %q, want block=%t", tc.unit, tc.tail, verdict.Action, tc.block)
		}
		if took > 2*time.Second {
			t.Errorf("unit %q: %d bytes read in %s", tc.unit, len(command), took)
		}
	}
}

// TestR105WindowsCMDHeredocDelimiterSearchIsLinear: finding the delimiter
// lines of many here-documents stays linear in the command when the code
// read for redefinitions has the bodies blanked, or a delimiter never comes
// (GAP-2557: 1 MiB of { cat <<A .. } | state write took ~60 s), and when
// every line of a { } re-read each body waiting for it to close. The time
// for 256 KB must stay near 16x the best time for 16 KB (quadratic is
// 256x), and the decision is the same at both sizes.
func TestR105WindowsCMDHeredocDelimiterSearchIsLinear(t *testing.T) {
	const connectorName = "r105-cmd-heredoc-delim-linear"
	installToolCallCorpusProfileConnector(t, connectorName, "default")
	const home = `C:\Users\Alice`
	resolved := map[string]string{}
	for _, value := range []string{"C:/Users/Alice/.defenseclaw", "C:/Users/Alice/.defenseclaw/config.yaml"} {
		resolved[value] = value
	}
	const write = "cmd /c type nul > %USERPROFILE%\\.defenseclaw\\config.yaml"
	decide := func(command string, runs int) (bool, time.Duration) {
		args, _ := json.Marshal(map[string]string{"command": command})
		input := actionfacts.Input{Tool: "Bash", Args: args, CWD: home + `\project`, ActiveHome: home}
		input.DialectHint = agentHookWindowsShellDialect(input)
		best := time.Duration(-1)
		block := false
		for range runs {
			start := time.Now()
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, LegacyText: string(args), Connector: connectorName,
				EnforcementCapable: true, ResolvedWriteTargets: resolved,
			})
			if took := time.Since(start); best < 0 || took < best {
				best = took
			}
			block = buildVerdict(findings, "tool_call").Action == "block"
		}
		return block, best
	}
	distinct := func(size int) string {
		var b strings.Builder
		for k := 0; b.Len() < size; k++ {
			fmt.Fprintf(&b, "cat <<'A%d'\n", k)
		}
		return b.String()
	}
	for _, tc := range []struct {
		name  string
		build func(size int) string
		block bool
	}{
		{"brace docs, state write", func(size int) string {
			return "{\n" + strings.Repeat("cat <<'A'\nx\nA\n", size/14) + "} | " + write
		}, true},
		{"nested brace docs, state write", func(size int) string {
			return "{\n" + strings.Repeat("{ cat <<'A'\nx\nA\n}\n", size/18) + "} | " + write
		}, true},
		{"brace docs, benign", func(size int) string {
			return "{\n" + strings.Repeat("cat <<'A'\nx\nA\n", size/14) + "} | grep -c x\ngit status"
		}, false},
		{"unterminated docs, state write", func(size int) string {
			return strings.Repeat("cat <<'A'\n", size/10) + write
		}, true},
		{"unterminated distinct docs, state write", func(size int) string {
			return distinct(size) + write
		}, true},
		{"unterminated substitution docs, state write", func(size int) string {
			return strings.Repeat("x=$(cat <<'A'\n", size/14) + write
		}, true},
	} {
		smallBlock, small := decide(tc.build(16<<10), 3)
		bigBlock, big := decide(tc.build(256<<10), 1)
		t.Logf("%s: 16 KB %s, 256 KB %s", tc.name, small, big)
		if smallBlock != tc.block || bigBlock != tc.block {
			t.Errorf("%s: block %t at 16 KB, %t at 256 KB, want %t", tc.name, smallBlock, bigBlock, tc.block)
		}
		if big > 48*small+200*time.Millisecond {
			t.Errorf("%s: 16 KB in %s, 256 KB in %s (not linear)", tc.name, small, big)
		}
	}
}

// TestR105WindowsCMDMentionsAndManyCalls: text that only mentions a cmd.exe
// state write in a Git Bash here-document body stays allowed, as does an
// ordinary command with many cmd calls and a DefenseClaw state read; a
// here-document fed to a shell or to cmd, an unquoted body's $(...) and a
// stop-parsing cmd call still block (checker it11 RV11-1, RV11-2, K01).
func TestR105WindowsCMDMentionsAndManyCalls(t *testing.T) {
	const connectorName = "r105-cmd-mentions"
	installToolCallCorpusProfileConnector(t, connectorName, "default")
	const home = `C:\Users\Alice`
	resolved := map[string]string{}
	for _, value := range []string{"C:/Users/Alice/.defenseclaw", "C:/Users/Alice/.defenseclaw/config.yaml"} {
		resolved[value] = value
	}
	const state = `%USERPROFILE%\.defenseclaw\config.yaml`
	steps := func(format string, n int, sep, tail string) string {
		var parts []string
		for k := range n {
			parts = append(parts, strings.ReplaceAll(format, "N", strconv.Itoa(k)))
		}
		return strings.Join(parts, sep) + sep + tail
	}
	for _, tc := range []struct {
		command string
		block   bool
	}{
		{"git commit -m \"$(cat <<'EOF'\nfix: block cmd /c type nul > " + state + "\n\nEOF\n)\"", false},
		{"cat > notes.md <<'EOF'\nTip: cmd /c type nul > " + state + " empties the config\nEOF", false},
		{"cat > notes.md <<'EOF'\nrepro: cmd //c \"rmdir /s /q %USERPROFILE%\\.defenseclaw\"\nEOF", false},
		{"cat > notes.md <<EOF\nTip: cmd /c type nul > " + state + " empties it\nEOF", false},
		{"cat > notes.md <<-'EOF'\n\tdon't run cmd /c type nul > " + state + "\n\tEOF\necho done", false},
		{steps("cmd /c echo stepN", 8, "; ", `Get-Content $HOME\.defenseclaw\config.yaml`), false},
		{steps("cmd /c echo stepN", 20, "; ", `Get-Content $HOME\.defenseclaw\config.yaml`), false},
		{steps("cmd /c ver", 12, "; ", `cmd /c dir %USERPROFILE%\.defenseclaw`), false},
		{steps("cmd //c echo sN", 12, " && ", "cat ~/.defenseclaw/config.yaml"), false},
		// Still a state write.
		{"bash <<'EOF'\ncmd /c type nul > " + state + "\nEOF", true},
		{"cat <<'EOF' | sh\ncmd /c type nul > " + state + "\nEOF", true},
		{"cmd <<'EOF'\ntype nul > " + state + "\nEOF", true},
		{"cat > notes.md <<EOF\n$(cmd /c type nul > " + state + ")\nEOF", true},
		{"cat <<'EOF'\nnote\nEOF\ncmd /c type nul > " + state, true},
		{"cat <<'EOF' \"x\nEOF\" ; cmd /c type nul > " + state + "\nEOF", true},
		{"echo $((1<<2))\ncmd /c type nul > " + state + "\n2", true},
		{"${x <<}\ncmd /c type nul > " + state + "\n}", true},
		{"cat <<'EOF'\nnote\n", false},
		{"cat <<'EOF'\ncmd /c type nul > " + state, true},
		{steps("cmd /c echo stepN", 8, "; ", "cmd /c type nul > "+state), true},
		{"cmd /c echo a; cmd /c \"type nul > " + state + "\"", true},
		{"cmd --% /c type nul > " + state, true},
		{"cmd --% /c echo a ; type nul > " + state, true},
		// A double-quoted Git Bash $(...) is parsed on its own: a quote in
		// a here-document it opens does not end the string, and PowerShell
		// cannot parse a << in a $(...) of a string, so it runs none of it
		// (pod it17: the real Claude Code heredoc commit was blocked).
		{"git commit --allow-empty -q -m \"$(cat <<'MSG'\nfix: block cmd /c type nul > " + state + "\nThe \"cmd //c\" form is the Git Bash spelling.\nMSG\n)\" && git log --oneline -1", false},
		{"git commit -m \"$(cat <<'EOF'\nnote: \"cmd /c type nul > " + state + "\" empties it\nEOF\n)\"", false},
		{"echo \"$(printf '%s' \")\"; cmd //c echo a)\" && cat ~/.defenseclaw/config.yaml", false},
		{"git commit -m \"$(cmd //c 'type nul > " + state + "')\"", true},
		{"echo \"$(cat <<'EOF'\nx \"y\"\nEOF\n)\"; cmd //c \"type nul > " + state + "\"", true},
		{"echo \"$(cat <<EOF\n$(cmd //c 'type nul > " + state + "')\nEOF\n)\"", true},
		{"echo \"$(echo \")\"; cmd /c type nul > " + state + ")\"", true},
		{"Write-Output \"$(cmd /c 'type nul > " + state + "')\"", true},
		{"Write-Output \"$(# <<\n)\"; cmd /c \"type nul > " + state + "\"", true},
		{"Write-Output \"$(<# << #> 1)\"; cmd /c \"type nul > " + state + "\"", true},
		{"echo \"$(cat <<'EOF'\nunterminated \"q\"\n)\"; cmd //c \"type nul > " + state + "\"", true},
	} {
		for _, tool := range []string{"Bash", "shell_command", "PowerShell"} {
			args, _ := json.Marshal(map[string]string{"command": tc.command})
			input := actionfacts.Input{Tool: tool, Args: args, CWD: home + `\project`, ActiveHome: home}
			input.DialectHint = agentHookWindowsShellDialect(input)
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, LegacyText: string(args), Connector: connectorName,
				EnforcementCapable: true, ResolvedWriteTargets: resolved,
			})
			verdict := buildVerdict(findings, "tool_call")
			if got := verdict.Action == "block"; got != tc.block {
				t.Errorf("%s %q (dialect %q): action %q, want block=%t (findings %v)",
					tool, tc.command, input.DialectHint, verdict.Action, tc.block, findings)
			}
		}
	}
}

// TestR105WindowsCMDHeredocSearchArgument: a here-document fed to a text
// consumer whose argument names cmd or a shell (grep cmd <<EOF) is text the
// consumer reads; only a command-position word of the outer line receives
// the body (GAP-2530, regression of f625b4a83e).
func TestR105WindowsCMDHeredocSearchArgument(t *testing.T) {
	const connectorName = "r105-cmd-heredoc-search"
	installToolCallCorpusProfileConnector(t, connectorName, "default")
	const home = `C:\Users\Alice`
	resolved := map[string]string{}
	for _, value := range []string{"C:/Users/Alice/.defenseclaw", "C:/Users/Alice/.defenseclaw/config.yaml"} {
		resolved[value] = value
	}
	const state = `%USERPROFILE%\.defenseclaw\config.yaml`
	const body = "\nTip: cmd /c type nul > " + state + " empties the config\nEOF"
	const run = "\ncmd /c type nul > " + state + "\nEOF"
	const cmdBody = "\ntype nul > " + state + "\nEOF"
	const enableBody = "\nTo enable the guard again: cmd /c type nul > " + state + " empties the config\nEOF"
	for _, tc := range []struct {
		command string
		block   bool
	}{
		{"grep -n cmd <<'EOF'" + body, false},
		{"grep -c cmd.exe <<'EOF'" + body, false},
		{"rg -i bash <<'EOF'" + body, false},
		{"grep -E 'cmd|sh' <<'EOF'" + body, false},
		{"cat <<'EOF' | grep cmd" + body, false},
		{"cat <<'EOF' | grep -i \"cmd /c\" > hits.txt" + body, false},
		{"wc -l <<'EOF' 2>cmd" + body, false},
		// Still fed to cmd or a shell.
		{"cmd <<'EOF'\ntype nul > " + state + "\nEOF", true},
		{"FOO=1 cmd <<'EOF'\ntype nul > " + state + "\nEOF", true},
		{"env cmd <<'EOF'\ntype nul > " + state + "\nEOF", true},
		{"<<'EOF' cmd\ntype nul > " + state + "\nEOF", true},
		{"\"C:\\Windows\\System32\\cmd.exe\" <<'EOF'\ntype nul > " + state + "\nEOF", true},
		{"{ cmd; } <<'EOF'\ntype nul > " + state + "\nEOF", true},
		{"cat <<'EOF' | grep -v x | sh\ncmd /c type nul > " + state + "\nEOF", true},
		{"cat <<'EOF' | bash\ncmd /c type nul > " + state + "\nEOF", true},
		{"grep -v x <<'EOF' | cmd" + body, true},
		// Checker it1 rows: a launcher, a closed descriptor before a pipe,
		// time options, a function and a substitution in double quotes
		// still hand the body to a shell or cmd.
		{"cat <<'EOF' >&-|sh" + run, true},
		{"cat <<'EOF' 2>&-|bash" + run, true},
		{"find . -maxdepth 0 -exec bash \\; <<'EOF'" + run, true},
		{"function f { bash; }; f <<'EOF'" + run, true},
		{"time -p bash <<'EOF'" + run, true},
		{"flock /tmp/x bash <<'EOF'" + run, true},
		{"wsl bash <<'EOF'" + run, true},
		{"b''ash <<'EOF'" + run, true},
		{"cat <<'EOF' >&-|cmd" + cmdBody, true},
		{"time -p cmd <<'EOF'" + cmdBody, true},
		{"\"$(command -v bash)\" <<'EOF'" + run, true},
		{"cat <<'EOF' | \"$(command -v sh)\" -s" + run, true},
		{"grep() { bash; }; grep x <<'EOF'" + run, true},
		{"tee >(bash) <<'EOF'" + run, true},
		{"/tmp/x/grep cmd <<'EOF'" + run, true},
		// Text consumers keep their arguments as text.
		{"gh pr create --title cmd --body-file - <<'EOF'" + body, false},
		{"cat <<'EOF' | grep -c sh | wc -l" + body, false},
		{"time -p grep -c bash <<'EOF'" + body, false},
		{"! grep -q cmd <<'EOF'" + body, false},
		// Checker it2 rows: a consumer inside a substitution can print the
		// program name, so it is never trusted; a quoted word is split as
		// the whole-line read split it; prose in a body or a quoted word
		// redefines nothing.
		{"\"$(grep -m1 bash /etc/shells)\" <<'EOF'" + run, true},
		{"`grep -m1 bash /etc/shells` <<'EOF'" + run, true},
		{"$(cat /etc/shells | grep -m1 bash) <<'EOF'" + run, true},
		{"cat <<'EOF' | $(grep -m1 sh /etc/shells)" + run, true},
		{"cat <<'EOF' | \"$(rg -m1 bash /etc/shells)\"" + run, true},
		{"\"$(grep -m1 cmd x.txt)\" <<'EOF'" + cmdBody, true},
		{"eval 'bash -s' <<'EOF'" + run, true},
		{"eval 'grep() { bash; }'; grep x <<'EOF'" + run, true},
		{"cat <<'EOF' | eval \"sh -s\"" + run, true},
		{"grep -n cmd <<'EOF'" + enableBody, false},
		{"grep -n cmd <<'EOF'" + "\nIn main() the line cmd /c type nul > " + state + " empties the config\nEOF", false},
		{"grep -n cmd <<'EOF'" + "\nThe config hash changes when cmd /c type nul > " + state + " empties the config\nEOF", false},
		{"gh pr create --title cmd --body-file - <<'EOF'" + enableBody, false},
		{"cat <<'EOF' | grep -c bash" + enableBody, false},
		{"gh pr create --title \"$(git log -1 --format=%s)\" --body-file - <<'EOF'" + body, false},
		{"gh pr create --title \"enable main() hash\" --body-file - <<'EOF'" + body, false},
		// GAP-2536 rows: a redefinition hidden by a backslash or quotes, a
		// redefinition on an earlier line and a command word that is a
		// variable or $0 still hand the body to a shell; a keyword that is
		// only an argument or a comment and a variable that is only an
		// argument or a redirect target stay text.
		{"\\alias grep=bash\ngrep -s bash <<'EOF'" + run, true},
		{"al\"\"ias grep=bash\ngrep -s bash <<'EOF'" + run, true},
		{"\\eval \"grep() { \\\"\\$0\\\" -s; }\"; grep -s bash <<'EOF'" + run, true},
		{"\\hash -p \"$BASH\" grep; grep -s bash <<'EOF'" + run, true},
		{"\\. ./x.sh; grep -s bash <<'EOF'" + run, true},
		{"\"$BASH\" -s <<'EOF'" + run, true},
		{"$0 -s <<'EOF'" + run, true},
		{"${SHELL:-sh} <<'EOF'" + run, true},
		{"cat <<'EOF' | \"$COMSPEC\"" + cmdBody, true},
		{"\\alias grep=bash\ngrep -s x <<'EOF'" + run, true},
		{"alias grep=bash; grep x <<'EOF'" + run, true},
		{"alias grep=bash\ngrep x <<'EOF'" + run, true},
		{"builtin alias grep=cmd\ngrep x <<'EOF'" + cmdBody, true},
		{"\"grep\"() { bash; }; grep x <<'EOF'" + run, true},
		{"grep -n alias <<'EOF'" + body, false},
		{"grep -rn source <<'EOF'" + enableBody, false},
		{"grep -n \"eval it\" <<'EOF'" + body, false},
		{"grep -n cmd <<'EOF' # alias grep=bash; eval x" + body, false},
		{"grep -n \"$PAT\" <<'EOF'" + body, false},
		{"cat <<'EOF' > \"$OUT\"" + body, false},
		{"arr=(); grep -c cmd <<'EOF'" + body, false},
		// GAP-2536 checker it4 rows: a shell named by an expansion behind a
		// launcher, a redefinition through an expansion command word on an
		// earlier line and a PATH assignment still hand the body to a
		// shell; an expansion that is only an argument of a consumer or of
		// a command that runs no argument, and a substitution that holds
		// the here-document, stay text.
		{"env \"$BASH\" -s <<'EOF'" + run, true},
		{"command \"$BASH\" -s <<'EOF'" + run, true},
		{"exec \"$BASH\" -s <<'EOF'" + run, true},
		{"nice $0 -s <<'EOF'" + run, true},
		{"timeout 5 \"$BASH\" -s <<'EOF'" + run, true},
		{"cat <<'EOF' | env \"$BASH\"" + run, true},
		{"cat <<'EOF' | xargs -0 \"$BASH\" -c" + run, true},
		{"env \"$(cat shell.txt)\" -s <<'EOF'" + run, true},
		{"E=eval; $E 'grep() { bash; }'\ngrep x <<'EOF'" + run, true},
		{"$'alias' grep=bash\ngrep x <<'EOF'" + run, true},
		{"ln -s \"$BASH\" grep; PATH=.:$PATH; grep x <<'EOF'" + run, true},
		{"export PATH=.:$PATH\ngrep x <<'EOF'" + run, true},
		{"cd \"$REPO\" && git commit -F - <<'EOF'" + body, false},
		{"mkdir -p \"$D\" && cat > \"$D/notes.md\" <<'EOF'" + body, false},
		{"git commit -m \"$(cat <<'EOF'" + body + "\n)\"", false},
		{"grep -n \"$X\" notes.md && cat > out.md <<'EOF'" + body, false},
		{"[ -n \"$X\" ] && grep -n cmd <<'EOF'" + body, false},
		{"echo \"$HOME\"; grep -c cmd <<'EOF'" + body, false},
		{"\"$PYTHON\" - <<'EOF'\nprint('hi')\nEOF", false},
		// GAP-2538 rows: a backslash-newline joins the lines before the
		// receiver read, so a continued line still hands the body to a
		// shell or cmd; a continued text consumer or git commit stays text.
		{"bash \\\n<<'EOF'" + run, true},
		{"env \"$BASH\" \\\n-s <<'EOF'" + run, true},
		{"\"$BASH\" \\\n-s <<'EOF'" + run, true},
		{"cat <<'EOF' \\\n| bash" + run, true},
		{"grep -v x <<'EOF' \\\n| bash" + run, true},
		{"env \\\nbash -s <<'EOF'" + run, true},
		{"cat <<'EOF' \\\n| cmd" + cmdBody, true},
		{"git commit \\\n-F - <<'EOF'" + body, false},
		{"grep -n \\\ncmd <<'EOF'" + body, false},
		{"cat <<'EOF' \\\n| grep -c cmd" + body, false},
		// GAP-2539 rows: a substitution that holds a here-document and is an
		// argument of a launcher or an unknown program hands the body over as
		// its argv; git commit/tag/notes, gh pr/issue, a text consumer, a
		// command that runs no argument and an assignment keep it text.
		{"env $(cat <<'EOF'" + run + "\n)", true},
		{"exec $(cat <<'EOF'" + run + "\n)", true},
		{"$(cat <<'EOF'" + run + "\n)", true},
		{"timeout 9 `cat <<'EOF'" + run + "\n`", true},
		{"xargs $(cat <<'EOF'" + run + "\n) </dev/null", true},
		{"nice \"$(cat <<'EOF'\nbash\nEOF\n)\" -s <<'X'\ncmd /c type nul > " + state + "\nX", true},
		{"env \"$(cat <<'EOF'" + run + "\n)\"", true},
		{"echo \"$(cat <<'EOF'" + run + "\n)\" | bash", true},
		{"gh pr create --title t --body \"$(cat <<'EOF'" + body + "\n)\"", false},
		{"git tag -a v1 -m \"$(cat <<'EOF'" + body + "\n)\"", false},
		{"MSG=$(cat <<'EOF'" + body + "\n)", false},
		{"echo \"$(cat <<'EOF'" + body + "\n)\" > notes.md", false},
		{"grep -c cmd notes.md \"$(cat <<'EOF'" + body + "\n)\"", false},
		// GAP-2547 rows: the command goes on after the body (a pipe or list
		// the << line left open, or a ( ), $( ), { } or loop closed and piped
		// on by a later line), so those lines are receivers too; a later
		// separate statement, a text consumer after the pipe and a closer
		// that pipes to a file keep the body text.
		{"cat <<'EOF' |" + run + "\nbash", true},
		{"( cat <<'EOF'" + run + "\n) | bash", true},
		{"{ cat <<'EOF'" + run + "\n} | bash", true},
		{"cat <<'EOF' |" + cmdBody + "\ncmd", true},
		{"echo $(cat <<'EOF'" + run + "\n) | bash", true},
		{"cat <<'EOF' |" + run + "\ngrep -v x |\nbash", true},
		{"while true; do\n  cat <<'EOF'" + run + "\ndone | bash", true},
		{"if true; then\n  { cat <<'EOF'" + run + "\n  } | sh; fi", true},
		{"cat <<'EOF' |" + body + "\ngrep -c cmd", false},
		{"{ cat <<'EOF'" + body + "\n} | grep -c cmd", false},
		{"( cat <<'EOF'" + body + "\n) > notes.md", false},
		{"if true; then\n  cat > notes.md <<'EOF'" + body + "\n  bash build.sh\nfi", false},
		{"cat > notes.md <<'EOF'" + body + "\nbash build.sh", false},
		// GAP-2547 checker it7: bash reads a pipe or list on across blank
		// and comment-only lines (X03, X04), and a comment may follow the
		// operator; a blank line before a separate statement keeps it text.
		{"cat <<'EOF' |" + run + "\n\nbash", true},
		{"cat <<'EOF' |" + run + "\n# then\nbash", true},
		{"cat <<'EOF' |" + run + "\n  \r\n\t# then\r\n\nbash", true},
		{"cat <<'EOF' | # pipe it on" + run + "\nbash", true},
		{"cat <<'EOF' |" + run + "\ngrep -v x | # keep going\n\nbash", true},
		{"cat > notes.md <<'EOF'" + body + "\n\nbash build.sh", false},
		{"cat > notes.md <<'EOF'" + body + "\n# build\nbash build.sh", false},
		{"cat <<'EOF' | # count" + body + "\n\n# the matches\ngrep -c cmd", false},
		{"echo \"a | #b\" > notes.md\nbash build.sh", false},
	} {
		for _, tool := range []string{"Bash", "shell_command", "PowerShell"} {
			args, _ := json.Marshal(map[string]string{"command": tc.command})
			input := actionfacts.Input{Tool: tool, Args: args, CWD: home + `\project`, ActiveHome: home}
			input.DialectHint = agentHookWindowsShellDialect(input)
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, LegacyText: string(args), Connector: connectorName,
				EnforcementCapable: true, ResolvedWriteTargets: resolved,
			})
			verdict := buildVerdict(findings, "tool_call")
			if got := verdict.Action == "block"; got != tc.block {
				t.Errorf("%s %q (dialect %q): action %q, want block=%t (findings %v)",
					tool, tc.command, input.DialectHint, verdict.Action, tc.block, findings)
			}
		}
	}
}
