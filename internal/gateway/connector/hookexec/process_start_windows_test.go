// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookexec

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

func testPowerShellBridgeArgs(script string) []string {
	encoded := utf16.Encode([]rune(script))
	data := make([]byte, len(encoded)*2)
	for i, value := range encoded {
		binary.LittleEndian.PutUint16(data[i*2:], value)
	}
	return []string{`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		"-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(data)}
}

// GAP-0167: the budgets of a hook launched through the system PowerShell
// bridge (Codex) or the per-user stable launcher count from the wrapper's
// start; anything else keeps the hook's own start.
func TestCallStartCountsTheWrappersThatLaunchedTheHook(t *testing.T) {
	const powerShell = `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
	created := time.Unix(1_000, 0)
	at := func(lead time.Duration) time.Time { return created.Add(-lead) }
	bridge := testPowerShellBridgeArgs("$ErrorActionPreference='Stop'; $env:NoDefaultCurrentDirectoryInExePath='1'; $hookStart=[System.Diagnostics.ProcessStartInfo]::new('C:\\Program Files\\DefenseClaw\\defenseclaw-hook.exe','hook --connector codex'); $hookProcess=[System.Diagnostics.Process]::Start($hookStart); $hookProcess.WaitForExit(); exit $hookProcess.ExitCode")
	for _, test := range []struct {
		name  string
		chain []hookWrapperProcess
		want  time.Time
	}{
		{"no parent", nil, created},
		{"the agent itself", []hookWrapperProcess{{`C:\Users\u\AppData\Local\claude\claude.exe`, at(time.Hour), nil}}, created},
		{"system PowerShell bridge", []hookWrapperProcess{{powerShell, at(1900 * time.Millisecond), bridge}}, at(1900 * time.Millisecond)},
		{"PowerShell, case differs", []hookWrapperProcess{{`c:\windows\system32\windowspowershell\v1.0\POWERSHELL.EXE`, at(time.Second), bridge}}, at(time.Second)},
		{"PowerShell script driving hook calls", []hookWrapperProcess{{powerShell, at(4 * time.Second), []string{powerShell, "-NoProfile", "-File", `C:\\driver.ps1`}}}, created},
		{"encoded PowerShell script driving hook calls", []hookWrapperProcess{{powerShell, at(4 * time.Second), testPowerShellBridgeArgs("for ($i=0; $i -lt 20; $i++) { & 'defenseclaw-hook.exe' hook --connector claudecode }")}}, created},
		{"unreadable PowerShell command", []hookWrapperProcess{{powerShell, at(4 * time.Second), nil}}, created},
		{"PowerShell encoded unrelated command", []hookWrapperProcess{{powerShell, at(4 * time.Second), testPowerShellBridgeArgs("Write-Output ready")}}, created},
		{"another PowerShell", []hookWrapperProcess{{`C:\Program Files\PowerShell\7\pwsh.exe`, at(time.Second), nil}}, created},
		{"PowerShell started long before (a shell)", []hookWrapperProcess{{powerShell, at(time.Minute), bridge}}, created},
		{"reused process id", []hookWrapperProcess{{powerShell, created.Add(time.Second), bridge}}, created},
		{"bridge then stable launcher", []hookWrapperProcess{
			{`C:\Users\u\.local\bin\defenseclaw-hook.exe`, at(800 * time.Millisecond), nil},
			{powerShell, at(1500 * time.Millisecond), bridge},
		}, at(1500 * time.Millisecond)},
		// GAP-1908: the direct Codex registration starts the launcher through
		// the system cmd.exe, as the per-user Claude Code command does; like
		// the agent's own shell it is not a wrapper the budgets count.
		{"system cmd.exe of a direct registration", []hookWrapperProcess{{`C:\Windows\System32\cmd.exe`, at(300 * time.Millisecond), nil}}, created},
		{"launcher under the agent", []hookWrapperProcess{
			{`C:\Users\u\.local\bin\defenseclaw-hook.exe`, at(800 * time.Millisecond), nil},
			{`C:\Users\u\AppData\Local\claude\claude.exe`, at(time.Hour), nil},
		}, at(800 * time.Millisecond)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := callStartBehindWrappers(created, test.chain, powerShell); !got.Equal(test.want) {
				t.Fatalf("call start %s, want %s", got, test.want)
			}
		})
	}
}

// GAP-0517: a fresh PowerShell script launches managed hook processes in a
// loop. Its own start is not each hook call's start. Before this regression
// fix the first calls passed, then the watchdog emitted no-answer immediately
// until the script became older than maxHookWrapperLead.
func TestManagedHookCallsFromFreshPowerShellScriptKeepTheirOwnBudget(t *testing.T) {
	if os.Getenv("DC_CF517_HOOK_CHILD") == "1" {
		started := ProcessStartTime()
		watchdog := ArmAnswerWatchdog(Options{
			Connector: "claudecode", ManagedEnterprise: true, StartedAt: started,
			Stdout: os.Stdout, Stderr: os.Stderr, Exit: os.Exit,
		}, []byte(preToolUsePayload))
		if watchdog == nil {
			os.Exit(98)
		}
		result := run(t, "claudecode", ok(`{"action":"allow"}`), func(opts *Options) {
			managedCodex(opts)
			opts.StartedAt = started
			opts.AnswerWatchdog = watchdog
			opts.Stdin = strings.NewReader(preToolUsePayload)
		})
		if result.code != 0 {
			fmt.Fprint(os.Stderr, result.stderr)
		}
		os.Exit(result.code)
	}
	script := filepath.Join(t.TempDir(), "drive.ps1")
	content := `param([string]$Binary)
$env:DC_CF517_HOOK_CHILD='1'
Start-Sleep -Milliseconds 2700
for ($i=0; $i -lt 10; $i++) {
  $output = & $Binary '-test.run=^TestManagedHookCallsFromFreshPowerShellScriptKeepTheirOwnBudget$' 2>&1
  "call=$i rc=$LASTEXITCODE out=$output"
}
`
	if err := os.WriteFile(script, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script, os.Args[0])
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("PowerShell hook driver: %v\n%s", err, output)
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) != 10 {
		t.Fatalf("PowerShell hook driver returned %d calls, want 10:\n%s", len(lines), output)
	}
	for i, line := range lines {
		if !strings.Contains(line, "rc=0") || strings.Contains(line, managedGatewayNoAnswerReason) {
			t.Fatalf("managed hook call %d from fresh PowerShell script: %s", i, line)
		}
	}
	fmt.Fprintln(os.Stdout, "10 managed hook calls from one fresh PowerShell process answered within their own budgets")
}

// The registered -EncodedCommand bridge is a separate process for each call.
// Its startup still counts against that call's cap after the script-driver fix.
// The bridge waits with a .NET sleep, not Start-Sleep, so it loads no module:
// Start-Sleep auto-loads Microsoft.PowerShell.Utility, and on a fresh Windows
// CI image that first load ran PowerShell's "Preparing modules for first use"
// step. The bridge then took 13 s instead of about 4 s, past
// maxHookWrapperLead, so the hook rightly stopped counting it and the test
// failed for a reason it does not pin.
func TestWindowsOneCallPowerShellBridgeStillCountsItsStartup(t *testing.T) {
	if os.Getenv("DC_CF517_BRIDGE_CHILD") == "1" {
		own, err := processCreationTime(windows.CurrentProcess())
		if err != nil {
			t.Fatal(err)
		}
		if lead := own.Sub(ProcessStartTime()); lead < 900*time.Millisecond {
			detail := "no launching process could be read"
			if chain := hookWrapperChain(); len(chain) > 0 {
				detail = fmt.Sprintf("%s started %s before this process (cap %s)",
					chain[0].image, own.Sub(chain[0].created), maxHookWrapperLead)
			}
			t.Fatalf("PowerShell bridge startup %s was not counted: %s", lead, detail)
		}
		return
	}
	script := "$ErrorActionPreference='Stop'; $env:NoDefaultCurrentDirectoryInExePath='1'; " +
		"[System.Threading.Thread]::Sleep(1200); " +
		"$hookStart=[System.Diagnostics.ProcessStartInfo]::new('" + strings.ReplaceAll(os.Args[0], "'", "''") +
		"','-test.run=^TestWindowsOneCallPowerShellBridgeStillCountsItsStartup$'); " +
		"$hookStart.UseShellExecute=$false; " +
		"$hookProcess=[System.Diagnostics.Process]::Start($hookStart); " +
		"$hookProcess.WaitForExit(); exit $hookProcess.ExitCode"
	argv := testPowerShellBridgeArgs(script)
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), "DC_CF517_BRIDGE_CHILD=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("one-call PowerShell bridge: %v\n%s", err, output)
	}
}

// The live reader never names a start after this process's own creation.
func TestProcessStartTimeIsNoLaterThanThisProcess(t *testing.T) {
	started, ok := processStartTime(time.Now())
	if !ok {
		t.Fatal("no process start on Windows")
	}
	own, err := processCreationTime(windows.CurrentProcess())
	if err != nil {
		t.Fatal(err)
	}
	if started.After(own) {
		t.Fatalf("call start %s is after this process's creation %s", started, own)
	}
}
