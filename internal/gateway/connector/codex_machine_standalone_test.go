// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func decodeTestEncodedCommand(t *testing.T, command string) string {
	t.Helper()
	const flag = " -EncodedCommand "
	index := strings.LastIndex(command, flag)
	if index < 0 {
		t.Fatalf("command has no -EncodedCommand: %s", command)
	}
	raw, err := base64.StdEncoding.DecodeString(command[index+len(flag):])
	if err != nil || len(raw)%2 != 0 {
		t.Fatalf("decode encoded command: %v", err)
	}
	wide := make([]uint16, len(raw)/2)
	for i := range wide {
		wide[i] = binary.LittleEndian.Uint16(raw[i*2:])
	}
	return string(utf16.Decode(wide))
}

func standaloneWindowsCodexMachineOptions() WindowsCodexMachineRequirementsOptions {
	opts := testWindowsCodexMachineOptions()
	opts.HookContractID = ResolveHookContract("codex", "").Contract.ContractID
	return opts
}

// The hook refuses a Codex invocation without its installer-bound event and
// contract, and the PowerShell call operator does not wait for the
// GUI-subsystem launcher. The standalone profile's machine requirements
// therefore bind each group's event and contract and wait for the launcher.
func TestWindowsCodexStandaloneRequirementsBindEventAndContract(t *testing.T) {
	opts := standaloneWindowsCodexMachineOptions()
	if opts.HookContractID == "" {
		t.Fatal("no default Codex hook contract")
	}
	rendered, _, err := reconcileWindowsCodexRequirements(nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyWindowsCodexRequirementsBytes(rendered, opts); err != nil {
		t.Fatal(err)
	}
	cfg, err := parseWindowsCodexRequirements(rendered)
	if err != nil {
		t.Fatal(err)
	}
	hooks := cfg["hooks"].(map[string]interface{})
	for _, group := range codexHookGroups {
		groups := hooks[group.eventType].([]interface{})
		if len(groups) != 1 {
			t.Fatalf("hooks.%s has %d groups", group.eventType, len(groups))
		}
		handler := groups[0].(map[string]interface{})["hooks"].([]interface{})[0].(map[string]interface{})
		command, _ := handler["command"].(string)
		if command != handler["command_windows"] {
			t.Fatalf("hooks.%s command and command_windows differ", group.eventType)
		}
		script := decodeTestEncodedCommand(t, command)
		for _, want := range []string{
			"Start-Process -FilePath '" + opts.HookBinary + "'",
			"'--enterprise-managed','--event','" + group.eventType + "','--hook-contract','" + opts.HookContractID + "'",
			"-NoNewWindow -Wait -PassThru",
			"exit $hookProcess.ExitCode",
		} {
			if !strings.Contains(script, want) {
				t.Fatalf("hooks.%s script missing %q:\n%s", group.eventType, want, script)
			}
		}
	}

	// The Secure Client options keep the certified unbound command.
	secureClient := testWindowsCodexMachineOptions()
	scRendered, _, err := reconcileWindowsCodexRequirements(nil, secureClient)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(scRendered), windowsCodexBoundManagedHookCommand(secureClient.HookBinary, "PreToolUse", opts.HookContractID)) ||
		!strings.Contains(string(scRendered), windowsCodexManagedHookCommand(secureClient.HookBinary)) {
		t.Fatal("Secure Client requirements must keep the unbound command")
	}
	if err := verifyWindowsCodexRequirementsBytes(rendered, secureClient); err == nil {
		t.Fatal("Secure Client verification must not accept the standalone command")
	}
}

// Only the standalone install's own launcher selects the bound command.
func TestWindowsCodexStandaloneHookContractFollowsTheStandaloneLauncher(t *testing.T) {
	layout, err := managed.StandaloneWindowsLayoutForRoots(`C:\Program Files`, `C:\ProgramData`)
	if err != nil {
		t.Fatal(err)
	}
	want := ResolveHookContract("codex", "").Contract.ContractID
	if got := windowsCodexStandaloneHookContractFor(layout, `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`); got != want {
		t.Fatalf("standalone launcher contract = %q, want %q", got, want)
	}
	if got := windowsCodexStandaloneHookContractFor(layout, `c:\program files\cisco\defenseclaw\bin\DEFENSECLAW-HOOK.EXE`); got != want {
		t.Fatalf("path comparison must be case-insensitive, got %q", got)
	}
	for _, other := range []string{
		`C:\Program Files\Cisco\Cisco Secure Client\DefenseClaw\bin\defenseclaw-hook.exe`,
		`C:\Users\alice\.defenseclaw\bin\defenseclaw-hook.exe`,
		"",
	} {
		if got := windowsCodexStandaloneHookContractFor(layout, other); got != "" {
			t.Fatalf("%q selected contract %q", other, got)
		}
	}
}

type countingAllowTransport struct{ requests int }

func (c *countingAllowTransport) RoundTrip(*http.Request) (*http.Response, error) {
	c.requests++
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"action":"allow"}`)),
	}, nil
}

// The contract bound into the standalone command must register every
// published event, or the hook refuses the call before it reaches the
// gateway; the unbound command is refused for every event.
func TestWindowsCodexStandaloneBindingIsAcceptedByTheHook(t *testing.T) {
	contract := standaloneWindowsCodexMachineOptions().HookContractID
	for _, group := range codexHookGroups {
		for _, bound := range []bool{true, false} {
			home := t.TempDir()
			hookDir := filepath.Join(home, "hooks")
			if err := os.MkdirAll(hookDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(hookDir, ".token"), []byte("DEFENSECLAW_GATEWAY_TOKEN=\"tkn\"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			transport := &countingAllowTransport{}
			var stdout, stderr bytes.Buffer
			opts := hookexec.Options{
				Connector:  "codex",
				APIAddr:    "127.0.0.1:8787",
				FailMode:   "closed",
				Home:       home,
				HookDir:    hookDir,
				Stdin:      strings.NewReader(fmt.Sprintf(`{"hook_event_name":%q}`, group.eventType)),
				Stdout:     &stdout,
				Stderr:     &stderr,
				HTTPClient: &http.Client{Transport: transport},
			}
			if bound {
				opts.Event, opts.HookContractID = group.eventType, contract
			}
			code := hookexec.Run(context.Background(), opts)
			switch {
			case bound && (code != 0 || transport.requests == 0):
				t.Fatalf("%s bound to %s: code=%d requests=%d stderr=%s", group.eventType, contract, code, transport.requests, stderr.String())
			case !bound && (code == 0 || transport.requests != 0 || !strings.Contains(stderr.String(), "installer-bound event")):
				t.Fatalf("%s unbound: code=%d requests=%d stderr=%s", group.eventType, code, transport.requests, stderr.String())
			}
		}
	}
}
