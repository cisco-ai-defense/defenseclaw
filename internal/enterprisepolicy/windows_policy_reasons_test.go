// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// A missing Windows machine hook is drift even when no user is enrolled.
// Keep that contract in the diagnostics emitted by policy and the guardian.
func TestWindowsPolicyReasonsDoNotConditionPublicationOnEnrollment(t *testing.T) {
	for _, dir := range []string{".", "../enterprisehooks"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if !strings.Contains(name, "windows") || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			path := filepath.Join(dir, name)
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			ast.Inspect(file, func(node ast.Node) bool {
				spec, ok := node.(*ast.ValueSpec)
				if !ok {
					return true
				}
				for _, ident := range spec.Names {
					if !strings.HasSuffix(ident.Name, "Reason") && !strings.HasSuffix(ident.Name, "Consequence") {
						continue
					}
					for _, value := range spec.Values {
						literal, ok := value.(*ast.BasicLit)
						if !ok || literal.Kind != token.STRING {
							continue
						}
						message, err := strconv.Unquote(literal.Value)
						if err != nil {
							t.Errorf("%s: %v", path, err)
							continue
						}
						lower := strings.ToLower(message)
						if strings.Contains(lower, "only while") || strings.Contains(lower, "at least one user is enrolled") {
							t.Errorf("%s: %s conditions machine-hook publication on enrollment", path, ident.Name)
						}
					}
				}
				return false
			})
		}
	}
}

// cowork-1-0-8 GAP-0076: the details an administrator of a managed Windows
// computer reads name the installed CLI as typed in an elevated PowerShell
// prompt; Setup puts no DefenseClaw command on PATH. Linux and macOS name the
// gateway by its absolute path.
func TestWindowsPolicyDetailsNameTheInstalledCLI(t *testing.T) {
	cli := "`" + managed.WindowsAdminCommand() + " "
	if runtime.GOOS != "windows" && cli != "`& 'C:\\Program Files\\Cisco\\DefenseClaw\\bin\\defenseclaw.exe' " {
		t.Fatalf("installed CLI = %s", cli)
	}
	if got, want := policyExportCommand("windows", "--connector", "claudecode", "--format", "claude-hklm-json"),
		cli+"enterprise policy export --connector claudecode --format claude-hklm-json` (from an elevated PowerShell prompt)"; got != want {
		t.Errorf("windows export = %s, want %s", got, want)
	}
	// On Linux and macOS the gateway is not on the PATH either: the command
	// names it by its absolute path (cowork-1-0-8 GAP-0081).
	for goos, gateway := range map[string]string{
		"linux":  "/opt/defenseclaw/bin/defenseclaw-gateway",
		"darwin": "/opt/cisco/defenseclaw/bin/defenseclaw-gateway",
	} {
		if got, want := policyExportCommand(goos, "--connector", "codex"), "`"+gateway+" enterprise policy export --connector codex`"; got != want {
			t.Errorf("%s export = %s, want %s", goos, got, want)
		}
	}
	missing := windowsMissingMachineHookDiagnostic("Codex")
	for _, want := range []string{"From an elevated PowerShell prompt, run " + cli + "enterprise windows reconcile --profile standalone` or " +
		cli + "enterprise windows repair --profile standalone`"} {
		if !strings.Contains(missing, want) {
			t.Errorf("missing machine hook diagnostic lacks %q: %s", want, missing)
		}
	}
	state := &State{Connector: "codex"}
	flapConflict("windows", state, "codex", `C:\ProgramData\OpenAI\Codex\requirements.toml`, flapThreshold)
	if len(state.Conflicts) != 1 || !strings.Contains(state.Conflicts[0], cli+"enterprise policy export --connector codex` (from an elevated PowerShell prompt)") ||
		strings.Contains(state.Conflicts[0], "`defenseclaw-gateway ") {
		t.Errorf("windows flap conflict = %q", state.Conflicts)
	}
	// A ProgramFiles a standard user set does not move the command
	// (g072 review 2 S2).
	want := policyExportCommand("windows", "--connector", "wsl")
	t.Setenv("ProgramFiles", `D:\Apps`)
	if got := policyExportCommand("windows", "--connector", "wsl"); got != want || !strings.HasPrefix(got, "`"+managed.WindowsAdminCommand()) ||
		strings.Contains(got, `D:\Apps`) {
		t.Errorf("export with a poisoned ProgramFiles = %s, want %s", got, want)
	}
}
