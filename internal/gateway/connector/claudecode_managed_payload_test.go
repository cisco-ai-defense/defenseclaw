// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookguard"
)

func managedPayloadRepoFile(t *testing.T, relative string) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source")
	}
	return filepath.Join(filepath.Dir(source), "..", "..", "..", filepath.FromSlash(relative))
}

// goStringListVar reads the string literals of a package-level []string var
// from a Go source file, so the test reads the shipped list itself.
func goStringListVar(t *testing.T, relative, name string) []string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), managedPayloadRepoFile(t, relative), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gen.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok || len(value.Names) != 1 || value.Names[0].Name != name || len(value.Values) != 1 {
				continue
			}
			literal, ok := value.Values[0].(*ast.CompositeLit)
			if !ok {
				t.Fatalf("%s in %s is not a list literal", name, relative)
			}
			var names []string
			for _, element := range literal.Elts {
				text, err := strconv.Unquote(element.(*ast.BasicLit).Value)
				if err != nil {
					t.Fatal(err)
				}
				names = append(names, text)
			}
			return names
		}
	}
	t.Fatalf("%s not found in %s", name, relative)
	return nil
}

func managedWrapperExecutableNames(t *testing.T) []string {
	t.Helper()
	launcher := `C:\Program Files\DefenseClaw\bin\defenseclaw-hook.exe`
	hookArgs := []string{"hook", "--connector", "claudecode", "--enterprise-managed"}
	names := map[string]bool{}
	for _, group := range claudeCodeAllHookGroups {
		command, args := claudeManagedGuardWrapperInvocation(group.eventType, launcher, hookArgs)
		if command == launcher {
			t.Fatalf("%s: managed command was not wrapped", group.eventType)
		}
		for _, word := range append([]string{command}, args...) {
			if lower := strings.ToLower(word); strings.HasSuffix(lower, ".exe") && strings.ContainsAny(word, `\/`) {
				name := word[strings.LastIndexAny(word, `\/`)+1:]
				if !strings.EqualFold(name, "cmd.exe") {
					names[strings.ToLower(name)] = true
				}
			}
		}
	}
	var sorted []string
	for name := range names {
		sorted = append(sorted, name)
	}
	slices.Sort(sorted)
	return sorted
}

// Every program the managed Claude Code command starts must be in the
// standalone payload and in the installation module's layout: a wrapper that
// names a program the signed Setup does not install fails closed on every
// event of every managed computer, and installing the same payload again
// cannot repair it.
func TestManagedClaudeCodeWrapperProgramsShipInStandalonePayload(t *testing.T) {
	names := managedWrapperExecutableNames(t)
	for _, want := range []string{"defenseclaw-hook.exe", windowsHookGuardBinaryName} {
		if !slices.Contains(names, want) {
			t.Fatalf("managed wrapper references %v, want it to include %s", names, want)
		}
	}
	setupList := goStringListVar(t, "cmd/defenseclaw-enterprise-setup/main.go", "standalonePayloadFiles")
	assemblerList := goStringListVar(t, "cmd/windows-avc-assembler/main.go", "requiredStandalonePayloadFiles")
	script, err := os.ReadFile(managedPayloadRepoFile(t, "packaging/windows/standalone/build-setup.sh"))
	if err != nil {
		t.Fatal(err)
	}
	block := regexp.MustCompile(`(?s)PAYLOAD_FILES=\((.*?)\n\)`).FindSubmatch(script)
	if block == nil {
		t.Fatal("build-setup.sh has no PAYLOAD_FILES list")
	}
	scriptList := strings.Fields(string(block[1]))
	module, err := os.ReadFile(managedPayloadRepoFile(t, "packaging/windows/DefenseClawEnterprise.psm1"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		inventories := map[string][]string{
			"Setup payload list":     setupList,
			"assembler payload list": assemblerList,
			"build-setup.sh payload": scriptList,
		}
		for label, list := range inventories {
			if !slices.Contains(list, name) {
				t.Errorf("%s is started by the managed Claude Code command but is not in the %s", name, label)
			}
		}
		layout := regexp.MustCompile(`Join-Path \$bin '` + regexp.QuoteMeta(name) + `'`)
		if !layout.Match(module) {
			t.Errorf("%s is started by the managed Claude Code command but is not in the installation module layout", name)
		}
	}
	if !slices.Equal(setupList, assemblerList) || !slices.Equal(setupList, scriptList) {
		t.Errorf("standalone payload lists differ: setup %v, assembler %v, script %v", setupList, assemblerList, scriptList)
	}
}

// A guard that is missing at run time gives the normal DefenseClaw reason:
// it names the guard and the repair command, then answers each event with its
// documented code (blocking events 2, neutral events 1).
func TestManagedClaudeCodeWrapperNamesMissingGuardAndRepair(t *testing.T) {
	launcher := `C:\Program Files\DefenseClaw\bin\defenseclaw-hook.exe`
	hookArgs := []string{"hook", "--connector", "claudecode", "--enterprise-managed"}
	for _, group := range claudeCodeAllHookGroups {
		_, args := claudeManagedGuardWrapperInvocation(group.eventType, launcher, hookArgs)
		open := slices.Index(args, "(")
		closeIndex := slices.Index(args, ")")
		if open < 0 || closeIndex < open {
			t.Fatalf("%s: wrapper has no missing-guard block: %q", group.eventType, args)
		}
		block := strings.Join(args[open+1:closeIndex], " ")
		for _, want := range []string{windowsHookGuardBinaryName, "enterprise windows repair --profile standalone", "1>&2"} {
			if !strings.Contains(block, want) {
				t.Errorf("%s: missing-guard block %q lacks %q", group.eventType, block, want)
			}
		}
		code := "2"
		if hookguard.NeutralEvent(group.eventType) {
			code = "1"
		}
		if !strings.HasSuffix(block, "exit /b "+code) {
			t.Errorf("%s: missing-guard block %q does not exit %s", group.eventType, block, code)
		}
		if text := block[:strings.Index(block, " 1>&2")]; strings.ContainsAny(text, "()%^|<>&!\"") {
			t.Errorf("%s: missing-guard text holds a cmd.exe metacharacter: %q", group.eventType, text)
		}
	}
}
