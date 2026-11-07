// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// windowsManagedLayoutSeamFile declares windowsManagedLayout, the one place
// internal/cli resolves the computer's own standalone layout and trusted
// enterprise roots (cowork-1-0-8 GAP-0093, round 2).
const windowsManagedLayoutSeamFile = "windows_managed_layout_windows.go"

// windowsSelfHealFile is the guardian's self-heal. It repairs the install,
// policy and service objects under the computer's Program Files and
// ProgramData, so it asks windowsManagedLayout.programRoots for them and
// never resolves the registrations itself (GAP-0093, review 2 S2). Other
// files read the same registrations to classify a path and stay as they are.
const windowsSelfHealFile = "enterprise_hooks_self_heal_windows.go"

// testDeploymentResolverProblems lists where one parsed non-test file of
// internal/cli goes around windowsManagedLayout: a direct use of
// managed.StandaloneWindowsLayout or winpath.TrustedEnterpriseRoots (called
// or taken as a value), or a write to windowsManagedLayout. Only the seam
// file declares the variable and names the two resolvers. The Secure Client
// profile's own lookups are left as they are: a call of
// winpath.TrustedEnterpriseRoots(winpath.EnterpriseProfileSecureClient), and
// the Secure Client host classification (secureClientHost), which is its own
// seam.
func testDeploymentResolverProblems(fset *token.FileSet, name string, file *ast.File) []string {
	imported := func(path string) map[string]bool {
		names := map[string]bool{}
		for _, spec := range file.Imports {
			if unquoted, err := strconv.Unquote(spec.Path.Value); err != nil || unquoted != path {
				continue
			}
			if spec.Name != nil {
				names[spec.Name.Name] = true
			} else {
				names[filepath.Base(path)] = true
			}
		}
		return names
	}
	managedNames := imported("github.com/defenseclaw/defenseclaw/internal/managed")
	winpathNames := imported("github.com/defenseclaw/defenseclaw/internal/winpath")
	selects := func(expr ast.Expr, packages map[string]bool, member string) bool {
		selector, ok := ast.Unparen(expr).(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != member {
			return false
		}
		ident, ok := selector.X.(*ast.Ident)
		return ok && packages[ident.Name]
	}
	isSeam := func(expr ast.Expr) bool {
		expr = ast.Unparen(expr)
		if selector, ok := expr.(*ast.SelectorExpr); ok {
			expr = selector.X
		}
		ident, ok := ast.Unparen(expr).(*ast.Ident)
		return ok && ident.Name == "windowsManagedLayout"
	}
	seamFile := name == windowsManagedLayoutSeamFile
	var problems []string
	report := func(node ast.Node, what string) {
		problems = append(problems, fset.Position(node.Pos()).String()+": "+what)
	}
	var stack []ast.Node
	enclosingDecl := func() string {
		for _, node := range stack {
			switch decl := node.(type) {
			case *ast.FuncDecl:
				return decl.Name.Name
			case *ast.ValueSpec:
				if len(decl.Names) > 0 {
					return decl.Names[0].Name
				}
			}
		}
		return ""
	}
	ast.Inspect(file, func(node ast.Node) bool {
		if node == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		var parent ast.Node
		if len(stack) > 0 {
			parent = stack[len(stack)-1]
		}
		stack = append(stack, node)
		switch typed := node.(type) {
		case *ast.SelectorExpr:
			if seamFile {
				return true
			}
			if name == windowsSelfHealFile {
				for _, member := range []string{"TrustedProgramFiles", "TrustedProgramData"} {
					if selects(typed, winpathNames, member) {
						report(typed, "winpath."+member+" is resolved directly in the guardian's self-heal; ask windowsManagedLayout.programRoots")
					}
				}
			}
			if selects(typed, managedNames, "StandaloneWindowsLayout") {
				report(typed, "managed.StandaloneWindowsLayout is resolved directly; ask windowsManagedLayout.standalone")
			}
			if selects(typed, winpathNames, "TrustedEnterpriseRoots") {
				call, isCall := parent.(*ast.CallExpr)
				secureClientCall := isCall && call.Fun == typed && len(call.Args) == 1 && selects(call.Args[0], winpathNames, "EnterpriseProfileSecureClient")
				secureClientHost := name == "managed_host_guard_windows.go" && enclosingDecl() == "secureClientHost"
				if !secureClientCall && !secureClientHost {
					report(typed, "winpath.TrustedEnterpriseRoots is resolved directly; ask windowsManagedLayout.roots")
				}
			}
		case *ast.AssignStmt:
			for _, lhs := range typed.Lhs {
				if isSeam(lhs) {
					report(lhs, "windowsManagedLayout is written outside the tests")
				}
			}
		case *ast.UnaryExpr:
			if typed.Op == token.AND && isSeam(typed.X) {
				report(typed, "windowsManagedLayout's address is taken outside the tests")
			}
		case *ast.IncDecStmt:
			if isSeam(typed.X) {
				report(typed, "windowsManagedLayout is written outside the tests")
			}
		case *ast.ValueSpec:
			for _, ident := range typed.Names {
				if ident.Name == "windowsManagedLayout" && !seamFile {
					report(ident, "windowsManagedLayout is declared outside "+windowsManagedLayoutSeamFile)
				}
			}
		}
		return true
	})
	return problems
}

// cowork-1-0-8 GAP-0093 (round 2): every non-test file of internal/cli finds
// the computer's own standalone layout and trusted roots through
// windowsManagedLayout, which TestMain points at the run's sandbox once, and
// nothing outside the tests can repoint it: several callers decide trust from
// these roots. The scan reads every file whatever its build tags, so it runs
// on every OS.
func TestWindowsManagedLayoutIsTheOneSourceOfTheDeploymentRoots(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var problems []string
	uses, seamDeclared, selfHealUses := 0, false, 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		problems = append(problems, testDeploymentResolverProblems(fset, name, file)...)
		ast.Inspect(file, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.SelectorExpr:
				if ident, ok := typed.X.(*ast.Ident); ok && ident.Name == "windowsManagedLayout" {
					uses++
					if name == windowsSelfHealFile && typed.Sel.Name == "programRoots" {
						selfHealUses++
					}
				}
			case *ast.ValueSpec:
				for _, ident := range typed.Names {
					seamDeclared = seamDeclared || ident.Name == "windowsManagedLayout" && name == windowsManagedLayoutSeamFile
				}
			}
			return true
		})
	}
	sort.Strings(problems)
	if len(problems) != 0 {
		t.Fatalf("internal/cli goes around windowsManagedLayout:\n%s", strings.Join(problems, "\n"))
	}
	if !seamDeclared {
		t.Fatalf("windowsManagedLayout is not declared in %s", windowsManagedLayoutSeamFile)
	}
	if selfHealUses == 0 {
		t.Fatalf("%s does not ask windowsManagedLayout.programRoots: the scan read the wrong file", windowsSelfHealFile)
	}
	// 29 layout and 29 roots call sites at the change, plus the two
	// function values the package seams default to.
	if uses < 58 {
		t.Fatalf("only %d uses of windowsManagedLayout: the scan read the wrong files", uses)
	}
}

// The scan reports each way around the seam, and leaves the Secure Client
// lookups and the seam file alone.
func TestDeploymentResolverScanReportsEveryWayAroundTheSeam(t *testing.T) {
	const source = `package cli

import (
	"github.com/defenseclaw/defenseclaw/internal/managed"
	wp "github.com/defenseclaw/defenseclaw/internal/winpath"
)

var layoutDefault = managed.StandaloneWindowsLayout

func reads() {
	_, _ = managed.StandaloneWindowsLayout()
	_, _ = wp.TrustedEnterpriseRoots("standalone")
	_, _ = wp.TrustedEnterpriseRoots(wp.EnterpriseProfileSecureClient)
	windowsManagedLayout.roots = wp.TrustedEnterpriseRoots
	windowsManagedLayout = windowsManagedLayout
	_ = &windowsManagedLayout
	_, _ = windowsManagedLayout.standalone()
}

var secureClientHost = func() bool { return check(wp.TrustedEnterpriseRoots) }
`
	parse := func(name string) []string {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, name, source, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		return testDeploymentResolverProblems(fset, name, file)
	}
	problems := parse("some_windows.go")
	if len(problems) != 8 {
		t.Errorf("the scan reported %d problems, want 8:\n%s", len(problems), strings.Join(problems, "\n"))
	}
	got := strings.Join(problems, "\n")
	for _, want := range []string{
		"some_windows.go:8:", "some_windows.go:11:", "some_windows.go:12:",
		"some_windows.go:14:", "some_windows.go:15:", "some_windows.go:16:", "some_windows.go:20:",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the scan missed %s:\n%s", want, got)
		}
	}
	for _, quiet := range []string{"some_windows.go:13:", "some_windows.go:17:"} {
		if strings.Contains(got, quiet) {
			t.Errorf("the scan reported %s:\n%s", quiet, got)
		}
	}
	if got := parse("managed_host_guard_windows.go"); len(got) != 7 {
		t.Errorf("in the Secure Client host classification's file the scan reported %d, want 7 (all but secureClientHost's):\n%s", len(got), strings.Join(got, "\n"))
	}
	for _, problem := range parse(windowsManagedLayoutSeamFile) {
		if !strings.Contains(problem, "written") && !strings.Contains(problem, "address") {
			t.Errorf("the seam file may name the resolvers: %s", problem)
		}
	}
}

// The guardian's self-heal may not resolve the Program Files and ProgramData
// registrations itself; every other file may.
func TestDeploymentResolverScanCoversTheSelfHealRoots(t *testing.T) {
	const source = `package cli

import wp "github.com/defenseclaw/defenseclaw/internal/winpath"

func repair() {
	programFiles, _ := wp.TrustedProgramFiles()
	programData, _ := wp.TrustedProgramData()
	_, _ = programFiles, programData
	programFiles, programData = windowsManagedLayout.programRoots()
}
`
	parse := func(name string) []string {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, name, source, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		return testDeploymentResolverProblems(fset, name, file)
	}
	problems := parse(windowsSelfHealFile)
	got := strings.Join(problems, "\n")
	if len(problems) != 2 || !strings.Contains(got, windowsSelfHealFile+":6:") || !strings.Contains(got, windowsSelfHealFile+":7:") {
		t.Errorf("the scan reported %d problems in the self-heal file, want lines 6 and 7:\n%s", len(problems), got)
	}
	if other := parse("windows_managed_hooks_lifecycle.go"); len(other) != 0 {
		t.Errorf("the scan reported a file that classifies a path by the registrations:\n%s", strings.Join(other, "\n"))
	}
}
