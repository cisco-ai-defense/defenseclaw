// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// substrate-1:GAP-0538(i): helmBinary skips a test where helm is missing
// unless DEFENSECLAW_HELM_REQUIRED is set, and only the CI job
// substrate-chart sets it, with the pinned helm. That job ran
// `go test -run '^TestChart'`, so a helm test with another name skipped in
// every run and still printed ok: it never rendered the chart anywhere. Every
// test of this package that reaches helmBinary must be one that job selects.
func TestEveryHelmTestRunsInTheChartJob(t *testing.T) {
	ci, err := os.ReadFile(filepath.Join("..", "..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	// A Windows checkout (core.autocrlf, as on the GitHub runners) ends the
	// workflow's lines with CRLF; ciJob finds jobs by "\n  name:\n"
	// (rel-1-0-10:GAP-1544).
	job := ciJob(t, strings.ReplaceAll(string(ci), "\r\n", "\n"), "substrate-chart")
	if !strings.Contains(job, `DEFENSECLAW_HELM_REQUIRED: "1"`) {
		t.Fatal("the CI job substrate-chart does not set DEFENSECLAW_HELM_REQUIRED: a missing helm would skip")
	}
	var filters []string
	runFlag := regexp.MustCompile(`-run[= ]+(?:'([^']*)'|"([^"]*)"|(\S+))`)
	for _, line := range strings.Split(job, "\n") {
		if !strings.Contains(line, "go test") || !strings.Contains(line, "./internal/substrate/setup") {
			continue
		}
		filter := ""
		if m := runFlag.FindStringSubmatch(line); m != nil {
			filter = m[1] + m[2] + m[3]
		}
		filters = append(filters, filter)
	}
	if len(filters) == 0 {
		t.Fatal("the CI job substrate-chart runs no go test of ./internal/substrate/setup")
	}
	selected := func(name string) bool {
		for _, filter := range filters {
			// go test matches -run per level of the name split on '/';
			// a top-level test is matched by the first part.
			first, _, _ := strings.Cut(filter, "/")
			if first == "" || regexp.MustCompile(first).MatchString(name) {
				return true
			}
		}
		return false
	}
	helmTests := testsReachingHelm(t)
	if len(helmTests) == 0 {
		t.Fatal("found no test that calls helmBinary: the scan is broken")
	}
	for _, name := range helmTests {
		if !selected(name) {
			t.Errorf("%s needs helm but the CI job substrate-chart (-run %q) does not run it, so it only ever skips", name, filters)
		}
	}
}

// ciJob is the text of one job of a workflow file: from its two-space key to
// the next job key.
func ciJob(t *testing.T, workflow, name string) string {
	t.Helper()
	start := strings.Index(workflow, "\n  "+name+":\n")
	if start < 0 {
		t.Fatalf("ci.yml has no job %s", name)
	}
	rest := workflow[start+1:]
	next := regexp.MustCompile(`\n  [A-Za-z0-9_-]+:\n`).FindStringIndex(rest[len(name)+3:])
	if next == nil {
		return rest
	}
	return rest[:len(name)+3+next[0]]
}

// testsReachingHelm lists the Test functions of this package's test files
// that call helmBinary, directly or through other functions of the package.
func testsReachingHelm(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	calls := map[string][]string{}
	fset := token.NewFileSet()
	for _, file := range files {
		parsed, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || fn.Recv != nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if id, ok := call.Fun.(*ast.Ident); ok {
						calls[fn.Name.Name] = append(calls[fn.Name.Name], id.Name)
					}
				}
				return true
			})
		}
	}
	reaches := map[string]bool{"helmBinary": true}
	for changed := true; changed; {
		changed = false
		for fn, callees := range calls {
			if reaches[fn] {
				continue
			}
			if slices.ContainsFunc(callees, func(c string) bool { return reaches[c] }) {
				reaches[fn], changed = true, true
			}
		}
	}
	var tests []string
	for fn := range reaches {
		if strings.HasPrefix(fn, "Test") {
			tests = append(tests, fn)
		}
	}
	slices.Sort(tests)
	return tests
}
