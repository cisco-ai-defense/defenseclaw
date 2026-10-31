// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/kernelpolicy"
)

// findingsOf is tetragonFindings with the inputs spelled out.
func findingsOf(goos string, intent tetragonIntent, haveIntent bool, state kernelpolicy.State, running bool, host tetragonHost) []tetragonFinding {
	return tetragonFindings(tetragonInputs{GOOS: goos, Intent: intent, HaveIntent: haveIntent, State: state, Running: running, Host: host})
}

// stringConstants returns the string constants of the Go files matched by
// glob (tests excluded) whose name has one of the prefixes.
func stringConstants(t *testing.T, glob string, prefixes ...string) map[string]string {
	t.Helper()
	files, err := filepath.Glob(glob)
	if err != nil || len(files) == 0 {
		t.Fatalf("glob %s: %v %v", glob, files, err)
	}
	out := map[string]string{}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			spec, ok := node.(*ast.ValueSpec)
			if !ok {
				return true
			}
			for i, name := range spec.Names {
				if i >= len(spec.Values) {
					continue
				}
				lit, ok := spec.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				for _, prefix := range prefixes {
					if strings.HasPrefix(name.Name, prefix) {
						value, _ := strconv.Unquote(lit.Value)
						out[file+":"+name.Name] = value
					}
				}
			}
			return true
		})
	}
	return out
}

// Every warning and reason code the helper, the Tetragon client, the config
// caps and this package raise has words in the table (or, for the reasons a
// session is observed but not enforced, in observedReasonWords).
func TestEveryTetragonCodeHasText(t *testing.T) {
	codes := stringConstants(t, "../sensor/kernelpolicy/types.go", "Warn", "Reason")
	for name, value := range stringConstants(t, "../sensor/tetragon/info.go", "Reason") {
		codes[name] = value
	}
	for name, value := range stringConstants(t, "../config/enterprise.go", "TetragonReason") {
		codes[name] = value
	}
	for name, value := range stringConstants(t, "tetragon_*.go", "code") {
		if strings.HasPrefix(value, "kernel_") || strings.HasPrefix(value, "tetragon_") || strings.HasPrefix(value, "enrollment_") {
			codes[name] = value
		}
	}
	if len(codes) < 30 {
		t.Fatalf("found only %d codes: %v", len(codes), codes)
	}
	// The helper's warnings written as literals rather than constants.
	literal := regexp.MustCompile(`addUnique\([^,]+, "([a-z_]+)"\)`)
	sources, _ := filepath.Glob("../sensor/kernelpolicy/*.go")
	for _, file := range sources {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range literal.FindAllStringSubmatch(string(data), -1) {
			codes[file+":"+match[1]] = match[1]
		}
	}
	for name, value := range codes {
		base, _, _ := strings.Cut(value, ":")
		if _, ok := tetragonCodes[base]; ok {
			continue
		}
		if _, ok := observedReasonWords[value]; ok {
			continue
		}
		t.Errorf("%s = %q has no entry in tetragonCodes", name, value)
	}
}

// fullTetragonFacts sets every fact a message can name.
func fullTetragonFacts(variant string) tetragonFacts {
	at := time.Date(2026, 10, 7, 9, 12, 0, 0, time.UTC)
	return tetragonFacts{
		Variant: variant, Detail: "claudecode", Mode: "enforce", Applied: "observe", Digest: kernelpolicy.Digest(),
		Ack: "sha256:000000000000", Address: "localhost:54321", Path: "/var/run/tetragon/tetragon.sock",
		Owner: "uid 1000", Perm: "0777", Version: "v1.8.0",
		Pause:        &kernelpolicy.Pause{Until: at.Add(4 * time.Hour), SetByUID: 1001, SetAt: at, Reason: "dccert maintenance"},
		PauseInvalid: "tetragon-pause: not a root-owned regular file", SetBy: "alice (uid 1001)", At: at, Verb: "deleted",
		Names: []string{"defenseclaw-controls-0a1b2c3d"}, UserCount: 1, Connectors: []string{"cursor"},
		Count: 3, State: "load_error", Error: "selector rejected", ETA: "~9 days", Why: "the sensor helper binary is gone",
	}
}

// allTetragonMessages renders every code with every variant it has.
func allTetragonMessages() map[string]string {
	out := map[string]string{}
	for code, entry := range tetragonCodes {
		variants := entry.Variants
		if len(variants) == 0 {
			variants = []string{""}
		}
		for _, variant := range variants {
			out[code+"/"+variant] = entry.Message(fullTetragonFacts(variant))
		}
	}
	return out
}

var (
	backticked   = regexp.MustCompile("`([^`]+)`")
	yamlSetting  = regexp.MustCompile(`^[a-z_]+(\.[a-z_<>]+)+: \S.*$`)
	tetragonFlag = regexp.MustCompile(`^echo \S+ \| sudo tee /etc/tetragon/tetragon\.conf\.d/[a-z-]+$`)
)

// runnableHint reports whether a quoted span is something an administrator
// can paste as printed: a root command with its path, a systemctl or
// journalctl call, a Tetragon flag write, or a YAML setting.
func runnableHint(span string) bool {
	for _, prefix := range []string{
		"sudo " + adminBinDir + "/", "sudo systemctl ", "sudo journalctl ", "systemctl status ", "sudo tetra tracingpolicy ",
	} {
		if strings.HasPrefix(span, prefix) {
			return true
		}
	}
	return tetragonFlag.MatchString(span) || yamlSetting.MatchString(span)
}

// Every command in every message runs as printed (sudo and the package path:
// the binaries are not on PATH and sudo resets PATH), and every message has
// the lifecycle's "<what> (<impact>); <next step>" shape.
func TestTetragonHintsAreRunnable(t *testing.T) {
	messages := allTetragonMessages()
	for name, message := range messages {
		if !strings.Contains(message, "); ") {
			t.Errorf("%s does not read <what> (<impact>); <next step>: %s", name, message)
		}
		for _, match := range backticked.FindAllStringSubmatch(message, -1) {
			if !runnableHint(match[1]) {
				t.Errorf("%s: %q does not run as printed: %s", name, match[1], message)
			}
		}
		if strings.Contains(strings.ReplaceAll(message, binGateway+" enterprise linux", ""), "enterprise linux ") {
			t.Errorf("%s names an enterprise linux command without its path: %s", name, message)
		}
	}
	// The same holds for every hint written into this package's Tetragon
	// sources (changes, refusals, the readiness checks).
	files, _ := filepath.Glob("tetragon_*.go")
	files = append(files, "policystate.go")
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			lit, ok := node.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			for _, match := range backticked.FindAllStringSubmatch(value, -1) {
				if !runnableHint(match[1]) {
					t.Errorf("%s: %q does not run as printed", file, match[1])
				}
			}
			return true
		})
	}
}

// A code the table does not know (only a newer helper reports one) prints as
// the helper wrote it, with the status command to look further.
func TestUnknownTetragonCodePrintsAsWritten(t *testing.T) {
	got := tetragonMessage("kernel_something_new:detail", tetragonFacts{})
	if !strings.HasPrefix(got, "kernel_something_new:detail (reported by the sensor helper); see `sudo ") {
		t.Fatalf("message %q", got)
	}
	// The detail of a known code fills its message.
	if got := tetragonMessage(kernelpolicy.WarnGuardrailObserve+":codex", tetragonFacts{}); !strings.Contains(got, "`guardrail.connectors.codex.mode: action`") {
		t.Fatalf("message %q", got)
	}
}

// Every code, and the doctor spelling of each that doctor reports, is on the
// troubleshooting page an administrator reads.
func TestEveryTetragonCodeIsDocumented(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "docs-site", "content", "docs", "enterprise", "troubleshooting.mdx"))
	if err != nil {
		t.Fatal(err)
	}
	page := string(data)
	var missing []string
	for code, entry := range tetragonCodes {
		if !strings.Contains(page, "`"+code+"`") && !strings.Contains(page, "`"+code+":") {
			missing = append(missing, code)
		}
		if entry.Doctor != "" && !strings.Contains(page, "`"+entry.Doctor+"`") {
			missing = append(missing, entry.Doctor+" (doctor spelling of "+code+")")
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("enterprise/troubleshooting.mdx does not list:\n  %s", strings.Join(missing, "\n  "))
	}
}

// The helper reports a protected file with a second hard link by its path;
// status and verify print the path, one line per file (rel-1-0-6 GAP-0124).
func TestExtraLinkWarningsNameTheFile(t *testing.T) {
	first, second := "/home/alice/.ssh/authorized_keys", "/home/bob/.ssh/authorized_keys"
	var state kernelpolicy.State
	state.Warnings = []string{
		kernelpolicy.NoteExtraLinks + ":" + first,
		kernelpolicy.NoteExtraLinks + ":" + second,
		kernelpolicy.NoteDentryMount + ":" + first,
	}
	var codes []string
	for _, finding := range findingsOf("linux", tetragonIntent{}, false, state, true, tetragonHost{}) {
		codes = append(codes, finding.Code)
		if strings.Contains(finding.Message, "reported by the sensor helper") {
			t.Errorf("%s printed as an unknown code: %s", finding.Code, finding.Message)
		}
		_, file, _ := strings.Cut(finding.Code, ":")
		if file == "" || !strings.Contains(finding.Message, file) {
			t.Errorf("%s: the message does not name the file: %s", finding.Code, finding.Message)
		}
	}
	want := []string{
		kernelpolicy.NoteExtraLinks + ":" + first, kernelpolicy.NoteExtraLinks + ":" + second,
		kernelpolicy.NoteDentryMount + ":" + first,
	}
	sort.Strings(codes)
	sort.Strings(want)
	if strings.Join(codes, "\n") != strings.Join(want, "\n") {
		t.Fatalf("codes %v, want %v", codes, want)
	}
}

// A code only a newer helper reports keeps its detail when it prints.
func TestUnknownTetragonCodeKeepsItsDetail(t *testing.T) {
	got := tetragonMessage("kernel_something_new", tetragonFacts{Detail: "/home/a"})
	if !strings.HasPrefix(got, "kernel_something_new:/home/a (reported by the sensor helper)") {
		t.Fatalf("message %q", got)
	}
}

// status-v2 GAP-0005: the enforce-inactive warning that status, verify and
// ensure carry counts the enrolled users without an agent and names none.
func TestEnforceInactiveCountsTheUsersWithoutAnAgent(t *testing.T) {
	in := tetragonInputs{GOOS: "linux"}
	in.State.UIDs = []kernelpolicy.UIDStatus{
		{UID: 1002, User: "dcr-std2", State: kernelpolicy.UIDInactive, Reason: kernelpolicy.ReasonNoAnchors},
		{UID: 1003, User: "dcr-std3", State: kernelpolicy.UIDInactive, Reason: kernelpolicy.ReasonNoAnchors},
		{UID: 1004, User: "dcr-std4", Connectors: []string{"claudecode"}, State: kernelpolicy.UIDEnforcing},
	}
	message := tetragonMessage(kernelpolicy.WarnEnforceInactive, inactiveFacts("", in))
	if !strings.Contains(message, "no agent installed for 2 enrolled users") {
		t.Fatalf("enforce-inactive warning does not count the users: %q", message)
	}
	for _, name := range []string{"dcr-std2", "dcr-std3", "dcr-std4", "1002", "1003"} {
		if strings.Contains(message, name) {
			t.Fatalf("enforce-inactive warning names %s: %q", name, message)
		}
	}
}
