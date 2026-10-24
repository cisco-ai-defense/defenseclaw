//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The private-copy scanner reports runnable npm packages, not a leftover
// package.json without the Codex entry point.
func writeRunnableWindowsCodexCopy(t *testing.T, dir, version string) {
	t.Helper()
	writeWindowsAgentPackageJSON(t, dir, version)
	entry := filepath.Join(dir, "bin", "codex.js")
	if err := os.MkdirAll(filepath.Dir(entry), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(entry, []byte("fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Under manifest enrollment the administrator's enabled targets are the
// accounts inspected: a target the group filters would exclude is
// inspected, a profile no enabled row names is not, a target ProfileList
// does not list is inspected at its authored home, and exclude_users still
// wins (GAP-0906).
func TestEnumerateWindowsManifestSubjectsAreTheInspectedAccounts(t *testing.T) {
	stubMachineWinGet(t, nil)
	stubGroupDirectory(t, map[string]string{`contoso\contractors`: testDomainGroupSID}, map[string][]string{})
	stubActiveSessions(t, map[string][]string{testDomainUserA: {testDomainGroupSID}})
	withOldCodex := func() string {
		home := codexProfile(t, "0.150.0")
		writeRunnableWindowsCodexCopy(t, filepath.Join(home, "private", "node_modules", "@openai", "codex"), "0.0.1")
		return home
	}
	homeA, homeB, homeC, homeD := withOldCodex(), withOldCodex(), withOldCodex(), withOldCodex()
	injectWindowsProfileList(t, map[string]string{
		testDomainUserA: homeA, // authored, in an excluded group
		testDomainUserB: homeB, // not authored
		testDomainUserC: homeC, // authored, excluded by name
	})
	enabled := true
	subjects := WindowsManifestSubjects(Manifest{Version: 1, Targets: []ManifestTarget{
		{SID: testDomainUserA, Connector: "codex", UserHome: homeA, Enabled: &enabled},
		{SID: testDomainUserC, Connector: "codex", UserHome: homeC, Enabled: &enabled},
		{SID: testLocalUserTwo, Connector: "codex", UserHome: homeD, Enabled: &enabled}, // not in ProfileList
	}})
	var reported []UnprotectedAgent
	_, err := EnumerateWindows(context.Background(), standaloneEnumeratorConfig("codex"), EnumerateOptions{
		ExcludeGroups:     []string{`CONTOSO\Contractors`},
		ExcludeUsers:      []string{testDomainUserC},
		GroupCache:        NewWindowsEnrollmentGroupCache(),
		ManifestSubjects:  subjects,
		ReportUnprotected: func(agent UnprotectedAgent) { reported = append(reported, agent) },
	})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, agent := range reported {
		if strings.Contains(agent.InstallPath, filepath.Join("private", "node_modules")) {
			got = append(got, agent.SID+" "+agent.Version)
		}
	}
	sort.Strings(got)
	want := []string{testLocalUserTwo + " 0.0.1", testDomainUserA + " 0.0.1"}
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("old copies reported for %v, want %v; all: %+v", got, want, reported)
	}
}
