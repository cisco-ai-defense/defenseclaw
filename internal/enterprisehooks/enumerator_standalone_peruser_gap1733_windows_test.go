// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-1733: a newly discovered account whose folder holds a per-user
// DefenseClaw install gets no row. The plan skips it, and a row written again
// republished targets.yaml after the install. The account is logged with the
// folder and the entry, and is reported as not protected, and the other
// account is enrolled. The folder is the one a per-user 1.0.10 install
// leaves, with its own DACL (owner and LocalSystem only), so an elevated
// Administrator cannot see its entries by path. The enumerator reads it as it
// does live, with no test hook. An account the manifest already holds a row
// for was adopted. There the same entry in its managed folder is tamper,
// which the guardian reports, and the new row is written (GAP-1733 review).
func TestEnumerateWindowsStandaloneSkipsANewRowWithAPerUserInstall(t *testing.T) {
	if !windowsTestRunsAsLocalSystem(t) && !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated Administrator to build the per-user install folder")
	}
	t.Setenv(managed.TrustStrictAncestorsEnv, "")
	stubMachineWinGet(t, nil)
	domain := fmt.Sprintf("S-1-5-21-1733%06d-%d-%d", os.Getpid()%1000000, time.Now().UnixNano()%1000000000, 1734)
	perUser := newGAP1733PerUserAccount(t, domain+"-1001")
	adopted := newGAP1733PerUserAccount(t, domain+"-1002")
	for _, account := range []gap1733Account{perUser, adopted} {
		writeWindowsAgentPackageJSON(t, filepath.Join(account.home, "AppData", "Local", "Programs", "cursor", "resources", "app"), "2.5.0")
	}
	perUserSID, adoptedSID := perUser.sid.String(), adopted.sid.String()
	injectWindowsProfileList(t, map[string]string{
		testLocalUserSID: cursorProfile(t, "2.5.0"),
		perUserSID:       perUser.home,
		adoptedSID:       adopted.home,
	})
	enabled := true
	existing := writeWindowsTestManifest(t, ManifestTarget{SID: adoptedSID, Connector: "codex", UserHome: adopted.home,
		DataDir: filepath.Join(adopted.home, ".defenseclaw"), AgentVersion: "0.150.0", Enabled: &enabled})
	var logged []string
	var reported []UnprotectedAgent
	manifest, err := EnumerateWindows(context.Background(), standaloneEnumeratorConfig("cursor"), EnumerateOptions{
		ExistingManifestPath: existing,
		Logger:               func(subject, reason string) { logged = append(logged, subject+": "+reason) },
		ReportUnprotected:    func(agent UnprotectedAgent) { reported = append(reported, agent) },
	})
	if err != nil {
		t.Fatalf("EnumerateWindows: %v", err)
	}
	var cursorRows []string
	for _, target := range manifest.Targets {
		if target.Connector == "cursor" {
			cursorRows = append(cursorRows, target.SID)
		}
	}
	sort.Strings(cursorRows)
	want := []string{adoptedSID, testLocalUserSID}
	sort.Strings(want)
	if strings.Join(cursorRows, ",") != strings.Join(want, ",") {
		t.Fatalf("cursor rows = %v, want the account without a per-user install and the adopted account %v; targets %+v", cursorRows, want, manifest.Targets)
	}
	wantLog := perUserSID + ": newly-discovered (SID, cursor) row skipped: " + perUser.data +
		" holds config.yaml, which a per-user DefenseClaw install leaves"
	if !strings.Contains(strings.Join(logged, "\n"), wantLog) {
		t.Fatalf("the skipped row must be logged with its folder; log:\n%s", strings.Join(logged, "\n"))
	}
	found := false
	for _, agent := range reported {
		found = found || (agent.SID == perUserSID && strings.Contains(agent.Message(), "is not protected") &&
			strings.Contains(agent.Reason, "per-user DefenseClaw install"))
	}
	if !found {
		t.Fatalf("the account was not reported as not protected: %+v", reported)
	}
}
