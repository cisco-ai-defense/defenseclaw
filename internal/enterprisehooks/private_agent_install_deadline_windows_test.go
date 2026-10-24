//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestWindowsPrivateInstallDeadlineKeepsOtherProfilesAndRows(t *testing.T) {
	stubMachineWinGet(t, nil)
	firstHome, secondHome := codexProfile(t, "0.150.0"), codexProfile(t, "0.150.0")
	old := filepath.Join(firstHome, "nested", "node_modules", "@openai", "codex")
	windowsClaudeCopy(t, old, "0.0.1", `bin\codex.js`)
	injectWindowsProfileList(t, map[string]string{testLocalUserSID: firstHome, testLocalUserTwo: secondHome})
	windowsProfileListSubkeyReader = func() ([]string, error) { return []string{testLocalUserSID, testLocalUserTwo}, nil }
	enabled := true
	prior := writeWindowsTestManifest(t, ManifestTarget{
		SID: testLocalUserTwo, Connector: "codex", UserHome: secondHome,
		DataDir: filepath.Join(secondHome, ".defenseclaw"), AgentVersion: "0.150.0", Enabled: &enabled,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var reported []UnprotectedAgent
	manifest, err := EnumerateWindows(ctx, standaloneEnumeratorConfig("codex"), EnumerateOptions{
		ExistingManifestPath: prior,
		ReportUnprotected: func(agent UnprotectedAgent) {
			reported = append(reported, agent)
			if agent.InstallPath == old {
				cancel()
			}
		},
	})
	if err != nil {
		t.Fatalf("a profile deadline must not fail the manifest: %v", err)
	}
	if len(manifest.Targets) != 2 || manifest.Targets[0].SID != testLocalUserSID ||
		manifest.Targets[1].SID != testLocalUserTwo || manifest.Targets[1].AgentVersion != "0.150.0" {
		t.Fatalf("decided and prior rows lost: %+v", manifest.Targets)
	}
	var oldCopy, laterIncomplete bool
	for _, agent := range reported {
		oldCopy = oldCopy || agent.SID == testLocalUserSID && agent.InstallPath == old
		laterIncomplete = laterIncomplete || agent.SID == testLocalUserTwo && agent.Code == UnprotectedCodeInstallScanIncomplete &&
			strings.Contains(agent.Reason, "could not be inspected this cycle")
	}
	if !oldCopy || !laterIncomplete {
		t.Fatalf("decided copy and uninspected account must both be reported: %+v", reported)
	}
}

func TestWindowsPrivateInstallExpiredProfileIsIncomplete(t *testing.T) {
	home := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	found := DiscoverWindowsPrivateAgentInstalls(ctx, home, []string{"claudecode", "codex"})
	if len(found) != 2 {
		t.Fatalf("expired scan = %+v, want one incomplete finding per connector", found)
	}
	for _, install := range found {
		if !install.Incomplete || install.Skipped != PrivateInstallSkippedHome {
			t.Fatalf("expired scan silently completed: %+v", found)
		}
	}
}

func TestWindowsOversizedProfileLeavesOnlyThatAccountIncomplete(t *testing.T) {
	stubMachineWinGet(t, nil)
	firstHome, secondHome := codexProfile(t, "0.150.0"), codexProfile(t, "0.150.0")
	for i := 0; i < 24; i++ {
		if err := os.Mkdir(filepath.Join(firstHome, "folder"+strconv.Itoa(i)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	bound := privateInstallWalkMaxEntries
	privateInstallWalkMaxEntries = 20
	t.Cleanup(func() { privateInstallWalkMaxEntries = bound })
	injectWindowsProfileList(t, map[string]string{testLocalUserSID: firstHome, testLocalUserTwo: secondHome})
	var reported []UnprotectedAgent
	manifest, err := EnumerateWindows(context.Background(), standaloneEnumeratorConfig("codex"), EnumerateOptions{
		ReportUnprotected: func(agent UnprotectedAgent) { reported = append(reported, agent) },
	})
	if err != nil || len(manifest.Targets) != 2 {
		t.Fatalf("oversized profile failed the manifest: targets=%+v err=%v", manifest.Targets, err)
	}
	var firstIncomplete bool
	for _, agent := range reported {
		if agent.SID == testLocalUserTwo && agent.Code == UnprotectedCodeInstallScanIncomplete {
			t.Fatalf("healthy sibling profile became incomplete: %+v", reported)
		}
		firstIncomplete = firstIncomplete || agent.SID == testLocalUserSID && agent.Code == UnprotectedCodeInstallScanIncomplete
	}
	if !firstIncomplete {
		t.Fatalf("oversized profile was silently complete: %+v", reported)
	}
}

func TestWindowsProfileTimeoutLeavesSiblingItsOwnScanShare(t *testing.T) {
	stubMachineWinGet(t, nil)
	firstHome, secondHome := codexProfile(t, "0.150.0"), codexProfile(t, "0.150.0")
	injectWindowsProfileList(t, map[string]string{testLocalUserSID: firstHome, testLocalUserTwo: secondHome})
	previousReader := windowsProfileListSubkeyReader
	t.Cleanup(func() { windowsProfileListSubkeyReader = previousReader })
	windowsProfileListSubkeyReader = func() ([]string, error) { return []string{testLocalUserSID, testLocalUserTwo}, nil }
	old := windowsPrivateInstallsForEnumeration
	t.Cleanup(func() { windowsPrivateInstallsForEnumeration = old })
	var called []string
	windowsPrivateInstallsForEnumeration = func(ctx context.Context, home string, names []string) []PrivateAgentInstall {
		called = append(called, home)
		if home == firstHome {
			<-ctx.Done() // This home consumes its entire profile share.
			return []PrivateAgentInstall{{Connector: "codex", Incomplete: true, Skipped: PrivateInstallSkippedHome}}
		}
		if ctx.Err() != nil {
			return []PrivateAgentInstall{{Connector: "codex", Incomplete: true, Skipped: PrivateInstallSkippedHome}}
		}
		return nil
	}
	cycleCtx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	var reported []UnprotectedAgent
	manifest, err := EnumerateWindows(cycleCtx, standaloneEnumeratorConfig("codex"), EnumerateOptions{
		ReportUnprotected: func(agent UnprotectedAgent) { reported = append(reported, agent) },
	})
	if err != nil || len(manifest.Targets) != 2 {
		t.Fatalf("profile share lost manifest rows: targets=%+v err=%v", manifest.Targets, err)
	}
	if len(called) != 2 || called[0] != firstHome || called[1] != secondHome {
		t.Fatalf("profile scans = %q, want both homes", called)
	}
	var firstIncomplete bool
	for _, agent := range reported {
		if agent.SID == testLocalUserTwo && agent.Code == UnprotectedCodeInstallScanIncomplete {
			t.Fatalf("sibling did not receive an independent share: %+v", reported)
		}
		firstIncomplete = firstIncomplete || agent.SID == testLocalUserSID && agent.Code == UnprotectedCodeInstallScanIncomplete &&
			strings.Contains(agent.Reason, "home could not be fully listed")
	}
	if !firstIncomplete {
		t.Fatalf("timed-out home did not report home_unreadable: %+v", reported)
	}
}

func TestWindowsPrivateProfileBudgetReservesPublicationTime(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if got := windowsPrivateProfileBudget(ctx, 2); got != 20*time.Second {
		t.Fatalf("two-profile share = %v, want 20s cap", got)
	}
	short, stop := context.WithTimeout(context.Background(), 9*time.Second)
	defer stop()
	if got := windowsPrivateProfileBudget(short, 2); got != 0 {
		t.Fatalf("publication margin consumed by scan: %v", got)
	}
}

func TestWindowsUnenrolledRunningAgentIsReportedBeforeAndAfterDeadline(t *testing.T) {
	stubMachineWinGet(t, nil)
	home := t.TempDir()
	injectWindowsProfileList(t, map[string]string{testLocalUserSID: home})
	for _, tc := range []struct {
		name     string
		deadline bool
		excluded bool
	}{
		{name: "normal cycle"},
		{name: "no profile time left", deadline: true},
		{name: "explicitly excluded", deadline: true, excluded: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.deadline {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 9*time.Second)
				defer cancel()
			}
			var reported []UnprotectedAgent
			opts := EnumerateOptions{
				ManifestSubjects:  map[string]WindowsManifestSubject{},
				RunningAgents:     map[string]map[string]string{testLocalUserSID: {"codex": "codex (pid 42)"}},
				ReportUnprotected: func(agent UnprotectedAgent) { reported = append(reported, agent) },
			}
			if tc.excluded {
				opts.ExcludeUsers = []string{testLocalUserSID}
			}
			manifest, err := EnumerateWindows(ctx, standaloneEnumeratorConfig("codex"), opts)
			if err != nil || len(manifest.Targets) != 0 {
				t.Fatalf("unenrolled profile acquired rows: %+v, err=%v", manifest.Targets, err)
			}
			if tc.excluded {
				if len(reported) != 0 {
					t.Fatalf("excluded profile was reported: %+v", reported)
				}
				return
			}
			if len(reported) != 1 || reported[0].SID != testLocalUserSID ||
				reported[0].Connector != "codex" || reported[0].Code != UnprotectedCodeAgentUnprotected ||
				!strings.Contains(reported[0].Reason, "no enabled enrollment manifest target") {
				t.Fatalf("running unenrolled agent was not reported: %+v", reported)
			}
		})
	}
}

func TestWindowsPrivateWalkChildKeepsHeldParentAcrossJunctionSwap(t *testing.T) {
	home, outside := t.TempDir(), t.TempDir()
	parent := filepath.Join(home, "parent")
	for _, dir := range []string{filepath.Join(parent, "nested"), filepath.Join(outside, "nested")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(parent, "nested", "inside"), []byte("fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "nested", "outside"), []byte("fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := openWindowsPrivateWalkDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := os.Rename(parent, parent+"-held"); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", parent, outside).CombinedOutput(); err != nil {
		t.Fatalf("replace parent with junction: %v: %s", err, out)
	}
	child, err := openWindowsPrivateWalkChild(f, "nested")
	if err != nil {
		t.Fatal(err)
	}
	defer child.Close()
	entries, err := child.ReadDir(-1)
	if err != nil || len(entries) != 1 || entries[0].Name() != "inside" {
		t.Fatalf("child of held parent followed replacement: %+v, %v", entries, err)
	}
}
