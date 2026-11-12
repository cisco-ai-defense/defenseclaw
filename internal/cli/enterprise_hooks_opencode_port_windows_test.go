//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

const (
	openCodeSIDFirst  = "S-1-5-21-100-200-300-1001"
	openCodeSIDSecond = "S-1-5-21-400-500-600-1002"
	openCodeSIDThird  = "S-1-5-21-700-800-900-1003"
)

type managedWindowsOpenCodePortFixture struct {
	profiles       []enterprisehooks.TargetCredentials
	homeSID        map[string]string
	record         map[string]int
	recordExists   bool
	contested      []enterprisehooks.WindowsOpenCodeContestedPort
	unknownEntries []enterprisehooks.WindowsOpenCodePortUnknown
	cleared        []enterprisehooks.WindowsOpenCodeContestCleared
	warningState   enterprisehooks.WindowsOpenCodeServicePortsState
	files          map[string]int
	claims         map[int]string
	readFailure    map[string]bool
	writeFailure   map[string]bool
	claimFailure   map[string]bool
	activeSID      string
	reads          int
	writes         int
}

func newManagedWindowsOpenCodePortFixture(t *testing.T) *managedWindowsOpenCodePortFixture {
	t.Helper()
	oldOptions, oldProfiles := enterpriseHookWindowsGuardianOptions, enterpriseHookWindowsEligibleProfiles
	oldLoad, oldWrite, oldLock := enterpriseHookWindowsOpenCodePortsLoad, enterpriseHookWindowsOpenCodePortsWrite, enterpriseHookWindowsOpenCodePortsLock
	oldRead, oldSet, oldRunAs := enterpriseHookWindowsOpenCodeRead, enterpriseHookWindowsOpenCodeSet, enterpriseHookWindowsOpenCodeRunAs
	oldClaims, oldClaim := enterpriseHookWindowsOpenCodeClaims, enterpriseHookWindowsOpenCodeClaim
	oldWarningWrite, oldWarningItemsWrite := enterpriseHookWindowsOpenCodeWarningWrite, enterpriseHookWindowsOpenCodeWarningItemsWrite
	oldManifest, oldConfig := enterpriseHookManifest, cfg
	oldTimeout := enterpriseHookWindowsOpenCodeReadTimeout
	t.Cleanup(func() {
		enterpriseHookWindowsGuardianOptions, enterpriseHookWindowsEligibleProfiles = oldOptions, oldProfiles
		enterpriseHookWindowsOpenCodePortsLoad, enterpriseHookWindowsOpenCodePortsWrite = oldLoad, oldWrite
		enterpriseHookWindowsOpenCodePortsLock = oldLock
		enterpriseHookWindowsOpenCodeRead, enterpriseHookWindowsOpenCodeSet, enterpriseHookWindowsOpenCodeRunAs = oldRead, oldSet, oldRunAs
		enterpriseHookWindowsOpenCodeClaims, enterpriseHookWindowsOpenCodeClaim = oldClaims, oldClaim
		enterpriseHookWindowsOpenCodeWarningWrite, enterpriseHookWindowsOpenCodeWarningItemsWrite = oldWarningWrite, oldWarningItemsWrite
		enterpriseHookManifest, cfg = oldManifest, oldConfig
		enterpriseHookWindowsOpenCodeReadTimeout = oldTimeout
	})
	f := &managedWindowsOpenCodePortFixture{
		homeSID: map[string]string{}, record: map[string]int{}, files: map[string]int{}, claims: map[int]string{},
		readFailure: map[string]bool{}, writeFailure: map[string]bool{}, claimFailure: map[string]bool{},
	}
	cfg = nil
	enterpriseHookManifest = filepath.Join(t.TempDir(), "targets.yaml")
	enterpriseHookWindowsGuardianOptions = func() (enterprisepolicy.Options, []string, bool, error) {
		return enterprisepolicy.Options{}, []string{"opencode"}, true, nil
	}
	enterpriseHookWindowsEligibleProfiles = func(context.Context) ([]enterprisehooks.TargetCredentials, error) { return f.profiles, nil }
	enterpriseHookWindowsOpenCodePortsLock = func(string) (func(), error) { return func() {}, nil }
	enterpriseHookWindowsOpenCodePortsLoad = func(string) (enterprisehooks.WindowsOpenCodeServicePortsState, error) {
		copy := map[string]int{}
		for key, port := range f.record {
			copy[key] = port
		}
		return enterprisehooks.WindowsOpenCodeServicePortsState{Exists: f.recordExists || len(copy) > 0, ImportDone: f.recordExists || len(copy) > 0,
			Ports: copy, Unknown: append([]enterprisehooks.WindowsOpenCodePortUnknown(nil), f.unknownEntries...),
			Contested: append([]enterprisehooks.WindowsOpenCodeContestedPort(nil), f.contested...),
			Cleared:   append([]enterprisehooks.WindowsOpenCodeContestCleared(nil), f.cleared...)}, nil
	}
	enterpriseHookWindowsOpenCodePortsWrite = func(_ string, state enterprisehooks.WindowsOpenCodeServicePortsState) error {
		f.record = map[string]int{}
		for key, port := range state.Ports {
			f.record[key] = port
		}
		f.recordExists = true
		f.contested, f.unknownEntries, f.cleared = state.Contested, state.Unknown, state.Cleared
		f.writes++
		return nil
	}
	enterpriseHookWindowsOpenCodeRunAs = func(profile enterprisehooks.TargetCredentials, fn func() error) error {
		if f.activeSID != "" {
			return fmt.Errorf("overlapping account callback")
		}
		f.activeSID = profile.SID
		defer func() { f.activeSID = "" }()
		return fn()
	}
	enterpriseHookWindowsOpenCodeRead = func(home string) (int, error) {
		if f.activeSID != f.homeSID[home] {
			return 0, fmt.Errorf("read outside account token")
		}
		f.reads++
		if f.readFailure[home] {
			return 0, fmt.Errorf("account file unavailable")
		}
		return f.files[home], nil
	}
	enterpriseHookWindowsOpenCodeSet = func(home string, port int) (enterprisepolicy.OpenCodeServicePortResult, error) {
		if f.activeSID != f.homeSID[home] {
			return enterprisepolicy.OpenCodeServicePortResult{}, fmt.Errorf("write outside account token")
		}
		if f.writeFailure[home] {
			return enterprisepolicy.OpenCodeServicePortResult{}, fmt.Errorf("account file cannot be replaced")
		}
		previous := f.files[home]
		f.files[home] = port
		return enterprisepolicy.OpenCodeServicePortResult{Port: port, Previous: previous, Changed: previous != port}, nil
	}
	enterpriseHookWindowsOpenCodeClaims = func() (map[int]string, error) {
		copy := map[int]string{}
		for port, sid := range f.claims {
			copy[port] = sid
		}
		return copy, nil
	}
	enterpriseHookWindowsOpenCodeClaim = func(sid string, port int) error {
		if f.claimFailure[sid] || f.claims[port] != "" && f.claims[port] != sid {
			return fmt.Errorf("claim unavailable")
		}
		f.claims[port] = sid
		return nil
	}
	enterpriseHookWindowsOpenCodeWarningWrite = func(state enterprisehooks.WindowsOpenCodeServicePortsState) error {
		f.warningState = state
		return nil
	}
	enterpriseHookWindowsOpenCodeWarningItemsWrite = func([]windowsOpenCodePortWarning) error { return nil }
	return f
}

func (f *managedWindowsOpenCodePortFixture) add(t *testing.T, sid string) string {
	t.Helper()
	home := t.TempDir()
	f.profiles = append(f.profiles, enterprisehooks.TargetCredentials{SID: sid, UserHome: home})
	f.homeSID[home] = sid
	return home
}

func (f *managedWindowsOpenCodePortFixture) run(t *testing.T) (map[string]int, error) {
	t.Helper()
	return enterpriseHookStandaloneOpenCodePorts(context.Background(), enterprisehooks.Manifest{})
}

func TestManagedWindowsOpenCodeRecordCommitFailureLeavesAccountFiles(t *testing.T) {
	f := newManagedWindowsOpenCodePortFixture(t)
	firstHome, secondHome, thirdHome := f.add(t, openCodeSIDFirst), f.add(t, openCodeSIDSecond), f.add(t, openCodeSIDThird)
	f.files[firstHome], f.files[secondHome] = 25003, 25003
	write := enterpriseHookWindowsOpenCodePortsWrite
	planned := map[string]int{}
	enterpriseHookWindowsOpenCodePortsWrite = func(_ string, state enterprisehooks.WindowsOpenCodeServicePortsState) error {
		for sid, port := range state.Ports {
			planned[sid] = port
		}
		return fmt.Errorf("record commit unavailable")
	}
	ports, err := f.run(t)
	if err == nil || len(ports) != 0 || len(f.record) != 0 || f.recordExists ||
		f.files[firstHome] != 25003 || f.files[secondHome] != 25003 || f.files[thirdHome] != 0 {
		t.Fatalf("failed commit changed an account file or record: ports=%v record=%v files=%v err=%v", ports, f.record, f.files, err)
	}
	enterpriseHookWindowsOpenCodePortsWrite = write
	ports, err = f.run(t)
	if err != nil || len(ports) != 3 || len(f.record) != 3 || len(f.contested) != 1 || f.contested[0].Port != 25003 ||
		f.record[openCodeSIDFirst] != planned[openCodeSIDFirst] || f.record[openCodeSIDSecond] != planned[openCodeSIDSecond] ||
		f.record[openCodeSIDThird] != planned[openCodeSIDThird] {
		t.Fatalf("retry did not commit the same import plan: planned=%v ports=%v record=%v marks=%v err=%v", planned, ports, f.record, f.contested, err)
	}
}

func TestManagedWindowsOpenCodeInterruptedPassResumesFromRecord(t *testing.T) {
	f := newManagedWindowsOpenCodePortFixture(t)
	firstHome, secondHome := f.add(t, openCodeSIDFirst), f.add(t, openCodeSIDSecond)
	f.files[firstHome], f.files[secondHome] = 25003, 25003
	write := enterpriseHookWindowsOpenCodePortsWrite
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	enterpriseHookWindowsOpenCodePortsWrite = func(path string, state enterprisehooks.WindowsOpenCodeServicePortsState) error {
		err := write(path, state)
		if err == nil {
			cancel() // stop after the record commit, before any account rewrite
		}
		return err
	}
	ports, err := enterpriseHookStandaloneOpenCodePorts(ctx, enterprisehooks.Manifest{})
	if err == nil || len(ports) != 0 || len(f.record) != 2 || !f.recordExists ||
		f.files[firstHome] != 25003 || f.files[secondHome] != 25003 || len(f.contested) != 1 {
		t.Fatalf("interrupted pass did not keep a whole record: ports=%v record=%v files=%v marks=%v err=%v", ports, f.record, f.files, f.contested, err)
	}
	enterpriseHookWindowsOpenCodePortsWrite = write
	ports, err = f.run(t)
	if err != nil || len(ports) != 2 || f.files[firstHome] != f.record[openCodeSIDFirst] ||
		f.files[secondHome] != f.record[openCodeSIDSecond] || len(f.contested) != 1 || f.reads != 2 {
		t.Fatalf("recovery did not use the committed record: ports=%v record=%v files=%v marks=%v reads=%d err=%v", ports, f.record, f.files, f.contested, f.reads, err)
	}
}

func TestManagedWindowsOpenCodeNewBindingSurvivesAccountFileRefusal(t *testing.T) {
	f := newManagedWindowsOpenCodePortFixture(t)
	firstHome, secondHome := f.add(t, openCodeSIDFirst), f.add(t, openCodeSIDSecond)
	f.writeFailure[firstHome] = true
	ports, err := f.run(t)
	firstPort, secondPort := f.record[openCodeSIDFirst], f.record[openCodeSIDSecond]
	if err == nil || ports[openCodeSIDFirst] != 0 || firstPort == 0 || secondPort == 0 || firstPort == secondPort ||
		f.files[firstHome] != 0 || f.files[secondHome] != secondPort || len(f.warningState.Unknown) != 1 {
		t.Fatalf("refused file lost a committed binding: ports=%v record=%v files=%v warnings=%v err=%v", ports, f.record, f.files, f.warningState.Unknown, err)
	}
	delete(f.writeFailure, firstHome)
	ports, err = f.run(t)
	if err != nil || ports[openCodeSIDFirst] != firstPort || f.files[firstHome] != firstPort ||
		f.record[openCodeSIDSecond] != secondPort || f.reads != 2 || len(f.warningState.Unknown) != 0 {
		t.Fatalf("ordinary recovery did not write the recorded binding: ports=%v record=%v files=%v warnings=%v reads=%d err=%v", ports, f.record, f.files, f.warningState.Unknown, f.reads, err)
	}
}

func TestManagedWindowsOpenCodeInterruptedRewriteResumesFromRecord(t *testing.T) {
	f := newManagedWindowsOpenCodePortFixture(t)
	firstHome, secondHome := f.add(t, openCodeSIDFirst), f.add(t, openCodeSIDSecond)
	f.files[firstHome], f.files[secondHome] = 25003, 25003
	set := enterpriseHookWindowsOpenCodeSet
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	enterpriseHookWindowsOpenCodeSet = func(home string, port int) (enterprisepolicy.OpenCodeServicePortResult, error) {
		result, err := set(home, port)
		if err == nil {
			cancel() // stop after the first account rewrite
		}
		return result, err
	}
	_, err := enterpriseHookStandaloneOpenCodePorts(ctx, enterprisehooks.Manifest{})
	if err == nil || len(f.record) != 2 || f.files[firstHome] != f.record[openCodeSIDFirst] ||
		f.files[secondHome] != 25003 || len(f.contested) != 1 {
		t.Fatalf("interrupted rewrite lost the whole record: record=%v files=%v marks=%v err=%v", f.record, f.files, f.contested, err)
	}
	enterpriseHookWindowsOpenCodeSet = set
	ports, err := f.run(t)
	if err != nil || ports[openCodeSIDSecond] != f.record[openCodeSIDSecond] ||
		f.files[secondHome] != f.record[openCodeSIDSecond] || len(f.contested) != 1 {
		t.Fatalf("next pass did not complete the rewrite: ports=%v record=%v files=%v marks=%v err=%v", ports, f.record, f.files, f.contested, err)
	}
}

func TestManagedWindowsGuardianKeepsOpenCodePortsBySIDAcrossEligibilityChanges(t *testing.T) {
	f := newManagedWindowsOpenCodePortFixture(t)
	firstHome, secondHome := f.add(t, openCodeSIDFirst), f.add(t, openCodeSIDSecond)
	first, err := f.run(t)
	if err != nil || first[openCodeSIDFirst] != 25001 || first[openCodeSIDSecond] != 25002 || f.reads != 2 {
		t.Fatalf("first pass: ports=%v reads=%d err=%v", first, f.reads, err)
	}
	second, err := f.run(t)
	if err != nil || second[openCodeSIDFirst] != 25001 || second[openCodeSIDSecond] != 25002 || f.reads != 2 {
		t.Fatalf("stable pass reread account files: ports=%v reads=%d err=%v", second, f.reads, err)
	}
	f.profiles = f.profiles[1:]
	f.record["S-1-5-21-11-22-33-9003"] = 25003
	thirdHome := f.add(t, openCodeSIDThird)
	third, err := f.run(t)
	if err != nil || third[openCodeSIDThird] != 25004 || f.record[openCodeSIDFirst] != 25001 || f.record["S-1-5-21-11-22-33-9003"] != 25003 {
		t.Fatalf("absent SID lost a reservation: ports=%v record=%v err=%v", third, f.record, err)
	}
	f.profiles = append(f.profiles, enterprisehooks.TargetCredentials{SID: openCodeSIDFirst, UserHome: firstHome})
	f.files[firstHome] = 49375
	returned, err := f.run(t)
	if err != nil || returned[openCodeSIDFirst] != 25001 || f.files[firstHome] != 25001 || f.files[secondHome] != 25002 || f.files[thirdHome] != 25004 {
		t.Fatalf("returning account or record authority: ports=%v files=%v err=%v", returned, f.files, err)
	}
	enterpriseHookWindowsGuardianOptions = func() (enterprisepolicy.Options, []string, bool, error) {
		return enterprisepolicy.Options{}, []string{"codex"}, true, nil
	}
	if off, err := f.run(t); err != nil || len(off) != 0 {
		t.Fatalf("OpenCode-off twin: %v %v", off, err)
	}
}

func TestManagedWindowsGuardianPlansFromEachAccountView(t *testing.T) {
	f := newManagedWindowsOpenCodePortFixture(t)
	firstHome, secondHome := f.add(t, openCodeSIDFirst), f.add(t, openCodeSIDSecond)
	f.files[firstHome] = 25002
	ports, err := f.run(t)
	if err != nil || ports[openCodeSIDFirst] != 25002 || ports[openCodeSIDSecond] != 25003 || f.files[secondHome] != 25003 || f.reads != 2 {
		t.Fatalf("account view did not reserve the import: ports=%v files=%v reads=%d err=%v", ports, f.files, f.reads, err)
	}
	stable, err := f.run(t)
	if err != nil || stable[openCodeSIDFirst] != 25002 || stable[openCodeSIDSecond] != 25003 || f.reads != 2 {
		t.Fatalf("stable pass reread account files: ports=%v reads=%d err=%v", stable, f.reads, err)
	}
}

func TestManagedWindowsGuardianContinuesAfterOneClaimFailure(t *testing.T) {
	f := newManagedWindowsOpenCodePortFixture(t)
	firstHome, secondHome, thirdHome := f.add(t, openCodeSIDFirst), f.add(t, openCodeSIDSecond), f.add(t, openCodeSIDThird)
	f.record[openCodeSIDFirst], f.files[firstHome], f.files[secondHome] = 25001, 25001, 25001
	f.claimFailure[openCodeSIDSecond] = true
	ports, err := f.run(t)
	if err == nil || ports[openCodeSIDFirst] != 25001 || ports[openCodeSIDSecond] != 0 || ports[openCodeSIDThird] != 25003 || f.record[openCodeSIDSecond] != 0 || f.files[thirdHome] != 25003 {
		t.Fatalf("claim failure changed another binding: ports=%v record=%v files=%v err=%v", ports, f.record, f.files, err)
	}
	delete(f.claimFailure, openCodeSIDSecond)
	ports, err = f.run(t)
	if err != nil || ports[openCodeSIDSecond] != 25002 || f.record[openCodeSIDSecond] != 25002 || f.files[secondHome] != 25002 {
		t.Fatalf("claim recovery: ports=%v record=%v err=%v", ports, f.record, err)
	}
}

func TestManagedWindowsGuardianUnknownAccountKeepsKnownAssignments(t *testing.T) {
	f := newManagedWindowsOpenCodePortFixture(t)
	firstHome, secondHome := f.add(t, openCodeSIDFirst), f.add(t, openCodeSIDSecond)
	f.readFailure[firstHome] = true
	ports, err := f.run(t)
	if err == nil || !strings.Contains(err.Error(), firstHome) || ports[openCodeSIDFirst] != 0 || ports[openCodeSIDSecond] != 25002 || f.record[openCodeSIDFirst] != 25001 || f.files[secondHome] != 25002 {
		t.Fatalf("unknown account changed another binding: ports=%v record=%v err=%v", ports, f.record, err)
	}
	delete(f.readFailure, firstHome)
	ports, err = f.run(t)
	if err != nil || ports[openCodeSIDFirst] != 25001 || ports[openCodeSIDSecond] != 25002 {
		t.Fatalf("healthy recovery: ports=%v err=%v", ports, err)
	}
	f.writeFailure[firstHome] = true
	ports, err = f.run(t)
	if err == nil || ports[openCodeSIDFirst] != 0 || ports[openCodeSIDSecond] != 25002 || f.record[openCodeSIDFirst] != 25001 || !strings.Contains(err.Error(), firstHome) {
		t.Fatalf("recorded file refusal moved another account: ports=%v record=%v err=%v", ports, f.record, err)
	}
}

func TestManagedWindowsGuardianUnreadableClaimsDeferThePass(t *testing.T) {
	f := newManagedWindowsOpenCodePortFixture(t)
	f.add(t, openCodeSIDFirst)
	enterpriseHookWindowsOpenCodeClaims = func() (map[int]string, error) { return nil, fmt.Errorf("claim directory unavailable") }
	ports, err := f.run(t)
	if err == nil || len(ports) != 0 || f.writes != 0 || len(f.record) != 0 {
		t.Fatalf("unreadable claims changed assignments: ports=%v record=%v writes=%d err=%v", ports, f.record, f.writes, err)
	}
}

func TestManagedWindowsGuardianMovesKnownConflictWithUnknownAccount(t *testing.T) {
	f := newManagedWindowsOpenCodePortFixture(t)
	firstHome, secondHome, thirdHome := f.add(t, openCodeSIDFirst), f.add(t, openCodeSIDSecond), f.add(t, openCodeSIDThird)
	f.record[openCodeSIDFirst], f.record[openCodeSIDSecond] = 25001, 25002
	f.files[firstHome], f.files[secondHome], f.files[thirdHome] = 25001, 25002, 25002
	f.readFailure[firstHome] = true // recorded account is written without a read
	ports, err := f.run(t)
	if err != nil || ports[openCodeSIDFirst] != 25001 || ports[openCodeSIDSecond] != 25002 || ports[openCodeSIDThird] != 25003 || f.files[thirdHome] != 25003 || f.record[openCodeSIDFirst] != 25001 {
		t.Fatalf("recorded port failed to decide an import: ports=%v files=%v record=%v err=%v", ports, f.files, f.record, err)
	}
}

func TestManagedWindowsGuardianMovesWritablePeerAfterLinkedAccountRecovers(t *testing.T) {
	f := newManagedWindowsOpenCodePortFixture(t)
	firstHome, secondHome := f.add(t, openCodeSIDFirst), f.add(t, openCodeSIDSecond)
	f.files[firstHome] = 25002
	f.readFailure[firstHome] = true
	first, err := f.run(t)
	if err == nil || first[openCodeSIDSecond] != 25002 || f.files[secondHome] != 25002 {
		t.Fatalf("first pass: ports=%v files=%v err=%v", first, f.files, err)
	}
	delete(f.readFailure, firstHome)
	f.writeFailure[firstHome] = true
	second, err := f.run(t)
	if err == nil || second[openCodeSIDFirst] != 0 || second[openCodeSIDSecond] != 25002 || f.record[openCodeSIDFirst] != 25001 || f.record[openCodeSIDSecond] != 25002 {
		t.Fatalf("linked file displaced a record: ports=%v record=%v err=%v", second, f.record, err)
	}
	delete(f.writeFailure, firstHome)
	third, err := f.run(t)
	if err != nil || third[openCodeSIDFirst] != 25001 || third[openCodeSIDSecond] != 25002 || f.files[firstHome] != 25001 {
		t.Fatalf("ordinary writable recovery: ports=%v files=%v err=%v", third, f.files, err)
	}
}

func TestManagedWindowsGuardianMovesPeerAfterAccountWriteRefusal(t *testing.T) {
	f := newManagedWindowsOpenCodePortFixture(t)
	firstHome, secondHome := f.add(t, openCodeSIDFirst), f.add(t, openCodeSIDSecond)
	f.record[openCodeSIDSecond] = 25002
	f.files[firstHome], f.files[secondHome] = 25002, 25002
	f.writeFailure[firstHome] = true
	for pass := 0; pass < 3; pass++ {
		ports, err := f.run(t)
		if err == nil || ports[openCodeSIDFirst] != 0 || ports[openCodeSIDSecond] != 25002 || f.record[openCodeSIDSecond] != 25002 || f.record[openCodeSIDFirst] != 25001 {
			t.Fatalf("pass %d moved the recorded peer after refusal: ports=%v record=%v err=%v", pass, ports, f.record, err)
		}
	}
	delete(f.writeFailure, firstHome)
	ports, err := f.run(t)
	if err != nil || ports[openCodeSIDFirst] != 25001 || ports[openCodeSIDSecond] != 25002 || f.files[firstHome] != 25001 {
		t.Fatalf("ordinary recovery: ports=%v files=%v err=%v", ports, f.files, err)
	}
}

func TestManagedWindowsGuardianAccountReadHasDeadline(t *testing.T) {
	f := newManagedWindowsOpenCodePortFixture(t)
	f.add(t, openCodeSIDFirst)
	release, finished := make(chan struct{}), make(chan struct{})
	enterpriseHookWindowsOpenCodeReadTimeout = 10 * time.Millisecond
	enterpriseHookWindowsOpenCodeRead = func(string) (int, error) { <-release; close(finished); return 0, nil }
	start := time.Now()
	ports, err := f.run(t)
	close(release)
	<-finished
	if err == nil || len(ports) != 0 || time.Since(start) > 5*time.Second || f.writes != 1 {
		t.Fatalf("account read did not stop at its deadline: ports=%v writes=%d err=%v", ports, f.writes, err)
	}
}

func TestManagedWindowsGuardianTimedOutReadDoesNotExhaustHealthyProfiles(t *testing.T) {
	f := newManagedWindowsOpenCodePortFixture(t)
	firstHome := f.add(t, openCodeSIDFirst)
	release, finished := make(chan struct{}), make(chan struct{})
	enterpriseHookWindowsOpenCodeReadTimeout = 10 * time.Millisecond
	enterpriseHookWindowsOpenCodeRunAs = func(_ enterprisehooks.TargetCredentials, fn func() error) error { return fn() }
	enterpriseHookWindowsOpenCodeRead = func(home string) (int, error) {
		if home == firstHome {
			<-release
			close(finished)
		}
		return 0, nil
	}
	enterpriseHookWindowsOpenCodeSet = func(_ string, port int) (enterprisepolicy.OpenCodeServicePortResult, error) {
		return enterprisepolicy.OpenCodeServicePortResult{Port: port}, nil
	}
	for pass := 0; pass < 5; pass++ {
		// Model a documented administrator rebuild before each pass. The
		// import window reopens, while the timed-out read remains pending.
		f.recordExists, f.record = false, map[string]int{}
		sid := fmt.Sprintf("S-1-5-21-700-800-900-%d", 1002+pass)
		f.add(t, sid)
		ports, err := f.run(t)
		if err == nil || ports[sid] == 0 || f.record[sid] == 0 || ports[openCodeSIDFirst] != 0 {
			t.Fatalf("pass %d lost a healthy account: ports=%v record=%v err=%v", pass, ports, f.record, err)
		}
	}
	close(release)
	<-finished
}

func TestManagedWindowsGuardianContestMarkSurvivesAnUnwrittenClaimant(t *testing.T) {
	f := newManagedWindowsOpenCodePortFixture(t)
	firstHome, secondHome := f.add(t, openCodeSIDFirst), f.add(t, openCodeSIDSecond)
	f.files[firstHome], f.files[secondHome] = 25002, 25002
	f.writeFailure[firstHome] = true
	ports, err := f.run(t)
	if err == nil || ports[openCodeSIDFirst] != 0 || f.record[openCodeSIDFirst] == 0 || ports[openCodeSIDSecond] == 25002 || len(f.contested) != 1 || f.contested[0].Port != 25002 {
		t.Fatalf("import pass: ports=%v marks=%v err=%v", ports, f.contested, err)
	}
	delete(f.writeFailure, firstHome)
	for pass := 0; pass < 3; pass++ {
		ports, err = f.run(t)
		if err != nil || ports[openCodeSIDFirst] == 25002 || ports[openCodeSIDSecond] == 25002 || f.record[openCodeSIDFirst] == 25002 || len(f.contested) != 1 || f.reads != 2 {
			t.Fatalf("pass %d: contested port reused: ports=%v record=%v marks=%v reads=%d err=%v", pass, ports, f.record, f.contested, f.reads, err)
		}
	}
}

func TestManagedWindowsGuardianResolvesOpenCodePortConflicts(t *testing.T) {
	f := newManagedWindowsOpenCodePortFixture(t)
	firstHome, secondHome := f.add(t, openCodeSIDFirst), f.add(t, openCodeSIDSecond)
	f.record[openCodeSIDFirst] = 25001
	f.files[firstHome], f.files[secondHome] = 25001, 25001
	ports, err := f.run(t)
	if err != nil || ports[openCodeSIDFirst] != 25001 || ports[openCodeSIDSecond] != 25002 || f.files[secondHome] != 25002 || f.record[openCodeSIDFirst] != 25001 {
		t.Fatalf("record/file conflict: ports=%v files=%v record=%v err=%v", ports, f.files, f.record, err)
	}
	f.files[firstHome] = 26000
	ports, err = f.run(t)
	if err != nil || ports[openCodeSIDFirst] != 25001 || f.files[firstHome] != 25001 || ports[openCodeSIDSecond] != 25002 {
		t.Fatalf("manual file edit changed binding: ports=%v files=%v err=%v", ports, f.files, err)
	}
	beforeWrites := f.writes
	enterpriseHookWindowsOpenCodePortsLoad = func(string) (enterprisehooks.WindowsOpenCodeServicePortsState, error) {
		return enterprisehooks.WindowsOpenCodeServicePortsState{}, fmt.Errorf("record unreadable")
	}
	if got, err := f.run(t); err == nil || len(got) != 0 || f.writes != beforeWrites {
		t.Fatalf("unreadable record made assignments: ports=%v writes=%d err=%v", got, f.writes, err)
	}
}

func TestManagedWindowsGuardianFinalServiceLinkDoesNotPublishClash(t *testing.T) {
	f := newManagedWindowsOpenCodePortFixture(t)
	firstHome, secondHome := f.add(t, openCodeSIDFirst), f.add(t, openCodeSIDSecond)
	f.files[firstHome] = 25002       // the account-side read follows the final link
	f.writeFailure[firstHome] = true // the protected writer refuses it
	ports, err := f.run(t)
	if err == nil || ports[openCodeSIDFirst] != 0 || ports[openCodeSIDSecond] == 25002 || f.record[openCodeSIDFirst] != 25002 || f.record[openCodeSIDSecond] == 25002 || f.files[secondHome] == 25002 {
		t.Fatalf("linked file port was published to another account: ports=%v files=%v record=%v err=%v", ports, f.files, f.record, err)
	}
	if len(f.contested) != 0 || f.record[openCodeSIDFirst] != 25002 {
		t.Fatalf("unwritten import binding was not kept: record=%v marks=%+v", f.record, f.contested)
	}
	newSID := "S-1-5-21-700-800-900-9002"
	f.add(t, newSID)
	ports, err = f.run(t)
	if err == nil || ports[newSID] == 25002 || f.record[newSID] == 25002 {
		t.Fatalf("later newcomer received the linked file's port: ports=%v record=%v err=%v", ports, f.record, err)
	}
	delete(f.writeFailure, firstHome)
	ports, err = f.run(t)
	if err != nil || ports[openCodeSIDFirst] != 25002 || f.files[firstHome] != 25002 {
		t.Fatalf("ordinary recovery lost the recorded port: ports=%v files=%v err=%v", ports, f.files, err)
	}
}

func TestManagedWindowsOpenCodePortReadSeesFinalServiceLink(t *testing.T) {
	home := t.TempDir()
	path := enterprisepolicy.OpenCodeServiceConfigPath(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(home, "linked-service.json")
	if err := os.WriteFile(target, []byte(`{"port":25002}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("service link unavailable: %v", err)
	}
	if port, err := enterprisepolicy.ReadOpenCodeServicePortAsUser(home); err != nil || port != 25002 {
		t.Fatalf("account read: %d %v", port, err)
	}
	if _, err := enterprisepolicy.SetOpenCodeServicePort(home, 25001); err == nil {
		t.Fatal("protected writer changed a final link")
	}
}
