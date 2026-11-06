//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

func TestManagedWindowsGuardianKeepsOpenCodePortsBySIDAcrossEligibilityChanges(t *testing.T) {
	const first = "S-1-5-21-100-200-300-1001"
	const second = "S-1-5-21-400-500-600-1001"
	const newcomer = "S-1-5-21-700-800-900-9003"
	const absent = "S-1-5-21-11-22-33-9003"
	previousOptions, previousProfiles := enterpriseHookWindowsGuardianOptions, enterpriseHookWindowsEligibleProfiles
	previousLoad, previousWrite := enterpriseHookWindowsOpenCodePortsLoad, enterpriseHookWindowsOpenCodePortsWrite
	previousRead, previousEnsure, previousReplace := enterpriseHookWindowsOpenCodeRead, enterpriseHookWindowsOpenCodeEnsure, enterpriseHookWindowsOpenCodeReplace
	previousRunAs := enterpriseHookWindowsOpenCodeRunAs
	previousClaims, previousClaim := enterpriseHookWindowsOpenCodeClaims, enterpriseHookWindowsOpenCodeClaim
	previousManifest, previousConfig := enterpriseHookManifest, cfg
	t.Cleanup(func() {
		enterpriseHookWindowsGuardianOptions, enterpriseHookWindowsEligibleProfiles = previousOptions, previousProfiles
		enterpriseHookWindowsOpenCodePortsLoad, enterpriseHookWindowsOpenCodePortsWrite = previousLoad, previousWrite
		enterpriseHookWindowsOpenCodeRead, enterpriseHookWindowsOpenCodeEnsure, enterpriseHookWindowsOpenCodeReplace = previousRead, previousEnsure, previousReplace
		enterpriseHookWindowsOpenCodeRunAs = previousRunAs
		enterpriseHookWindowsOpenCodeClaims, enterpriseHookWindowsOpenCodeClaim = previousClaims, previousClaim
		enterpriseHookManifest, cfg = previousManifest, previousConfig
	})
	cfg = nil
	enterpriseHookManifest = filepath.Join(t.TempDir(), "targets.yaml")
	enterpriseHookWindowsGuardianOptions = func() (enterprisepolicy.Options, []string, bool, error) {
		return enterprisepolicy.Options{}, []string{"opencode"}, true, nil
	}
	homes := map[string]string{first: t.TempDir(), second: t.TempDir(), newcomer: t.TempDir()}
	profiles := []enterprisehooks.TargetCredentials{{SID: first, UserHome: homes[first]}, {SID: second, UserHome: homes[second]}}
	enterpriseHookWindowsEligibleProfiles = func(context.Context) ([]enterprisehooks.TargetCredentials, error) { return profiles, nil }
	record := map[string]int{}
	enterpriseHookWindowsOpenCodePortsLoad = func(string) (map[string]int, error) {
		copy := map[string]int{}
		for key, port := range record {
			copy[key] = port
		}
		return copy, nil
	}
	enterpriseHookWindowsOpenCodePortsWrite = func(_ string, ports map[string]int) error {
		record = map[string]int{}
		for key, port := range ports {
			record[key] = port
		}
		return nil
	}
	claims := map[int]string{}
	enterpriseHookWindowsOpenCodeClaims = func() (map[int]string, error) {
		copy := map[int]string{}
		for port, sid := range claims {
			copy[port] = sid
		}
		return copy, nil
	}
	enterpriseHookWindowsOpenCodeClaim = func(sid string, port int) error {
		if other := claims[port]; other != "" && other != sid {
			return fmt.Errorf("port claimed")
		}
		claims[port] = sid
		return nil
	}
	runAsCalls := 0
	enterpriseHookWindowsOpenCodeRunAs = func(_ enterprisehooks.TargetCredentials, fn func() error) error {
		runAsCalls++
		return fn()
	}
	run := func() map[string]int {
		t.Helper()
		ports, err := enterpriseHookStandaloneOpenCodePorts(context.Background(), enterprisehooks.Manifest{})
		if err != nil {
			t.Fatal(err)
		}
		return ports
	}
	firstPass := run()
	if firstPass[first] != 25001 || firstPass[second] != 25002 {
		t.Fatalf("two accounts with the same RID: %v", firstPass)
	}
	if runAsCalls != 4 {
		t.Fatalf("first pass ran as %d account reads and writes, want 4", runAsCalls)
	}
	if stable := run(); stable[first] != firstPass[first] || stable[second] != firstPass[second] || runAsCalls != 6 {
		t.Fatalf("stable pass did not read both accounts as user: ports=%v calls=%d", stable, runAsCalls)
	}
	for sid, home := range homes {
		if port, err := enterprisepolicy.ReadOpenCodeServicePortAsUser(home); err != nil || port != firstPass[sid] {
			t.Fatalf("service.json for %s = %d, want %d, err=%v", sid, port, firstPass[sid], err)
		}
	}
	// The account behind this recorded SID may be temporarily unavailable
	// to Windows. Its reservation remains unavailable to a new account.
	record[absent] = 25003
	profiles = []enterprisehooks.TargetCredentials{{SID: second, UserHome: homes[second]}, {SID: newcomer, UserHome: homes[newcomer]}}
	withoutFirst := run()
	if withoutFirst[first] != firstPass[first] || withoutFirst[second] != firstPass[second] ||
		withoutFirst[absent] != 25003 || withoutFirst[newcomer] != 25004 || record[first] != firstPass[first] {
		t.Fatalf("recorded account lost its port: %v", withoutFirst)
	}
	profiles = []enterprisehooks.TargetCredentials{{SID: first, UserHome: homes[first]}, {SID: second, UserHome: homes[second]}, {SID: newcomer, UserHome: homes[newcomer]}}
	returned := run()
	if returned[first] != firstPass[first] || returned[second] != firstPass[second] || returned[newcomer] != withoutFirst[newcomer] {
		t.Fatalf("returning account moved ports: %v -> %v", firstPass, returned)
	}
	service := enterprisepolicy.OpenCodeServiceConfigPath(homes[second])
	if err := os.WriteFile(service, []byte(`{"port":49375}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if chosen := run(); chosen[second] != 49375 || chosen[first] != firstPass[first] || chosen[newcomer] != withoutFirst[newcomer] {
		t.Fatalf("user-chosen port was not kept: %v", chosen)
	}
	enterpriseHookWindowsGuardianOptions = func() (enterprisepolicy.Options, []string, bool, error) {
		return enterprisepolicy.Options{}, []string{"codex"}, true, nil
	}
	if ports := run(); len(ports) != 0 {
		t.Fatalf("OpenCode off still assigns ports: %v", ports)
	}
}

type managedWindowsOpenCodePortFixture struct {
	profiles     []enterprisehooks.TargetCredentials
	homeSID      map[string]string
	record       map[string]int
	files        map[string]int
	claims       map[int]string
	claimFailure map[string]bool
	activeSID    string
	reads        int
	writes       int
}

func newManagedWindowsOpenCodePortFixture(t *testing.T) *managedWindowsOpenCodePortFixture {
	t.Helper()
	previousOptions, previousProfiles := enterpriseHookWindowsGuardianOptions, enterpriseHookWindowsEligibleProfiles
	previousLoad, previousWrite := enterpriseHookWindowsOpenCodePortsLoad, enterpriseHookWindowsOpenCodePortsWrite
	previousRead, previousEnsure, previousReplace := enterpriseHookWindowsOpenCodeRead, enterpriseHookWindowsOpenCodeEnsure, enterpriseHookWindowsOpenCodeReplace
	previousRunAs := enterpriseHookWindowsOpenCodeRunAs
	previousClaims, previousClaim := enterpriseHookWindowsOpenCodeClaims, enterpriseHookWindowsOpenCodeClaim
	previousManifest, previousConfig := enterpriseHookManifest, cfg
	previousTimeout := enterpriseHookWindowsOpenCodeReadTimeout
	t.Cleanup(func() {
		enterpriseHookWindowsGuardianOptions, enterpriseHookWindowsEligibleProfiles = previousOptions, previousProfiles
		enterpriseHookWindowsOpenCodePortsLoad, enterpriseHookWindowsOpenCodePortsWrite = previousLoad, previousWrite
		enterpriseHookWindowsOpenCodeRead, enterpriseHookWindowsOpenCodeEnsure, enterpriseHookWindowsOpenCodeReplace = previousRead, previousEnsure, previousReplace
		enterpriseHookWindowsOpenCodeRunAs = previousRunAs
		enterpriseHookWindowsOpenCodeClaims, enterpriseHookWindowsOpenCodeClaim = previousClaims, previousClaim
		enterpriseHookManifest, cfg = previousManifest, previousConfig
		enterpriseHookWindowsOpenCodeReadTimeout = previousTimeout
	})
	f := &managedWindowsOpenCodePortFixture{
		homeSID: map[string]string{}, record: map[string]int{}, files: map[string]int{},
		claims: map[int]string{}, claimFailure: map[string]bool{},
	}
	cfg = nil
	enterpriseHookManifest = filepath.Join(t.TempDir(), "targets.yaml")
	enterpriseHookWindowsGuardianOptions = func() (enterprisepolicy.Options, []string, bool, error) {
		return enterprisepolicy.Options{}, []string{"opencode"}, true, nil
	}
	enterpriseHookWindowsEligibleProfiles = func(context.Context) ([]enterprisehooks.TargetCredentials, error) { return f.profiles, nil }
	enterpriseHookWindowsOpenCodePortsLoad = func(string) (map[string]int, error) {
		copy := map[string]int{}
		for key, port := range f.record {
			copy[key] = port
		}
		return copy, nil
	}
	enterpriseHookWindowsOpenCodePortsWrite = func(_ string, ports map[string]int) error {
		f.record = map[string]int{}
		for key, port := range ports {
			f.record[key] = port
		}
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
			return 0, fmt.Errorf("account read outside its token")
		}
		f.reads++
		return f.files[home], nil
	}
	enterpriseHookWindowsOpenCodeEnsure = func(home string, port int) (enterprisepolicy.OpenCodeServicePortResult, error) {
		if f.activeSID != f.homeSID[home] {
			return enterprisepolicy.OpenCodeServicePortResult{}, fmt.Errorf("account write outside its token")
		}
		if existing := f.files[home]; existing > 0 {
			return enterprisepolicy.OpenCodeServicePortResult{Port: existing}, nil
		}
		f.files[home] = port
		return enterprisepolicy.OpenCodeServicePortResult{Port: port, Changed: true}, nil
	}
	enterpriseHookWindowsOpenCodeReplace = func(home string, port, stale int) (enterprisepolicy.OpenCodeServicePortResult, error) {
		if f.activeSID != f.homeSID[home] || f.files[home] != stale {
			return enterprisepolicy.OpenCodeServicePortResult{}, fmt.Errorf("account replacement did not match its token and file")
		}
		f.files[home] = port
		return enterprisepolicy.OpenCodeServicePortResult{Port: port, Changed: true}, nil
	}
	enterpriseHookWindowsOpenCodeClaims = func() (map[int]string, error) {
		copy := map[int]string{}
		for port, sid := range f.claims {
			copy[port] = sid
		}
		return copy, nil
	}
	enterpriseHookWindowsOpenCodeClaim = func(sid string, port int) error {
		if f.claimFailure[sid] {
			return fmt.Errorf("claim unavailable")
		}
		if owner := f.claims[port]; owner != "" && owner != sid {
			return fmt.Errorf("claimed by another account")
		}
		f.claims[port] = sid
		return nil
	}
	return f
}

func (f *managedWindowsOpenCodePortFixture) add(t *testing.T, sid string) string {
	t.Helper()
	home := t.TempDir()
	f.profiles = append(f.profiles, enterprisehooks.TargetCredentials{SID: sid, UserHome: home})
	f.homeSID[home] = sid
	return home
}

func TestManagedWindowsGuardianPlansFromEachAccountView(t *testing.T) {
	const first, second = "S-1-5-21-100-200-300-1001", "S-1-5-21-400-500-600-1002"
	f := newManagedWindowsOpenCodePortFixture(t)
	firstHome, secondHome := f.add(t, first), f.add(t, second)
	f.files[firstHome] = 25002
	ports, err := enterpriseHookStandaloneOpenCodePorts(context.Background(), enterprisehooks.Manifest{})
	if err != nil || ports[first] != 25002 || ports[second] != 25003 || f.files[secondHome] != 25003 || f.reads != 2 {
		t.Fatalf("account view did not reserve its existing port: ports=%v files=%v reads=%d err=%v", ports, f.files, f.reads, err)
	}
	stable, err := enterpriseHookStandaloneOpenCodePorts(context.Background(), enterprisehooks.Manifest{})
	if err != nil || stable[first] != 25002 || stable[second] != 25003 || f.reads != 4 {
		t.Fatalf("ordinary second pass was not stable: ports=%v reads=%d err=%v", stable, f.reads, err)
	}
}

func TestManagedWindowsGuardianContinuesAfterOneClaimFailure(t *testing.T) {
	const first, second, third = "S-1-5-21-100-200-300-1001", "S-1-5-21-400-500-600-1001", "S-1-5-21-700-800-900-1003"
	f := newManagedWindowsOpenCodePortFixture(t)
	firstHome, secondHome, thirdHome := f.add(t, first), f.add(t, second), f.add(t, third)
	f.record[first], f.files[firstHome], f.files[secondHome], f.claims[25001] = 25001, 25001, 25001, second
	f.claimFailure[first] = true
	ports, err := enterpriseHookStandaloneOpenCodePorts(context.Background(), enterprisehooks.Manifest{})
	if err == nil || ports[first] != 0 || ports[second] != 0 || ports[third] != 25003 ||
		f.files[thirdHome] != 25003 || f.record[third] != 25003 || f.record[second] != 0 {
		t.Fatalf("one failed claim stopped unrelated account: ports=%v record=%v files=%v err=%v", ports, f.record, f.files, err)
	}
	delete(f.claimFailure, first)
	ports, err = enterpriseHookStandaloneOpenCodePorts(context.Background(), enterprisehooks.Manifest{})
	if err != nil || ports[first] != 25002 || ports[second] != 25001 || ports[third] != 25003 ||
		f.files[firstHome] != 25002 || f.record[second] != 25001 {
		t.Fatalf("re-enrollment did not reconcile claim and record: ports=%v record=%v err=%v", ports, f.record, err)
	}
}

func TestManagedWindowsGuardianUnknownAccountDefersThePass(t *testing.T) {
	const first, second = "S-1-5-21-100-200-300-1001", "S-1-5-21-400-500-600-1002"
	f := newManagedWindowsOpenCodePortFixture(t)
	firstHome, secondHome := f.add(t, first), f.add(t, second)
	f.record[first] = 25001
	previousRead := enterpriseHookWindowsOpenCodeRead
	enterpriseHookWindowsOpenCodeRead = func(home string) (int, error) {
		if home == firstHome {
			return 0, fmt.Errorf("account file unavailable")
		}
		return previousRead(home)
	}
	ports, err := enterpriseHookStandaloneOpenCodePorts(context.Background(), enterprisehooks.Manifest{})
	if err == nil || ports[first] != 0 || ports[second] != 0 || f.record[first] != 25001 || f.files[secondHome] != 0 || f.writes != 0 || len(f.claims) != 0 || f.reads != 0 {
		t.Fatalf("unknown account view changed assignments: ports=%v files=%v claims=%v writes=%d reads=%d err=%v", ports, f.files, f.claims, f.writes, f.reads, err)
	}
	// A healthy second pass can assign the waiting account.
	enterpriseHookWindowsOpenCodeRead = previousRead
	ports, err = enterpriseHookStandaloneOpenCodePorts(context.Background(), enterprisehooks.Manifest{})
	if err != nil || ports[first] != 25001 || ports[second] != 25002 {
		t.Fatalf("healthy account read did not resume assignments: ports=%v err=%v", ports, err)
	}
}

func TestManagedWindowsGuardianUnreadableClaimsDeferThePass(t *testing.T) {
	const first = "S-1-5-21-100-200-300-1001"
	f := newManagedWindowsOpenCodePortFixture(t)
	f.add(t, first)
	enterpriseHookWindowsOpenCodeClaims = func() (map[int]string, error) {
		return nil, fmt.Errorf("claim directory unavailable")
	}
	ports, err := enterpriseHookStandaloneOpenCodePorts(context.Background(), enterprisehooks.Manifest{})
	if err == nil || len(ports) != 0 || f.writes != 0 || len(f.record) != 0 {
		t.Fatalf("unreadable claims changed assignments: ports=%v record=%v writes=%d err=%v", ports, f.record, f.writes, err)
	}
}

func TestManagedWindowsGuardianAccountReadHasDeadline(t *testing.T) {
	const first = "S-1-5-21-100-200-300-1001"
	f := newManagedWindowsOpenCodePortFixture(t)
	f.add(t, first)
	release := make(chan struct{})
	defer close(release)
	enterpriseHookWindowsOpenCodeReadTimeout = 10 * time.Millisecond
	enterpriseHookWindowsOpenCodeRead = func(string) (int, error) { <-release; return 0, nil }
	start := time.Now()
	ports, err := enterpriseHookStandaloneOpenCodePorts(context.Background(), enterprisehooks.Manifest{})
	if err == nil || len(ports) != 0 || time.Since(start) > 5*time.Second || f.writes != 0 {
		t.Fatalf("account read did not stop at its deadline: ports=%v writes=%d err=%v", ports, f.writes, err)
	}
}

func TestManagedWindowsGuardianResolvesOpenCodePortConflicts(t *testing.T) {
	const (
		first  = "S-1-5-21-100-200-300-1001"
		second = "S-1-5-21-400-500-600-1002"
	)
	previousOptions, previousProfiles := enterpriseHookWindowsGuardianOptions, enterpriseHookWindowsEligibleProfiles
	previousLoad, previousWrite := enterpriseHookWindowsOpenCodePortsLoad, enterpriseHookWindowsOpenCodePortsWrite
	previousRead, previousEnsure, previousReplace := enterpriseHookWindowsOpenCodeRead, enterpriseHookWindowsOpenCodeEnsure, enterpriseHookWindowsOpenCodeReplace
	previousRunAs := enterpriseHookWindowsOpenCodeRunAs
	previousClaims, previousClaim := enterpriseHookWindowsOpenCodeClaims, enterpriseHookWindowsOpenCodeClaim
	previousManifest, previousConfig := enterpriseHookManifest, cfg
	t.Cleanup(func() {
		enterpriseHookWindowsGuardianOptions, enterpriseHookWindowsEligibleProfiles = previousOptions, previousProfiles
		enterpriseHookWindowsOpenCodePortsLoad, enterpriseHookWindowsOpenCodePortsWrite = previousLoad, previousWrite
		enterpriseHookWindowsOpenCodeRead, enterpriseHookWindowsOpenCodeEnsure, enterpriseHookWindowsOpenCodeReplace = previousRead, previousEnsure, previousReplace
		enterpriseHookWindowsOpenCodeRunAs = previousRunAs
		enterpriseHookWindowsOpenCodeClaims, enterpriseHookWindowsOpenCodeClaim = previousClaims, previousClaim
		enterpriseHookManifest, cfg = previousManifest, previousConfig
	})
	cfg = nil
	enterpriseHookManifest = filepath.Join(t.TempDir(), "targets.yaml")
	enterpriseHookWindowsGuardianOptions = func() (enterprisepolicy.Options, []string, bool, error) {
		return enterprisepolicy.Options{}, []string{"opencode"}, true, nil
	}
	profiles := []enterprisehooks.TargetCredentials{{SID: first, UserHome: `C:\Users\first`}, {SID: second, UserHome: `C:\Users\second`}}
	enterpriseHookWindowsEligibleProfiles = func(context.Context) ([]enterprisehooks.TargetCredentials, error) { return profiles, nil }
	record := map[string]int{first: 25001}
	var readErr error
	writes := 0
	enterpriseHookWindowsOpenCodePortsLoad = func(string) (map[string]int, error) {
		if readErr != nil {
			return nil, readErr
		}
		copy := map[string]int{}
		for key, port := range record {
			copy[key] = port
		}
		return copy, nil
	}
	enterpriseHookWindowsOpenCodePortsWrite = func(_ string, ports map[string]int) error {
		writes++
		record = ports
		return nil
	}
	files := map[string]int{`C:\Users\second`: 25001}
	enterpriseHookWindowsOpenCodeRead = func(home string) (int, error) { return files[home], nil }
	enterpriseHookWindowsOpenCodeEnsure = func(home string, port int) (enterprisepolicy.OpenCodeServicePortResult, error) {
		files[home] = port
		return enterprisepolicy.OpenCodeServicePortResult{Port: port, Changed: true}, nil
	}
	replacements := 0
	enterpriseHookWindowsOpenCodeReplace = func(home string, port, stale int) (enterprisepolicy.OpenCodeServicePortResult, error) {
		if files[home] != stale {
			t.Fatalf("replacement expected port %d, got %d", stale, files[home])
		}
		replacements++
		files[home] = port
		return enterprisepolicy.OpenCodeServicePortResult{Port: port, Changed: true}, nil
	}
	enterpriseHookWindowsOpenCodeRunAs = func(_ enterprisehooks.TargetCredentials, fn func() error) error { return fn() }
	claims := 0
	enterpriseHookWindowsOpenCodeClaims = func() (map[int]string, error) { return nil, nil }
	enterpriseHookWindowsOpenCodeClaim = func(string, int) error { claims++; return nil }
	ports, err := enterpriseHookStandaloneOpenCodePorts(context.Background(), enterprisehooks.Manifest{})
	if err != nil || ports[first] != 25001 || ports[second] != 25002 || files[`C:\Users\second`] != 25002 || replacements != 1 {
		t.Fatalf("record/file conflict was not resolved: ports=%v files=%v replacements=%d err=%v", ports, files, replacements, err)
	}
	ports, err = enterpriseHookStandaloneOpenCodePorts(context.Background(), enterprisehooks.Manifest{})
	if err != nil || ports[first] != 25001 || ports[second] != 25002 || replacements != 1 {
		t.Fatalf("second pass was not stable: ports=%v replacements=%d err=%v", ports, replacements, err)
	}
	readErr = fmt.Errorf("record unreadable")
	beforeWrites, beforeClaims := writes, claims
	if existing, err := enterpriseHookStandaloneOpenCodePorts(context.Background(), enterprisehooks.Manifest{}); err == nil || len(existing) != 0 || writes != beforeWrites || claims != beforeClaims || replacements != 1 {
		t.Fatalf("unreadable record made an assignment: existing=%v writes=%d claims=%d replacements=%d err=%v", existing, writes, claims, replacements, err)
	}
}
