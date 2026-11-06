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
	if runAsCalls != 2 {
		t.Fatalf("first pass ran as %d accounts, want 2", runAsCalls)
	}
	if stable := run(); stable[first] != firstPass[first] || stable[second] != firstPass[second] || runAsCalls != 2 {
		t.Fatalf("unchanged ports required a user token: ports=%v calls=%d", stable, runAsCalls)
	}
	for sid, home := range homes {
		if port := enterprisepolicy.ReadOpenCodeServicePort(home); port != firstPass[sid] {
			t.Fatalf("service.json for %s = %d, want %d", sid, port, firstPass[sid])
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
	enterpriseHookWindowsOpenCodeRead = func(home string) int { return files[home] }
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
	if existing, err := enterpriseHookStandaloneOpenCodePorts(context.Background(), enterprisehooks.Manifest{}); err == nil || existing[second] != 25002 || writes != beforeWrites || claims != beforeClaims || replacements != 1 {
		t.Fatalf("unreadable record made an assignment: existing=%v writes=%d claims=%d replacements=%d err=%v", existing, writes, claims, replacements, err)
	}
}
