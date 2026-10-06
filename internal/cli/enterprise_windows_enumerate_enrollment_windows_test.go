// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func standaloneWindowsEnrollmentConfig(enrollment config.EnterpriseEnrollmentConfig) *config.Config {
	return &config.Config{
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise: config.EnterpriseConfig{
			Profile:    managed.ProfileStandalone,
			Enrollment: enrollment,
		},
	}
}

// exempt_users must not become exclusions: an excluded SID is unregistered
// and every machine-policy hook fails closed for it.
func TestStandaloneWindowsEnumerateOptionsKeepsExemptUsersSeparate(t *testing.T) {
	cfg := standaloneWindowsEnrollmentConfig(config.EnterpriseEnrollmentConfig{
		IncludeUsers: []string{"alice"},
		ExcludeUsers: []string{"bob"},
		ExemptUsers:  []string{"breakglass"},
	})
	opts := standaloneWindowsEnumerateOptions(cfg, enterprisehooks.EnumerateOptions{})
	if strings.Join(opts.ExcludeUsers, ",") != "bob" {
		t.Fatalf("ExcludeUsers = %v, want only the excluded user", opts.ExcludeUsers)
	}
	if strings.Join(opts.ExemptUsers, ",") != "breakglass" || strings.Join(opts.IncludeUsers, ",") != "alice" {
		t.Fatalf("options = %+v, want include and exempt carried separately", opts)
	}

	secureClient := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	if got := standaloneWindowsEnumerateOptions(secureClient, enterprisehooks.EnumerateOptions{}); len(got.IncludeUsers)+len(got.ExcludeUsers)+len(got.ExemptUsers) != 0 {
		t.Fatalf("Secure Client options gained enrollment filters: %+v", got)
	}
}

func runStandaloneWindowsEnumerateCycleForTest(t *testing.T, cfg *config.Config) (string, int) {
	t.Helper()
	previousConfig := enterpriseWindowsEnumerateConfigLoader
	previousEnumerator := enterpriseWindowsEnumerateProfileEnumerator
	previousWriter := enterpriseWindowsEnumerateManifestWriter
	t.Cleanup(func() {
		enterpriseWindowsEnumerateConfigLoader = previousConfig
		enterpriseWindowsEnumerateProfileEnumerator = previousEnumerator
		enterpriseWindowsEnumerateManifestWriter = previousWriter
	})
	enterpriseWindowsEnumerateConfigLoader = func() (*config.Config, error) { return cfg, nil }
	calls := 0
	enterpriseWindowsEnumerateProfileEnumerator = func(context.Context, *config.Config, enterprisehooks.EnumerateOptions) (enterprisehooks.Manifest, error) {
		calls++
		return enterprisehooks.Manifest{Version: 1, Targets: []enterprisehooks.ManifestTarget{}}, nil
	}
	enterpriseWindowsEnumerateManifestWriter = func(string, enterprisehooks.Manifest) (bool, error) {
		calls++
		return false, nil
	}
	stderr := new(bytes.Buffer)
	manifest := filepath.Join(t.TempDir(), "targets.yaml")
	if err := runEnterpriseWindowsEnumerateSingleCycle(context.Background(), stderr, manifest); err != nil {
		t.Fatalf("cycle: %v", err)
	}
	return stderr.String(), calls
}

// enterprise.enrollment.mode manifest hands targets.yaml to the
// administrator on Windows too: the enumerator neither walks nor publishes.
func TestEnterpriseWindowsEnumerateIdlesInManifestMode(t *testing.T) {
	log, calls := runStandaloneWindowsEnumerateCycleForTest(t, standaloneWindowsEnrollmentConfig(
		config.EnterpriseEnrollmentConfig{Mode: config.EnterpriseEnrollmentManifest},
	))
	if calls != 0 {
		t.Fatalf("manifest mode walked or published targets (%d calls)", calls)
	}
	if !strings.Contains(log, "cycle idle: enterprise.enrollment.mode is manifest") {
		t.Fatalf("idle cycle must say why; log:\n%s", log)
	}

	_, calls = runStandaloneWindowsEnumerateCycleForTest(t, standaloneWindowsEnrollmentConfig(
		config.EnterpriseEnrollmentConfig{Mode: config.EnterpriseEnrollmentAuto},
	))
	if calls != 2 {
		t.Fatalf("auto mode must enumerate and publish (%d calls)", calls)
	}
}

// include_groups and exclude_groups reach the Windows enumerator (they were
// only warned about), with the membership cache it keeps between cycles, and
// every agent it reports as unprotected is published for status and verify.
func TestEnterpriseWindowsEnumerateAppliesGroupFiltersAndPublishesUnprotectedAgents(t *testing.T) {
	cfg := standaloneWindowsEnrollmentConfig(config.EnterpriseEnrollmentConfig{
		IncludeGroups: []string{"Developers"},
		ExcludeGroups: []string{"Administrators"},
	})
	previousConfig := enterpriseWindowsEnumerateConfigLoader
	previousEnumerator := enterpriseWindowsEnumerateProfileEnumerator
	previousWriter := enterpriseWindowsEnumerateManifestWriter
	previousCacheLoader := enterpriseWindowsEnumerateGroupCacheLoader
	previousCacheWriter := enterpriseWindowsEnumerateGroupCacheWriter
	previousRecordWriter := enterpriseWindowsEnumerateUnprotectedWriter
	t.Cleanup(func() {
		enterpriseWindowsEnumerateConfigLoader = previousConfig
		enterpriseWindowsEnumerateProfileEnumerator = previousEnumerator
		enterpriseWindowsEnumerateManifestWriter = previousWriter
		enterpriseWindowsEnumerateGroupCacheLoader = previousCacheLoader
		enterpriseWindowsEnumerateGroupCacheWriter = previousCacheWriter
		enterpriseWindowsEnumerateUnprotectedWriter = previousRecordWriter
	})
	enterpriseWindowsEnumerateConfigLoader = func() (*config.Config, error) { return cfg, nil }
	cached := enterprisehooks.NewWindowsEnrollmentGroupCache()
	cached.Names["developers"] = "S-1-5-32-545"
	manifest := filepath.Join(t.TempDir(), "targets.yaml")
	enterpriseWindowsEnumerateGroupCacheLoader = func(path string) (*enterprisehooks.WindowsEnrollmentGroupCache, error) {
		if path != enterprisehooks.WindowsEnrollmentGroupsCachePath(manifest) {
			t.Errorf("cache path = %s", path)
		}
		return cached, nil
	}
	var seen enterprisehooks.EnumerateOptions
	enterpriseWindowsEnumerateProfileEnumerator = func(_ context.Context, _ *config.Config, opts enterprisehooks.EnumerateOptions) (enterprisehooks.Manifest, error) {
		seen = opts
		if opts.ReportUnprotected != nil {
			opts.ReportUnprotected(enterprisehooks.UnprotectedAgent{User: "alice", SID: "S-1-5-21-1-2-3-1001", Connector: "cursor", Version: "4.1.0", Reason: "version 4.1.0 is not verified against a known hook contract"})
		}
		return enterprisehooks.Manifest{Version: 1, Targets: []enterprisehooks.ManifestTarget{}}, nil
	}
	enterpriseWindowsEnumerateManifestWriter = func(string, enterprisehooks.Manifest) (bool, error) { return false, nil }
	var savedCache *enterprisehooks.WindowsEnrollmentGroupCache
	enterpriseWindowsEnumerateGroupCacheWriter = func(_ string, cache *enterprisehooks.WindowsEnrollmentGroupCache) (bool, error) {
		savedCache = cache
		return true, nil
	}
	var published []enterprisehooks.UnprotectedAgent
	enterpriseWindowsEnumerateUnprotectedWriter = func(path string, agents []enterprisehooks.UnprotectedAgent) (bool, error) {
		if path != manifest {
			t.Errorf("record manifest path = %s", path)
		}
		published = agents
		return true, nil
	}
	stderr := new(bytes.Buffer)
	if err := runEnterpriseWindowsEnumerateSingleCycle(context.Background(), stderr, manifest); err != nil {
		t.Fatalf("cycle: %v", err)
	}
	if strings.Join(seen.IncludeGroups, ",") != "Developers" || strings.Join(seen.ExcludeGroups, ",") != "Administrators" {
		t.Fatalf("group filters not passed: %+v", seen)
	}
	if seen.GroupCache != cached || savedCache != cached {
		t.Fatal("the loaded membership cache must be handed to the enumerator and saved after the cycle")
	}
	if len(published) != 1 || published[0].Connector != "cursor" {
		t.Fatalf("published = %+v", published)
	}
	if log := stderr.String(); strings.Contains(log, "are not applied on Windows") || !strings.Contains(log, "cursor 4.1.0 for user alice") {
		t.Fatalf("log:\n%s", log)
	}

	// Secure Client keeps its enumeration exactly: no group filters, no
	// cache, no record.
	secureClient := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	secureClient.Enterprise.Enrollment = cfg.Enterprise.Enrollment
	enterpriseWindowsEnumerateConfigLoader = func() (*config.Config, error) { return secureClient, nil }
	published, savedCache, seen = nil, nil, enterprisehooks.EnumerateOptions{}
	if err := runEnterpriseWindowsEnumerateSingleCycle(context.Background(), new(bytes.Buffer), manifest); err != nil {
		t.Fatalf("Secure Client cycle: %v", err)
	}
	if len(seen.IncludeGroups)+len(seen.ExcludeGroups) != 0 || seen.GroupCache != nil || seen.ReportUnprotected != nil || savedCache != nil || published != nil {
		t.Fatalf("Secure Client enumeration changed: %+v", seen)
	}
}
