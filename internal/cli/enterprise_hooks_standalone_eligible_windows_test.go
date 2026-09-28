// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The guardian's foreign-hook cleanup decides eligible profiles with the
// configured group filters and the enumerator's membership cache beside the
// manifest; without group filters the cache is never read.
func TestWindowsEligibleProfilesUseTheGroupFiltersAndTheEnumeratorCache(t *testing.T) {
	previousLoader, previousList := enterpriseHookWindowsGroupCacheLoader, enterpriseHookWindowsStandaloneEligibleList
	t.Cleanup(func() {
		enterpriseHookWindowsGroupCacheLoader, enterpriseHookWindowsStandaloneEligibleList = previousLoader, previousList
	})
	current := &config.Config{
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise:     config.EnterpriseConfig{Profile: managed.ProfileStandalone},
	}
	current.Enterprise.Enrollment.ExcludeUsers = []string{"build"}
	current.Enterprise.Enrollment.IncludeGroups = []string{"S-1-5-32-545"}
	current.Enterprise.Enrollment.ExcludeGroups = []string{`CONTOSO\Contractors`}
	const manifest = `C:\ProgramData\DefenseClaw\enterprise\targets.yaml`
	cache := enterprisehooks.NewWindowsEnrollmentGroupCache()
	cache.Users["S-1-5-21-1-2-3-1001"] = []string{"S-1-5-32-545"}
	var loadedFrom string
	var loadErr error
	enterpriseHookWindowsGroupCacheLoader = func(path string) (*enterprisehooks.WindowsEnrollmentGroupCache, error) {
		loadedFrom = path
		if loadErr != nil {
			return nil, loadErr
		}
		return cache, nil
	}
	var got enterprisehooks.EnumerateOptions
	enterpriseHookWindowsStandaloneEligibleList = func(_ context.Context, opts enterprisehooks.EnumerateOptions) ([]enterprisehooks.TargetCredentials, error) {
		got = opts
		return nil, nil
	}

	if _, err := enterpriseHookWindowsEligibleProfilesFor(context.Background(), current, manifest); err != nil {
		t.Fatal(err)
	}
	if loadedFrom != enterprisehooks.WindowsEnrollmentGroupsCachePath(manifest) {
		t.Fatalf("cache read from %q, want the enumerator's cache beside the manifest", loadedFrom)
	}
	if strings.Join(got.IncludeGroups, ",") != "S-1-5-32-545" || strings.Join(got.ExcludeGroups, ",") != `CONTOSO\Contractors` ||
		strings.Join(got.ExcludeUsers, ",") != "build" || got.GroupCache != cache {
		t.Fatalf("options = %+v, want the configured filters and the loaded cache", got)
	}

	// An unreadable cache decides from the signed-in sessions alone.
	loadErr = errors.New("the cache is not a protected record")
	if _, err := enterpriseHookWindowsEligibleProfilesFor(context.Background(), current, manifest); err != nil || got.GroupCache != nil {
		t.Fatalf("unreadable cache: options = %+v, %v", got, err)
	}

	loadedFrom, loadErr = "", nil
	current.Enterprise.Enrollment.IncludeGroups, current.Enterprise.Enrollment.ExcludeGroups = nil, nil
	if _, err := enterpriseHookWindowsEligibleProfilesFor(context.Background(), current, manifest); err != nil || loadedFrom != "" {
		t.Fatalf("without group filters the cache must not be read: %q %v", loadedFrom, err)
	}
}
