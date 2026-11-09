// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// GAP-0979: each enumeration cycle hands the machine-wide hook the SIDs it
// judged excluded, and an empty cycle hands it none, so an account taken off
// exclude_users is governed again; a failed publish is logged, not fatal.
func TestEnumerationCyclePublishesTheExcludedAccountMarkers(t *testing.T) {
	previous := enterpriseWindowsExcludedAccountMarkerPublisher
	t.Cleanup(func() { enterpriseWindowsExcludedAccountMarkerPublisher = previous })
	var got [][]string
	var failure error
	enterpriseWindowsInventoryReadRevoker = func(enterprisehooks.Manifest) error { return nil }
	enterpriseWindowsExcludedAccountMarkerPublisher = func(sids []string) error {
		got = append(got, sids)
		return failure
	}
	var stderr bytes.Buffer
	publishEnterpriseWindowsExcludedAccountMarkers(&stderr, []enterprisehooks.ManifestTarget{
		{SID: "S-1-5-21-1-2-3-1001"}, {SID: "S-1-5-21-1-2-3-1002"},
	})
	publishEnterpriseWindowsExcludedAccountMarkers(&stderr, nil)
	want := [][]string{{"S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002"}, {}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("published %v, want %v", got, want)
	}
	if stderr.Len() != 0 {
		t.Fatalf("a clean publish logged %q", stderr.String())
	}
	failure = errors.New("access is denied")
	publishEnterpriseWindowsExcludedAccountMarkers(&stderr, nil)
	if !strings.Contains(stderr.String(), "could not publish the excluded-account markers") {
		t.Fatalf("a failed publish was not logged: %q", stderr.String())
	}
}

// excludedMarkerCycleHarness runs whole enumeration cycles with a marker store
// in memory, and answers the hook decision of one account from that store, so
// a test sees what the machine-wide hook would see after each cycle.
type excludedMarkerCycleHarness struct {
	t     *testing.T
	cfg   *config.Config
	store map[string]bool
	// walk is what the profile walk of the next cycle does.
	walk func(opts enterprisehooks.EnumerateOptions) (enterprisehooks.Manifest, error)
	// writeErr is what the manifest write of the next cycle returns.
	writeErr error
}

func newExcludedMarkerCycleHarness(t *testing.T, cfg *config.Config) *excludedMarkerCycleHarness {
	t.Helper()
	h := &excludedMarkerCycleHarness{t: t, cfg: cfg, store: map[string]bool{}}
	previousConfig, previousEnumerator := enterpriseWindowsEnumerateConfigLoader, enterpriseWindowsEnumerateProfileEnumerator
	previousWriter, previousRecordWriter := enterpriseWindowsEnumerateManifestWriter, enterpriseWindowsEnumerateUnprotectedWriter
	previousPublisher, previousExcluded := enterpriseWindowsExcludedAccountMarkerPublisher, windowsCurrentAccountExcluded
	previousLoader, previousCacheWriter := enterpriseWindowsEnumerateGroupCacheLoader, enterpriseWindowsEnumerateGroupCacheWriter
	previousSpool, previousRevoker := enterpriseWindowsIdentitySpoolWriter, enterpriseWindowsInventoryReadRevoker
	t.Cleanup(func() {
		enterpriseWindowsEnumerateConfigLoader, enterpriseWindowsEnumerateProfileEnumerator = previousConfig, previousEnumerator
		enterpriseWindowsEnumerateManifestWriter, enterpriseWindowsEnumerateUnprotectedWriter = previousWriter, previousRecordWriter
		enterpriseWindowsExcludedAccountMarkerPublisher, windowsCurrentAccountExcluded = previousPublisher, previousExcluded
		enterpriseWindowsEnumerateGroupCacheLoader, enterpriseWindowsEnumerateGroupCacheWriter = previousLoader, previousCacheWriter
		enterpriseWindowsIdentitySpoolWriter, enterpriseWindowsInventoryReadRevoker = previousSpool, previousRevoker
	})
	enterpriseWindowsEnumerateConfigLoader = func() (*config.Config, error) { return h.cfg, nil }
	enterpriseWindowsEnumerateProfileEnumerator = func(_ context.Context, _ *config.Config, opts enterprisehooks.EnumerateOptions) (enterprisehooks.Manifest, error) {
		return h.walk(opts)
	}
	enterpriseWindowsEnumerateManifestWriter = func(string, enterprisehooks.Manifest) (bool, error) { return false, h.writeErr }
	enterpriseWindowsEnumerateUnprotectedWriter = func(string, []enterprisehooks.UnprotectedAgent) (bool, error) { return false, nil }
	enterpriseWindowsEnumerateGroupCacheLoader = func(string) (*enterprisehooks.WindowsEnrollmentGroupCache, error) {
		return enterprisehooks.NewWindowsEnrollmentGroupCache(), nil
	}
	enterpriseWindowsEnumerateGroupCacheWriter = func(string, *enterprisehooks.WindowsEnrollmentGroupCache) (bool, error) { return false, nil }
	enterpriseWindowsIdentitySpoolWriter = func(context.Context, string, *enterprisehooks.WindowsEnrollmentGroupCache, []string, map[string]map[string]string, func(string) error, func(string, ...any)) error {
		return nil
	}
	enterpriseWindowsInventoryReadRevoker = func(enterprisehooks.Manifest) error { return nil }
	enterpriseWindowsExcludedAccountMarkerPublisher = func(sids []string) error {
		h.store = map[string]bool{}
		for _, sid := range sids {
			h.store[sid] = true
		}
		return nil
	}
	return h
}

func (h *excludedMarkerCycleHarness) cycle() error {
	h.t.Helper()
	return runEnterpriseWindowsEnumerateSingleCycle(context.Background(), new(bytes.Buffer), filepath.Join(h.t.TempDir(), "targets.yaml"))
}

// hookPasses is the hook decision of the account that runs with sid, given
// the markers the cycles left.
func (h *excludedMarkerCycleHarness) hookPasses(sid string) bool {
	h.t.Helper()
	windowsCurrentAccountExcluded = func() (bool, error) { return h.store[sid], nil }
	previousCheck, previousClosure := standaloneEnterpriseHookCheck, windowsStandaloneHooksHeldClosed
	standaloneEnterpriseHookCheck = func(string) bool { return true }
	windowsStandaloneHooksHeldClosed = func() (bool, error) { return false, nil }
	h.t.Cleanup(func() {
		standaloneEnterpriseHookCheck, windowsStandaloneHooksHeldClosed = previousCheck, previousClosure
	})
	unregistered := fmt.Errorf("%w: the current SID is absent from the protected target set", enterprisehooks.ErrWindowsManagedSIDUnregistered)
	return windowsExcludedAccountNoop(`C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`, unregistered)
}

// Under enterprise.enrollment.mode manifest the cycle is the install scan, and
// an account in exclude_users that the administrator's targets omit is
// reported excluded by it, so its marker is published and the machine-wide
// hook passes its calls instead of refusing them as a pending enrollment
// (GAP-0979). When the account leaves exclude_users the next cycle ends the
// pass, and a cycle that cannot judge anyone ends every pass.
func TestManifestModeCyclePublishesTheExclusionMarkerAndAFailedCycleRevokesIt(t *testing.T) {
	const excludedSID = "S-1-5-21-1-2-3-1001"
	const otherSID = "S-1-5-21-1-2-3-1002"
	cfg := standaloneWindowsEnrollmentConfig(config.EnterpriseEnrollmentConfig{
		Mode:         config.EnterpriseEnrollmentManifest,
		ExcludeUsers: []string{"carol"},
	})
	h := newExcludedMarkerCycleHarness(t, cfg)
	excludes := true
	h.walk = func(opts enterprisehooks.EnumerateOptions) (enterprisehooks.Manifest, error) {
		if opts.ReportExcluded == nil {
			t.Fatal("the manifest-mode scan does not receive exclusions")
		}
		if excludes {
			opts.ReportExcluded(enterprisehooks.ManifestTarget{SID: excludedSID})
		}
		return enterprisehooks.Manifest{Version: 1}, nil
	}
	if err := h.cycle(); err != nil {
		t.Fatal(err)
	}
	if !h.hookPasses(excludedSID) {
		t.Fatal("the excluded account is still refused after a manifest-mode cycle")
	}
	if h.hookPasses(otherSID) {
		t.Fatal("an account with no marker passes")
	}

	// A cycle whose scan fails to run leaves no pass behind.
	h.walk = func(enterprisehooks.EnumerateOptions) (enterprisehooks.Manifest, error) {
		return enterprisehooks.Manifest{}, errors.New("ProfileList is unreadable")
	}
	if err := h.cycle(); err != nil {
		t.Fatal(err)
	}
	if h.hookPasses(excludedSID) {
		t.Fatal("a scan that judged nobody left the pass in place")
	}

	// The account leaves exclude_users: the next cycle ends the pass.
	excludes = true
	h.walk = func(opts enterprisehooks.EnumerateOptions) (enterprisehooks.Manifest, error) {
		if excludes {
			opts.ReportExcluded(enterprisehooks.ManifestTarget{SID: excludedSID})
		}
		return enterprisehooks.Manifest{Version: 1}, nil
	}
	if err := h.cycle(); err != nil || !h.hookPasses(excludedSID) {
		t.Fatalf("republish: err=%v", err)
	}
	excludes = false
	if err := h.cycle(); err != nil {
		t.Fatal(err)
	}
	if h.hookPasses(excludedSID) {
		t.Fatal("the account taken off exclude_users still passes")
	}
}

// In the automatic mode a cycle that fails after the configuration loaded (the
// profile walk, the manifest write) or before it (no configuration) revokes
// every pass, so a failed cycle never leaves an old marker authorizing an
// account that may no longer be excluded (GAP-0979).
func TestAutomaticModeFailedCycleRevokesTheExclusionMarkers(t *testing.T) {
	const excludedSID = "S-1-5-21-1-2-3-1001"
	cfg := standaloneWindowsEnrollmentConfig(config.EnterpriseEnrollmentConfig{
		Mode:         config.EnterpriseEnrollmentAuto,
		ExcludeUsers: []string{"carol"},
	})
	h := newExcludedMarkerCycleHarness(t, cfg)
	good := func(opts enterprisehooks.EnumerateOptions) (enterprisehooks.Manifest, error) {
		opts.ReportExcluded(enterprisehooks.ManifestTarget{SID: excludedSID})
		return enterprisehooks.Manifest{Version: 1, Targets: []enterprisehooks.ManifestTarget{}}, nil
	}
	h.walk = good
	if err := h.cycle(); err != nil || !h.hookPasses(excludedSID) {
		t.Fatalf("good cycle: err=%v", err)
	}
	for name, fail := range map[string]func(){
		"profile walk fails": func() {
			h.walk = func(enterprisehooks.EnumerateOptions) (enterprisehooks.Manifest, error) {
				return enterprisehooks.Manifest{}, errors.New("walk failed")
			}
		},
		"manifest write fails": func() { h.writeErr = errors.New("access is denied") },
		"configuration unreadable": func() {
			enterpriseWindowsEnumerateConfigLoader = func() (*config.Config, error) { return nil, errors.New("config.yaml: access is denied") }
		},
	} {
		h.walk, h.writeErr = good, nil
		enterpriseWindowsEnumerateConfigLoader = func() (*config.Config, error) { return h.cfg, nil }
		if err := h.cycle(); err != nil || !h.hookPasses(excludedSID) {
			t.Fatalf("%s: setup cycle: err=%v", name, err)
		}
		fail()
		if err := h.cycle(); err == nil {
			t.Fatalf("%s: the cycle did not fail", name)
		}
		if h.hookPasses(excludedSID) {
			t.Fatalf("%s: the failed cycle left the pass of an account it could not judge", name)
		}
	}
}
