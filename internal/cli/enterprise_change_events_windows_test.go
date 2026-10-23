// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// stubWindowsChangeSpool records change events into a plain folder of the
// test, as an elevated caller, and returns the spool.
func stubWindowsChangeSpool(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), enterprisestatus.ChangeEventsDirName)
	state := t.TempDir()
	savedSpool, savedElevated := windowsChangeSpool, windowsSecretIsElevated
	windowsChangeSpool = func(managed.StandaloneLayout) (enterprisestatus.ChangeSpool, error) {
		return enterprisestatus.ChangeSpool{Dir: dir, StateDir: state}, nil
	}
	windowsSecretIsElevated = func() bool { return true }
	t.Cleanup(func() { windowsChangeSpool, windowsSecretIsElevated = savedSpool, savedElevated })
	return dir
}

func windowsChangeEvents(t *testing.T, spool string) []enterprisestatus.ChangeEvent {
	t.Helper()
	var out []enterprisestatus.ChangeEvent
	for _, id := range enterprisestatus.ListChangeEventIDs(spool) {
		ev, err := enterprisestatus.ReadChangeEvent(filepath.Join(spool, id+".json"))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, ev)
	}
	return out
}

func assertNoWindowsChangeReservations(t *testing.T, spool string) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(spool, enterprisestatus.ChangeReservedDirName))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("change reservations left: %v", entries)
	}
}

func assertOneRefusedAnchorInstall(t *testing.T, spool, code string) {
	t.Helper()
	events := windowsChangeEvents(t, spool)
	if len(events) != 1 {
		t.Fatalf("change events = %+v, want one refused anchor install", events)
	}
	ev := events[0]
	if ev.Kind != enterprisestatus.ChangeKindTrustAnchors || ev.Outcome != enterprisestatus.ChangeRefused ||
		ev.SHA256 != "" || (code != "" && ev.ReasonCode != code) || ev.ReasonCode == "" {
		t.Fatalf("change event = %+v, want a refused anchor install (%q) with no installed file", ev, code)
	}
}

func TestWindowsAnchorPreflightRefusalRecordsOneChangeEvent(t *testing.T) {
	stubWindowsBundleHost(t)
	spool := stubWindowsChangeSpool(t)
	cmd, out := windowsBundleCommand()
	opts := &windowsEnterpriseLifecycleOptions{trustAnchors: "anchors.json", configPath: "config.yaml",
		profile: managed.ProfileStandalone, jsonOutput: true, installedBeforeRun: true}
	done, err := prepareWindowsEnterpriseBundle(t.Context(), cmd, "ensure", opts)
	if !done || commandExitCode(err) != enterprisestatus.WindowsExitInvalidArgs {
		t.Fatalf("incompatible arguments: done=%v, err=%v, output=%s", done, err, out)
	}
	assertOneRefusedAnchorInstall(t, spool, "bundle_required")
	assertNoWindowsChangeReservations(t, spool)
	// Fresh and unelevated callers cannot create an installed-host audit.
	opts.installedBeforeRun = false
	_, _ = prepareWindowsEnterpriseBundle(t.Context(), cmd, "ensure", opts)
	opts.installedBeforeRun = true
	windowsSecretIsElevated = func() bool { return false }
	_, _ = prepareWindowsEnterpriseBundle(t.Context(), cmd, "ensure", opts)
	assertOneRefusedAnchorInstall(t, spool, "bundle_required")
}

// An ensure with TRUSTANCHORS= whose BUNDLE= is rejected after the anchors
// were staged installs no anchors and records one refused anchor install
// with the bundle's refusal code. Before, the run staged the anchors and
// returned through the bundle refusal with no change event.
func TestWindowsStagedAnchorsOfARejectedBundleRecordOneRefusal(t *testing.T) {
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	layout := stubWindowsBundleHost(t)
	spool := stubWindowsChangeSpool(t)
	rejected := filepath.Join(e.dir, "rejected.dcbundle")
	writeBundleTestFile(t, rejected, []byte("not a policy bundle"))
	cmd, out := windowsBundleCommand()
	opts := &windowsEnterpriseLifecycleOptions{bundlePath: rejected, trustAnchors: e.anchors, profile: managed.ProfileStandalone,
		jsonOutput: true, installedBeforeRun: true}
	done, err := prepareWindowsEnterpriseBundle(context.Background(), cmd, "ensure", opts)
	cleanupPreparedWindowsBundle(t, opts)
	if !done || err == nil {
		t.Fatalf("a rejected bundle was accepted: done=%v err=%v\n%s", done, err, out)
	}
	assertWindowsBundleInstalledAnchors(t, layout, nil, "after the rejected bundle")
	assertOneRefusedAnchorInstall(t, spool, "")
	assertNoWindowsChangeReservations(t, spool)
}

// A run that returns after prepare without finish installed none of the
// anchors it staged: release records one refused install (interrupted),
// once.
func TestWindowsStagedAnchorsOfARunThatEndsBeforeFinishRecordOneRefusal(t *testing.T) {
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	signed := filepath.Join(e.dir, "v5.dcbundle")
	if out, code := runBundle(t, e.signArgs("--out", signed, "--key", filepath.Join(e.dir, "key.pem"), "--key-id", "k1")...); code != 0 {
		t.Fatalf("sign exit %d: %s", code, out)
	}
	layout := stubWindowsBundleHost(t)
	spool := stubWindowsChangeSpool(t)
	cmd, out := windowsBundleCommand()
	opts := &windowsEnterpriseLifecycleOptions{bundlePath: signed, trustAnchors: e.anchors, profile: managed.ProfileStandalone,
		jsonOutput: true, installedBeforeRun: true}
	if done, err := prepareWindowsEnterpriseBundle(context.Background(), cmd, "ensure", opts); done || err != nil {
		t.Fatalf("prepare ended: %v\n%s", err, out)
	}
	cleanupPreparedWindowsBundle(t, opts)
	if events := windowsChangeEvents(t, spool); len(events) != 0 {
		t.Fatalf("recorded %+v before the run ended", events)
	}
	run := opts.bundle
	run.release()
	run.release()
	assertWindowsBundleInstalledAnchors(t, layout, nil, "after the run ended")
	assertOneRefusedAnchorInstall(t, spool, "interrupted")
	assertNoWindowsChangeReservations(t, spool)
}

// A TRUSTANCHORS= run refused because bundle.lock is busy records one
// refused anchor install, as Linux and macOS do.
func TestWindowsAnchorsLockRefusalRecordsOneChangeEvent(t *testing.T) {
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	layout := stubWindowsBundleHost(t)
	spool := stubWindowsChangeSpool(t)
	unlock, err := lockWindowsBundleStore(layout.LifecycleDir)
	if err != nil {
		t.Fatalf("hold bundle.lock: %v", err)
	}
	t.Cleanup(unlock)
	cmd, out := windowsBundleCommand()
	opts := &windowsEnterpriseLifecycleOptions{trustAnchors: e.anchors, profile: managed.ProfileStandalone,
		jsonOutput: true, installedBeforeRun: true}
	done, err := prepareWindowsEnterpriseBundle(context.Background(), cmd, "ensure", opts)
	cleanupPreparedWindowsBundle(t, opts)
	if !done || commandExitCode(err) != enterprisestatus.WindowsExitBusy {
		t.Fatalf("held lock: done=%v exit=%d out=%s", done, commandExitCode(err), out)
	}
	ids := enterprisestatus.ListChangeEventIDs(spool)
	if len(ids) != 1 {
		t.Fatalf("change events = %v, want one refused anchor install", ids)
	}
	ev, err := enterprisestatus.ReadChangeEvent(filepath.Join(spool, ids[0]+".json"))
	if err != nil || ev.Kind != enterprisestatus.ChangeKindTrustAnchors || ev.Outcome != enterprisestatus.ChangeRefused ||
		ev.ReasonCode != "lifecycle_busy" {
		t.Fatalf("change event = %+v, %v", ev, err)
	}
}

// The real Windows creator must stamp both directories, including the
// protected flag, on a never-bundled install and on an inherited parent.
func TestWindowsChangeSpoolProtectsTheBundleParent(t *testing.T) {
	if !windowsEnterpriseIsElevated() {
		t.Skip("setting the Administrators owner requires elevation")
	}
	service, err := managed.WindowsServiceAccountSID(`NT SERVICE\` + managed.StandaloneWindowsGatewaySvc)
	if err != nil {
		t.Fatal(err)
	}
	for _, inherited := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing", true: "inherited"}[inherited], func(t *testing.T) {
			layout := managed.StandaloneLayout{ConfigDir: filepath.Join(windowsBundleScratchDir(t), "etc")}
			bundles := filepath.Join(layout.ConfigDir, "bundles")
			if inherited {
				if err := os.MkdirAll(bundles, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			spool, err := windowsChangeSpool(layout)
			if err != nil {
				t.Fatal(err)
			}
			if err := spool.Prepare(spool.Dir); err != nil {
				t.Fatal(err)
			}
			for path, descriptor := range map[string]string{
				bundles:   windowsBundleDirectorySDDL(service.String()),
				spool.Dir: windowsBundleVersionSDDL(service.String(), true),
			} {
				actual, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
					windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
				if err != nil {
					t.Fatal(err)
				}
				expected, err := windows.SecurityDescriptorFromString(descriptor)
				if err != nil {
					t.Fatal(err)
				}
				equal, err := windowsEnterpriseExactDescriptorMatch(actual, expected)
				if err != nil || !equal {
					t.Fatalf("%s ACL=%s, want %s: %v", path, actual.String(), descriptor, err)
				}
			}
		})
	}
}

// A TRUSTANCHORS= run refused over its arguments on an installed computer
// records one refused anchor install with the refusal code; nothing is
// installed. Before, these refusals returned before any change event was
// recorded. A computer that is not installed records nothing.
func TestWindowsAnchorsArgumentRefusalsRecordOneChangeEvent(t *testing.T) {
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	for _, tc := range []struct {
		name, action, code string
		edit               func(*windowsEnterpriseLifecycleOptions)
	}{
		{"with CONFIG=", "ensure", string(enterprisebundle.CodeBundleRequired),
			func(o *windowsEnterpriseLifecycleOptions) { o.configPath = filepath.Join(e.dir, "config.yaml") }},
		{"with --refuse-capability-loss and no BUNDLE=", "ensure", "invalid_arguments",
			func(o *windowsEnterpriseLifecycleOptions) { o.refuseCapabilityLoss = true }},
		{"with repair", "repair", "invalid_arguments", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			layout := stubWindowsBundleHost(t)
			spool := stubWindowsChangeSpool(t)
			cmd, out := windowsBundleCommand()
			opts := &windowsEnterpriseLifecycleOptions{trustAnchors: e.anchors, profile: managed.ProfileStandalone,
				jsonOutput: true, installedBeforeRun: true}
			if tc.edit != nil {
				tc.edit(opts)
			}
			done, err := prepareWindowsEnterpriseBundle(context.Background(), cmd, tc.action, opts)
			cleanupPreparedWindowsBundle(t, opts)
			if !done || err == nil || !strings.Contains(out.String(), tc.code) {
				t.Fatalf("refusal: done=%v err=%v\n%s", done, err, out)
			}
			assertWindowsBundleInstalledAnchors(t, layout, nil, "after the refusal")
			assertOneRefusedAnchorInstall(t, spool, tc.code)
			assertNoWindowsChangeReservations(t, spool)
		})
	}
	t.Run("not installed", func(t *testing.T) {
		stubWindowsBundleHost(t)
		spool := stubWindowsChangeSpool(t)
		cmd, out := windowsBundleCommand()
		opts := &windowsEnterpriseLifecycleOptions{trustAnchors: e.anchors, configPath: filepath.Join(e.dir, "config.yaml"),
			profile: managed.ProfileStandalone, jsonOutput: true}
		if done, err := prepareWindowsEnterpriseBundle(context.Background(), cmd, "ensure", opts); !done || err == nil {
			t.Fatalf("refusal: done=%v err=%v\n%s", done, err, out)
		}
		if events := windowsChangeEvents(t, spool); len(events) != 0 {
			t.Fatalf("a computer that is not installed recorded %+v", events)
		}
	})
}

// An anchor-only ensure whose new anchor file fails its check once it
// replaced the installed one (anchor_insecure here) puts the previous file
// back (none when there was none) and records one failed anchor install
// with the file left installed. Before, the run left the new file in place
// and recorded the change as refused, which says nothing was changed.
func TestWindowsAnchorsThatFailTheirCheckAfterTheReplaceRecordAFailedChange(t *testing.T) {
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	for _, tc := range []struct {
		name   string
		before bool
	}{{"replacing installed anchors", true}, {"with no anchors before", false}} {
		t.Run(tc.name, func(t *testing.T) {
			layout := stubWindowsBundleHost(t)
			installedPath := newWindowsBundleDriver(layout).AnchorsPath
			var previous []byte
			if tc.before {
				if _, _, err := installWindowsBundleAnchors(e.anchors, installedPath); err != nil {
					t.Fatal(err)
				}
				previous = readWindowsBundleAnchors(t, installedPath)
			}
			candidate := windowsBundleCandidateAnchors(t, e)
			spool := stubWindowsChangeSpool(t)
			trust := bundleAnchorTrust // stubWindowsBundleHost restores it.
			checked := 0
			bundleAnchorTrust = func(path string) error {
				if filepath.Clean(path) == filepath.Clean(installedPath) {
					checked++
					return errors.New("a standard user can write the installed trust anchor file")
				}
				if trust == nil {
					return nil
				}
				return trust(path)
			}
			cmd, out := windowsBundleCommand()
			opts := &windowsEnterpriseLifecycleOptions{trustAnchors: candidate, profile: managed.ProfileStandalone,
				jsonOutput: true, installedBeforeRun: true}
			done, err := prepareWindowsEnterpriseBundle(context.Background(), cmd, "ensure", opts)
			cleanupPreparedWindowsBundle(t, opts)
			if !done || err == nil || checked == 0 {
				t.Fatalf("anchors that failed their check were accepted: done=%v err=%v checked=%d\n%s", done, err, checked, out)
			}
			if !strings.Contains(out.String(), string(enterprisebundle.CodeAnchorInsecure)) || !strings.Contains(out.String(), "put back") {
				t.Fatalf("result does not say the anchors failed their check and were put back:\n%s", out)
			}
			assertWindowsBundleInstalledAnchors(t, layout, previous, "after the failed check")
			events := windowsChangeEvents(t, spool)
			if len(events) != 1 {
				t.Fatalf("change events = %+v, want one failed anchor install", events)
			}
			ev := events[0]
			wantSHA := ""
			if previous != nil {
				wantSHA = anchorsSHA256(previous)
			}
			if ev.Kind != enterprisestatus.ChangeKindTrustAnchors || ev.Outcome != enterprisestatus.ChangeFailed ||
				ev.ReasonCode != string(enterprisebundle.CodeAnchorInsecure) || ev.SHA256 != wantSHA {
				t.Fatalf("change event = %+v, want a failed anchor install (anchor_insecure) with sha256 %q", ev, wantSHA)
			}
			assertNoWindowsChangeReservations(t, spool)
		})
	}
}
