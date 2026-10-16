// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

type launchdJobFixture struct {
	loaded, disabled, stubborn bool
	state, reason, code, spawn string
	runs                       int
}

// fixtureLaunchdRunner handles both account domains; the host fake keeps
// answering all other lifecycle commands.
type fixtureLaunchdRunner struct {
	base          Runner
	domains       map[int]bool
	jobs          map[int]map[string]*launchdJobFixture
	userDomains   map[int]bool
	userJobs      map[int]map[string]*launchdJobFixture
	domainMissing map[string]bool
	domainErrors  map[string]error
	calls         []string
	mutated       []string
	disabledError bool
}

func (f *fixtureLaunchdRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	if name != "launchctl" || len(args) < 2 || !strings.HasPrefix(args[1], "gui/") && !strings.HasPrefix(args[1], "user/") {
		return f.base.Run(ctx, name, args...)
	}
	f.calls = append(f.calls, "launchctl "+strings.Join(args, " "))
	domainKind, rest, _ := strings.Cut(args[1], "/")
	uidText, label, _ := strings.Cut(rest, "/")
	uid, _ := strconv.Atoi(uidText)
	domain := domainKind + "/" + uidText
	if !f.domains[uid] && domainKind == "gui" || !f.userDomains[uid] && domainKind == "user" || f.domainMissing[domain] {
		return CommandResult{Stderr: []byte("Bad request.\nCould not find domain for user " + domainKind + ": " + uidText)}, errors.New("exit status 112: Could not find domain")
	}
	if err := f.domainErrors[domain]; err != nil && args[0] == "print" && label == "" {
		return CommandResult{Stderr: []byte("launchctl inspection failed")}, err
	}
	jobs := f.jobs[uid]
	if domainKind == "user" {
		jobs = f.userJobs[uid]
	}
	job := jobs[label]
	switch args[0] {
	case "print-disabled":
		if f.disabledError {
			return CommandResult{}, errors.New("launchctl disabled state unavailable")
		}
		var body strings.Builder
		body.WriteString("disabled services = {\n")
		for key, item := range jobs {
			if item.disabled {
				fmt.Fprintf(&body, "  %q => disabled\n", key)
			}
		}
		body.WriteString("}\n")
		return CommandResult{Stdout: []byte(body.String())}, nil
	case "print":
		if label == "" {
			return CommandResult{Stdout: []byte(fmt.Sprintf("%s = {\n}\n", domain))}, nil
		}
		if job == nil || !job.loaded {
			return CommandResult{Stderr: []byte("Could not find service \"" + label + "\" in domain for uid: " + uidText)}, errors.New("exit status 113: Could not find service")
		}
		var body strings.Builder
		fmt.Fprintf(&body, "%s/%s = {\n\tstate = %s\n\truns = %d\n", domain, label, job.state, job.runs)
		if job.reason != "" {
			fmt.Fprintf(&body, "\tlast exit reason = %s\n", job.reason)
		}
		if job.code != "" {
			fmt.Fprintf(&body, "\tlast exit code = %s\n", job.code)
		}
		if job.spawn != "" {
			fmt.Fprintf(&body, "\tlast spawn error = %s\n", job.spawn)
		}
		body.WriteString("}\n")
		return CommandResult{Stdout: []byte(body.String())}, nil
	case "bootout":
		if job == nil || !job.loaded {
			return CommandResult{}, errors.New("service not loaded")
		}
		f.mutated = append(f.mutated, "launchctl "+strings.Join(args, " "))
		job.loaded = false
		return CommandResult{}, nil
	case "bootstrap":
		if len(args) != 3 {
			return CommandResult{}, errors.New("missing plist")
		}
		label = strings.TrimSuffix(filepath.Base(args[2]), ".plist")
		job = jobs[label]
		if job == nil {
			return CommandResult{}, errors.New("unrecognized label")
		}
		f.mutated = append(f.mutated, "launchctl "+strings.Join(args, " "))
		job.loaded, job.state, job.reason, job.code, job.spawn, job.runs = true, "not running", "", "(never exited)", "", 0
		return CommandResult{}, nil
	case "kickstart":
		if job == nil || !job.loaded {
			return CommandResult{}, errors.New("service not loaded")
		}
		f.mutated = append(f.mutated, "launchctl "+strings.Join(args, " "))
		if job.stubborn {
			job.state, job.reason, job.code, job.runs = "not running", "OS_REASON_CODESIGNING", "(never exited)", 5
		} else {
			job.state, job.reason, job.code, job.runs = "running", "", "(never exited)", 1
		}
		return CommandResult{}, nil
	}
	return f.base.Run(ctx, name, args...)
}

func newLaunchdTestHost(t *testing.T) (*osHost, *fixtureLaunchdRunner, []byte) {
	t.Helper()
	h := newOSHost(t, "darwin")
	cfg := sandboxConfig(t, "darwin", true, map[string]any{"install": "prerequisite"})
	requireOK(t, h.ensure(cfg))
	f := &fixtureLaunchdRunner{base: h.runner, domains: map[int]bool{h.alice.UID: true}, jobs: map[int]map[string]*launchdJobFixture{h.alice.UID: {}}}
	h.env.Runner = f
	return h, f, cfg
}

func newMacOSPackageLaunchdHost(t *testing.T) (*osHost, *fixtureLaunchdRunner) {
	t.Helper()
	h := newOSHost(t, "darwin")
	bin := h.env.P(h.env.Layout.BinDir)
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	staged := h.payload("1.0.1")
	for _, name := range []string{binGateway, binHook, binSensorHelper} {
		if err := h.env.copyFileAtomic(filepath.Join(staged, name), filepath.Join(bin, name), 0o755, rootOwner()); err != nil {
			t.Fatal(err)
		}
	}
	for _, u := range h.env.userUnits() {
		data, err := h.env.userUnitBytes(u)
		if err != nil {
			t.Fatal(err)
		}
		writeHostFile(t, h.testHost, h.env.userUnitPath(u, ChannelPackage), string(data))
	}
	launcher := h.env.P(h.env.launcherPath())
	if err := os.MkdirAll(filepath.Dir(launcher), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(h.env.launcherTarget(), launcher); err != nil {
		t.Fatal(err)
	}
	cfg := sandboxConfig(t, "darwin", true, map[string]any{"install": "prerequisite"})
	requireOK(t, h.run(Options{Action: ActionEnsure, FromPackage: true, Reason: "package", ConfigFile: writeTempConfig(t, cfg)}))
	f := &fixtureLaunchdRunner{base: h.runner, domains: map[int]bool{h.alice.UID: true}, jobs: map[int]map[string]*launchdJobFixture{h.alice.UID: {}}}
	h.env.Runner = f
	return h, f
}

func replaceMacOSPackageBinaries(t *testing.T, h *osHost, version string) {
	t.Helper()
	staged := h.payload(version)
	for _, name := range []string{binGateway, binHook, binSensorHelper} {
		if err := h.env.copyFileAtomic(filepath.Join(staged, name), h.env.P(filepath.Join(h.env.Layout.BinDir, name)), 0o755, rootOwner()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMacOSLaunchAgentRepairDecision(t *testing.T) {
	for _, tc := range []struct {
		name, state, reason, code string
		loaded, domain, stubborn  bool
		wantReload, wantError     bool
	}{
		{"code signing failure", "not running", "OS_REASON_CODESIGNING", "(never exited)", true, true, false, true, false},
		{"healthy running", "running", "", "(never exited)", true, true, false, false, false},
		{"normal idle", "not running", "", "0", true, true, false, false, false},
		{"not loaded", "not running", "", "", false, true, false, false, false},
		{"logged out", "not running", "OS_REASON_CODESIGNING", "(never exited)", true, false, false, false, false},
		{"still failing after bootstrap", "not running", "OS_REASON_CODESIGNING", "(never exited)", true, true, true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, f, _ := newLaunchdTestHost(t)
			f.domains[h.alice.UID] = tc.domain
			f.jobs[h.alice.UID][labelOpenShellGateway] = &launchdJobFixture{loaded: tc.loaded, state: tc.state, reason: tc.reason, code: tc.code, runs: 5, stubborn: tc.stubborn}
			r := h.run(Options{Action: ActionRepair})
			if (len(r.Errors) > 0) != tc.wantError {
				t.Fatalf("repair errors = %+v, want error %v", r.Errors, tc.wantError)
			}
			var want []string
			if tc.wantReload {
				uid := h.alice.UID
				want = []string{
					fmt.Sprintf("launchctl bootout gui/%d/%s", uid, labelOpenShellGateway),
					fmt.Sprintf("launchctl bootstrap gui/%d %s", uid, h.env.P("/Library/LaunchAgents/"+labelOpenShellGateway+".plist")),
					fmt.Sprintf("launchctl kickstart gui/%d/%s", uid, labelOpenShellGateway),
				}
			}
			if !reflect.DeepEqual(f.mutated, want) {
				t.Fatalf("launchctl mutations = %v, want %v", f.mutated, want)
			}
			if tc.wantError && !strings.Contains(messagesOf(r.Errors, codeSandboxUserState), h.alice.Name) {
				t.Fatalf("failed repair did not name the user and label: %+v", r.Errors)
			}
		})
	}
}

func TestMacOSDisabledLaunchAgentIsLeftAlone(t *testing.T) {
	h, f, _ := newLaunchdTestHost(t)
	f.jobs[h.alice.UID][labelOpenShellGateway] = &launchdJobFixture{loaded: true, disabled: true, state: "not running", reason: "OS_REASON_CODESIGNING", code: "(never exited)", runs: 5}
	f.jobs[h.alice.UID][labelSandbox] = &launchdJobFixture{loaded: true, state: "not running", reason: "OS_REASON_CODESIGNING", code: "(never exited)", runs: 5}
	r := h.run(Options{Action: ActionRepair})
	want := []string{
		fmt.Sprintf("launchctl bootout gui/%d/%s", h.alice.UID, labelSandbox),
		fmt.Sprintf("launchctl bootstrap gui/%d %s", h.alice.UID, h.env.P("/Library/LaunchAgents/"+labelSandbox+".plist")),
		fmt.Sprintf("launchctl kickstart gui/%d/%s", h.alice.UID, labelSandbox),
	}
	if len(r.Errors) != 0 || !reflect.DeepEqual(f.mutated, want) {
		t.Fatalf("disabled job changed or failing sibling not repaired: errors %+v, calls %v, want %v", r.Errors, f.mutated, want)
	}
}

func TestMacOSIdleGatewayIsFailedWhileSandboxRuns(t *testing.T) {
	h, f, _ := newLaunchdTestHost(t)
	f.jobs[h.alice.UID][labelOpenShellGateway] = &launchdJobFixture{loaded: true, state: "not running", code: "0", runs: 2}
	h.ops.status[h.alice.UID] = SandboxStatus{Active: true, Running: 1}
	r := h.run(Options{Action: ActionRepair})
	if len(f.mutated) != 0 {
		t.Fatalf("running sandbox was interrupted: %v", f.mutated)
	}
	if !strings.Contains(messagesOf(r.Errors, codeSandboxUserState), "loaded but not running") {
		t.Fatalf("repair reported success while the needed gateway is down: %+v", r.Errors)
	}
}

func TestMacOSLaunchAgentStatusAndVerifyReportCodeSigningFailure(t *testing.T) {
	h, f, _ := newLaunchdTestHost(t)
	f.jobs[h.alice.UID][labelOpenShellGateway] = &launchdJobFixture{loaded: true, state: "not running", reason: "OS_REASON_CODESIGNING", code: "(never exited)", runs: 5}
	for _, action := range []string{ActionStatus, ActionVerify} {
		r := h.run(Options{Action: action})
		message := messagesOf(r.Errors, codeSandboxUserState)
		if !strings.Contains(message, h.alice.Name) || !strings.Contains(message, labelOpenShellGateway) {
			t.Errorf("%s did not report the failed loaded job: %+v", action, r.Errors)
		}
		if r.SecurityComplete {
			t.Errorf("%s reported security complete while its loaded gateway job failed", action)
		}
	}
	if len(f.mutated) != 0 {
		t.Fatalf("status or verify mutated launchd: %v", f.mutated)
	}
}

func TestMacOSPackageGatewayIdentityReloadsOnlyLoadedJobsOnce(t *testing.T) {
	h, f, cfg := newLaunchdTestHost(t)
	bob := SandboxAccount{Name: "bob", UID: h.alice.UID + 1, Home: "/Users/bob"}
	carol := SandboxAccount{Name: "carol", UID: h.alice.UID + 2, Home: "/Users/carol"}
	h.ops.accounts = []SandboxAccount{h.alice, bob, carol}
	f.domains[bob.UID], f.domains[carol.UID] = true, true
	f.jobs[bob.UID] = map[string]*launchdJobFixture{}
	f.jobs[carol.UID] = map[string]*launchdJobFixture{}
	f.jobs[h.alice.UID][labelOpenShellGateway] = &launchdJobFixture{loaded: true, state: "not running", reason: "OS_REASON_CODESIGNING", code: "(never exited)", runs: 5}
	f.jobs[bob.UID][labelSandbox] = &launchdJobFixture{loaded: true, state: "running", code: "(never exited)", runs: 1}
	f.jobs[carol.UID][labelOpenShellGateway] = &launchdJobFixture{loaded: false}
	f.jobs[bob.UID]["com.example.other-product"] = &launchdJobFixture{loaded: true, state: "running"}
	path := h.env.P(filepath.Join(h.env.Layout.BinDir, binGateway))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tmp := path + ".pkg-replacement"
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
	requireOK(t, h.ensure(cfg))
	want := []string{
		fmt.Sprintf("launchctl bootout gui/%d/%s", h.alice.UID, labelOpenShellGateway),
		fmt.Sprintf("launchctl bootstrap gui/%d %s", h.alice.UID, h.env.P("/Library/LaunchAgents/"+labelOpenShellGateway+".plist")),
		fmt.Sprintf("launchctl kickstart gui/%d/%s", h.alice.UID, labelOpenShellGateway),
		fmt.Sprintf("launchctl bootout gui/%d/%s", bob.UID, labelSandbox),
		fmt.Sprintf("launchctl bootstrap gui/%d %s", bob.UID, h.env.P("/Library/LaunchAgents/"+labelSandbox+".plist")),
	}
	if !reflect.DeepEqual(f.mutated, want) {
		t.Fatalf("post-upgrade mutations = %v, want %v", f.mutated, want)
	}
	f.mutated = nil
	requireOK(t, h.ensure(cfg))
	if len(f.mutated) != 0 {
		t.Fatalf("a second ensure of the same gateway inode reloaded healthy jobs: %v", f.mutated)
	}
}

func TestMacOSLaunchAgentReloadWaitsForRunningSandbox(t *testing.T) {
	h, f, cfg := newLaunchdTestHost(t)
	f.jobs[h.alice.UID][labelOpenShellGateway] = &launchdJobFixture{loaded: true, state: "running", code: "(never exited)", runs: 1}
	h.ops.status[h.alice.UID] = SandboxStatus{Active: true, Running: 1}
	path := h.env.P(filepath.Join(h.env.Layout.BinDir, binGateway))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".new", data, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".new", path); err != nil {
		t.Fatal(err)
	}
	requireOK(t, h.ensure(cfg))
	if len(f.mutated) != 0 {
		t.Fatalf("running sandbox was interrupted: %v", f.mutated)
	}
	if entry := h.env.loadOpenShellState().Pending[strconv.Itoa(h.alice.UID)]; entry.Kind != "launchd" {
		t.Fatalf("gateway reload was not pending: %+v", entry)
	}
	h.ops.status[h.alice.UID] = SandboxStatus{Active: true}
	requireOK(t, h.ensure(cfg))
	if len(f.mutated) != 2 || !strings.Contains(f.mutated[0], "bootout") || !strings.Contains(f.mutated[1], "bootstrap") {
		t.Fatalf("idle account did not reload its loaded gateway: %v", f.mutated)
	}
	if len(h.env.loadOpenShellState().Pending) != 0 {
		t.Fatalf("completed reload stayed pending: %+v", h.env.loadOpenShellState().Pending)
	}
}

func TestMacOSPackageEnsureRecordsFailedUserReloadForRepair(t *testing.T) {
	h, f := newMacOSPackageLaunchdHost(t)
	f.jobs[h.alice.UID][labelOpenShellGateway] = &launchdJobFixture{loaded: true, state: "not running", reason: "OS_REASON_CODESIGNING", code: "(never exited)", runs: 5, stubborn: true}
	replaceMacOSPackageBinaries(t, h, "1.0.2")
	r := h.run(Options{Action: ActionEnsure, FromPackage: true, Reason: "package"})
	if len(r.Errors) != 0 {
		t.Fatalf("one user's reload failed the package ensure: %+v", r.Errors)
	}
	if entry := h.env.loadOpenShellState().Pending[strconv.Itoa(h.alice.UID)]; entry.Kind != "launchd" {
		t.Fatalf("failed reload was not recorded for repair: %+v", entry)
	}
	if !hasWarning(r, codeSandboxUserState) {
		t.Fatalf("failed reload gave no warning: %+v", r.Warnings)
	}
}

func TestMacOSPackageEnsureRecordsUninspectableLoadedJob(t *testing.T) {
	h, f := newMacOSPackageLaunchdHost(t)
	f.jobs[h.alice.UID][labelOpenShellGateway] = &launchdJobFixture{loaded: true, state: "running", code: "(never exited)", runs: 1}
	f.disabledError = true
	replaceMacOSPackageBinaries(t, h, "1.0.2")
	r := h.run(Options{Action: ActionEnsure, FromPackage: true, Reason: "package"})
	if len(r.Errors) != 0 || len(f.mutated) != 0 {
		t.Fatalf("uninspectable job failed install or was mutated: errors %+v, calls %v", r.Errors, f.mutated)
	}
	if entry := h.env.loadOpenShellState().Pending[strconv.Itoa(h.alice.UID)]; entry.Kind != "launchd" {
		t.Fatalf("uninspectable job was not recorded for repair: %+v", entry)
	}
}

func TestMacOSPackageUpgradeWithoutOldOpenShellStateReloadsOnce(t *testing.T) {
	h, f := newMacOSPackageLaunchdHost(t)
	f.jobs[h.alice.UID][labelOpenShellGateway] = &launchdJobFixture{loaded: true, state: "running", code: "(never exited)", runs: 1}
	if err := os.Remove(h.env.openshellStatePath()); err != nil {
		t.Fatal(err)
	}
	replaceMacOSPackageBinaries(t, h, "1.0.2")
	requireOK(t, h.run(Options{Action: ActionEnsure, FromPackage: true, Reason: "package"}))
	want := []string{
		fmt.Sprintf("launchctl bootout gui/%d/%s", h.alice.UID, labelOpenShellGateway),
		fmt.Sprintf("launchctl bootstrap gui/%d %s", h.alice.UID, h.env.P("/Library/LaunchAgents/"+labelOpenShellGateway+".plist")),
	}
	if !reflect.DeepEqual(f.mutated, want) {
		t.Fatalf("1.0.1 to 1.0.2 upgrade without old state reloaded %v, want %v", f.mutated, want)
	}
	f.mutated = nil
	requireOK(t, h.run(Options{Action: ActionEnsure, FromPackage: true, Reason: "package"}))
	if len(f.mutated) != 0 {
		t.Fatalf("repeated ensure of the same package inode reloaded it again: %v", f.mutated)
	}
}
