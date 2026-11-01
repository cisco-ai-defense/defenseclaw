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
			// The services launchd has loaded in the domain, as launchctl
			// lists them.
			var body strings.Builder
			fmt.Fprintf(&body, "%s = {\n\tservices = {\n", domain)
			for _, key := range sortedKeys(jobs) {
				if jobs[key].loaded {
					fmt.Fprintf(&body, "\t\t       0      -\t%s\n", key)
				}
			}
			body.WriteString("\t}\n}\n")
			return CommandResult{Stdout: []byte(body.String())}, nil
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
			if _, err := os.Stat(args[2]); err != nil || jobs == nil {
				return CommandResult{}, errors.New("unrecognized label")
			}
			job = &launchdJobFixture{}
			jobs[label] = job
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

func TestMacOSPackageLaunchAgentUsesContentAddressedGateway(t *testing.T) {
	h, _, _ := newLaunchdTestHost(t)
	h.env.UserUnitSource = nil
	unit := h.env.userUnits()[0]
	canonical := h.env.P(filepath.Join(h.env.Layout.BinDir, binGateway))
	digest, err := sha256File(canonical)
	if err != nil {
		t.Fatal(err)
	}
	copyPath := h.env.P(filepath.Join(h.env.Layout.BinDir, "launch-agents", digest, binGateway))
	if err := os.MkdirAll(filepath.Dir(copyPath), 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(copyPath, data, 0o755); err != nil {
		t.Fatal(err)
	}
	plist, err := h.env.userUnitBytes(unit)
	if err != nil || !strings.Contains(string(plist), "/launch-agents/"+digest+"/"+binGateway) {
		t.Fatalf("packaged plist points elsewhere: %v %s", err, plist)
	}
	if err := os.WriteFile(copyPath, []byte("different signed program"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := h.env.userUnitBytes(unit); err == nil {
		t.Fatal("mismatched LaunchAgent program accepted")
	}
	if err := os.Remove(copyPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(canonical, copyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := h.env.userUnitBytes(unit); err == nil {
		t.Fatal("symlinked LaunchAgent program accepted")
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
			f.jobs[h.alice.UID][h.env.launchAgentLabel(labelOpenShellGateway)] = &launchdJobFixture{loaded: tc.loaded, state: tc.state, reason: tc.reason, code: tc.code, runs: 5, stubborn: tc.stubborn}
			r := h.run(Options{Action: ActionRepair})
			if (len(r.Errors) > 0) != tc.wantError {
				t.Fatalf("repair errors = %+v, want error %v", r.Errors, tc.wantError)
			}
			var want []string
			if tc.wantReload {
				uid := h.alice.UID
				want = []string{
					fmt.Sprintf("launchctl bootout gui/%d/%s", uid, h.env.launchAgentLabel(labelOpenShellGateway)),
					fmt.Sprintf("launchctl bootstrap gui/%d %s", uid, h.env.P("/Library/LaunchAgents/"+h.env.launchAgentLabel(labelOpenShellGateway)+".plist")),
					fmt.Sprintf("launchctl kickstart gui/%d/%s", uid, h.env.launchAgentLabel(labelOpenShellGateway)),
				}
			}
			if !reflect.DeepEqual(f.mutated, want) {
				t.Fatalf("launchctl mutations = %v, want %v", f.mutated, want)
			}
			if tc.wantError && !strings.Contains(messagesOf(r.Errors, codeSandboxUserState), h.alice.Name) {
				t.Fatalf("failed repair did not name the user and label: %+v", r.Errors)
			}
			if tc.wantError && (strings.Contains(messagesOf(r.Errors, codeSandboxUserState), "run `"+h.env.lifecycleCommand(ActionRepair)+"`") || !strings.Contains(messagesOf(r.Errors, codeSandboxUserState), "reinstall a signed DefenseClaw package")) {
				t.Fatalf("failed repair recommended retrying itself: %+v", r.Errors)
			}
		})
	}
}

func TestMacOSDisabledLaunchAgentIsLeftAlone(t *testing.T) {
	h, f, _ := newLaunchdTestHost(t)
	f.jobs[h.alice.UID][h.env.launchAgentLabel(labelOpenShellGateway)] = &launchdJobFixture{loaded: true, disabled: true, state: "not running", reason: "OS_REASON_CODESIGNING", code: "(never exited)", runs: 5}
	f.jobs[h.alice.UID][h.env.launchAgentLabel(labelSandbox)] = &launchdJobFixture{loaded: true, state: "not running", reason: "OS_REASON_CODESIGNING", code: "(never exited)", runs: 5}
	r := h.run(Options{Action: ActionRepair})
	want := []string{
		fmt.Sprintf("launchctl bootout gui/%d/%s", h.alice.UID, h.env.launchAgentLabel(labelSandbox)),
		fmt.Sprintf("launchctl bootstrap gui/%d %s", h.alice.UID, h.env.P("/Library/LaunchAgents/"+h.env.launchAgentLabel(labelSandbox)+".plist")),
		fmt.Sprintf("launchctl kickstart gui/%d/%s", h.alice.UID, h.env.launchAgentLabel(labelSandbox)),
	}
	if len(r.Errors) != 0 || !reflect.DeepEqual(f.mutated, want) {
		t.Fatalf("disabled job changed or failing sibling not repaired: errors %+v, calls %v, want %v", r.Errors, f.mutated, want)
	}
}

func TestMacOSIdleGatewayIsFailedWhileSandboxRuns(t *testing.T) {
	h, f, _ := newLaunchdTestHost(t)
	f.jobs[h.alice.UID][h.env.launchAgentLabel(labelOpenShellGateway)] = &launchdJobFixture{loaded: true, state: "not running", code: "0", runs: 2}
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
	f.jobs[h.alice.UID][h.env.launchAgentLabel(labelOpenShellGateway)] = &launchdJobFixture{loaded: true, state: "not running", reason: "OS_REASON_CODESIGNING", code: "(never exited)", runs: 5}
	for _, action := range []string{ActionStatus, ActionVerify} {
		r := h.run(Options{Action: action})
		message := messagesOf(r.Errors, codeSandboxUserState)
		if !strings.Contains(message, h.alice.Name) || !strings.Contains(message, h.env.launchAgentLabel(labelOpenShellGateway)) {
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

func TestMacOSLaunchAgentStatusNamesCodeSigningStateAndRemedy(t *testing.T) {
	h, f, _ := newLaunchdTestHost(t)
	f.jobs[h.alice.UID][h.env.launchAgentLabel(labelSandbox)] = &launchdJobFixture{loaded: true, state: "not running", reason: "OS_REASON_CODESIGNING", code: "(never exited)", runs: 3}
	gateway := h.env.P(filepath.Join(h.env.Layout.BinDir, binGateway))
	before, err := os.Stat(gateway)
	if err != nil {
		t.Fatal(err)
	}
	r := h.run(Options{Action: ActionStatus})
	message := messagesOf(r.Errors, codeSandboxUserState)
	for _, want := range []string{"failed: last start was killed for code signing (OS_REASON_CODESIGNING)", "run `" + h.env.lifecycleCommand(ActionRepair) + "`", "gives the LaunchAgent gateway a new file and reloads the job"} {
		if !strings.Contains(message, want) {
			t.Errorf("status message %q lacks %q", message, want)
		}
	}
	if after, err := os.Stat(gateway); err != nil || !os.SameFile(before, after) {
		t.Fatalf("status replaced the gateway file: %v", err)
	}
}

// launchAgentGatewayCopy lays down the package's content-addressed copy of
// the installed gateway, which the packaged LaunchAgents execute.
func launchAgentGatewayCopy(t *testing.T, h *osHost) (gateway, program string, data []byte) {
	t.Helper()
	gateway = h.env.P(filepath.Join(h.env.Layout.BinDir, binGateway))
	data, err := os.ReadFile(gateway)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := sha256File(gateway)
	if err != nil {
		t.Fatal(err)
	}
	program = h.env.P(filepath.Join(h.env.Layout.BinDir, "launch-agents", digest, binGateway))
	if err := os.MkdirAll(filepath.Dir(program), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(program, data, 0o755); err != nil {
		t.Fatal(err)
	}
	return gateway, program, data
}

func TestMacOSRepairGivesCodeSigningKilledGatewayANewFile(t *testing.T) {
	// GAP-0049: after a package upgrade the user-domain sandbox job of a
	// logged-out account stayed killed for code signing. A reload alone
	// starts the same rejected file, so repair first gives the gateway and
	// its LaunchAgent copy new files with the same bytes.
	h, f, cfg := newLaunchdTestHost(t)
	uid := h.alice.UID
	gateway, program, data := launchAgentGatewayCopy(t, h)
	f.domains[uid] = false
	f.userDomains = map[int]bool{uid: true}
	f.userJobs = map[int]map[string]*launchdJobFixture{uid: {h.env.launchAgentLabel(labelSandbox): {loaded: true, state: "not running", reason: "OS_REASON_CODESIGNING", code: "(never exited)", runs: 3}}}
	before := map[string]os.FileInfo{}
	for _, path := range []string{gateway, program} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		before[path] = info
	}
	r := h.run(Options{Action: ActionRepair})
	if len(r.Errors) != 0 || r.ExitCode != 0 {
		t.Fatalf("repair failed: %+v", r.Errors)
	}
	domain := "user/" + strconv.Itoa(uid)
	want := []string{
		"launchctl bootout " + domain + "/" + h.env.launchAgentLabel(labelSandbox),
		"launchctl bootstrap " + domain + " " + h.env.P("/Library/LaunchAgents/"+h.env.launchAgentLabel(labelSandbox)+".plist"),
		"launchctl kickstart " + domain + "/" + h.env.launchAgentLabel(labelSandbox),
	}
	if !reflect.DeepEqual(f.mutated, want) {
		t.Fatalf("repair mutations = %v, want %v", f.mutated, want)
	}
	for path, old := range before {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if os.SameFile(old, info) {
			t.Errorf("%s kept its file, so launchd starts the rejected file again", path)
		}
		if info.Mode().Perm() != 0o755 {
			t.Errorf("%s mode = %v, want 0755", path, info.Mode().Perm())
		}
		if got, err := os.ReadFile(path); err != nil || string(got) != string(data) {
			t.Errorf("%s changed its bytes: %v", path, err)
		}
	}
	if !strings.Contains(strings.Join(r.Changes, "\n"), "new file") {
		t.Errorf("repair did not report the new gateway file: %v", r.Changes)
	}
	f.mutated = nil
	requireOK(t, h.ensure(cfg))
	if len(f.mutated) != 0 {
		t.Fatalf("an ensure after the repair reloaded the healthy job again: %v", f.mutated)
	}
}

func TestMacOSRepairKeepsTheGatewayFileForOtherFailures(t *testing.T) {
	h, f, _ := newLaunchdTestHost(t)
	gateway := h.env.P(filepath.Join(h.env.Layout.BinDir, binGateway))
	before, err := os.Stat(gateway)
	if err != nil {
		t.Fatal(err)
	}
	f.jobs[h.alice.UID][h.env.launchAgentLabel(labelOpenShellGateway)] = &launchdJobFixture{loaded: true, state: "not running", spawn: "Input/output error", code: "(never exited)", runs: 2}
	r := h.run(Options{Action: ActionRepair})
	if len(r.Errors) != 0 || len(f.mutated) != 3 {
		t.Fatalf("repair of a spawn failure: errors %+v, calls %v", r.Errors, f.mutated)
	}
	if after, err := os.Stat(gateway); err != nil || !os.SameFile(before, after) {
		t.Fatalf("a failure other than code signing replaced the gateway file: %v", err)
	}
}

func TestMacOSRepairRefusesAnUntrustedLaunchAgentProgram(t *testing.T) {
	h, f, _ := newLaunchdTestHost(t)
	gateway, program, _ := launchAgentGatewayCopy(t, h)
	if err := os.Remove(program); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(gateway, program); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(gateway)
	if err != nil {
		t.Fatal(err)
	}
	f.jobs[h.alice.UID][h.env.launchAgentLabel(labelSandbox)] = &launchdJobFixture{loaded: true, state: "not running", reason: "OS_REASON_CODESIGNING", code: "(never exited)", runs: 3}
	r := h.run(Options{Action: ActionRepair})
	if len(f.mutated) != 0 {
		t.Fatalf("repair reloaded a job whose program it refused: %v", f.mutated)
	}
	if after, err := os.Stat(gateway); err != nil || !os.SameFile(before, after) {
		t.Fatalf("repair replaced the gateway while the LaunchAgent program was untrusted: %v", err)
	}
	if warning := messagesOf(r.Warnings, codeSandboxUserState); !strings.Contains(warning, "not a regular file") {
		t.Errorf("repair did not name the refused program: %+v", r.Warnings)
	}
	if message := messagesOf(r.Errors, codeSandboxUserState); !strings.Contains(message, "reinstall a signed DefenseClaw package") {
		t.Errorf("failed repair gave no next step: %+v", r.Errors)
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
	f.jobs[h.alice.UID][h.env.launchAgentLabel(labelOpenShellGateway)] = &launchdJobFixture{loaded: true, state: "not running", reason: "OS_REASON_CODESIGNING", code: "(never exited)", runs: 5}
	f.jobs[bob.UID][h.env.launchAgentLabel(labelSandbox)] = &launchdJobFixture{loaded: true, state: "running", code: "(never exited)", runs: 1}
	f.jobs[carol.UID][h.env.launchAgentLabel(labelOpenShellGateway)] = &launchdJobFixture{loaded: false}
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
		fmt.Sprintf("launchctl bootout gui/%d/%s", h.alice.UID, h.env.launchAgentLabel(labelOpenShellGateway)),
		fmt.Sprintf("launchctl bootstrap gui/%d %s", h.alice.UID, h.env.P("/Library/LaunchAgents/"+h.env.launchAgentLabel(labelOpenShellGateway)+".plist")),
		fmt.Sprintf("launchctl kickstart gui/%d/%s", h.alice.UID, h.env.launchAgentLabel(labelOpenShellGateway)),
		fmt.Sprintf("launchctl bootout gui/%d/%s", bob.UID, h.env.launchAgentLabel(labelSandbox)),
		fmt.Sprintf("launchctl bootstrap gui/%d %s", bob.UID, h.env.P("/Library/LaunchAgents/"+h.env.launchAgentLabel(labelSandbox)+".plist")),
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
	f.jobs[h.alice.UID][h.env.launchAgentLabel(labelOpenShellGateway)] = &launchdJobFixture{loaded: true, state: "running", code: "(never exited)", runs: 1}
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
	f.jobs[h.alice.UID][h.env.launchAgentLabel(labelOpenShellGateway)] = &launchdJobFixture{loaded: true, state: "not running", reason: "OS_REASON_CODESIGNING", code: "(never exited)", runs: 5, stubborn: true}
	// The same build again: a new gateway file, the same label.
	replaceMacOSPackageBinaries(t, h, "1.0.1")
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
	f.jobs[h.alice.UID][h.env.launchAgentLabel(labelOpenShellGateway)] = &launchdJobFixture{loaded: true, state: "running", code: "(never exited)", runs: 1}
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
	old := h.env.launchAgentLabel(labelOpenShellGateway)
	f.jobs[h.alice.UID][old] = &launchdJobFixture{loaded: true, state: "running", code: "(never exited)", runs: 1}
	if err := os.Remove(h.env.openshellStatePath()); err != nil {
		t.Fatal(err)
	}
	replaceMacOSPackageBinaries(t, h, "1.0.2")
	requireOK(t, h.run(Options{Action: ActionEnsure, FromPackage: true, Reason: "package"}))
	// The job of the earlier label goes; the new label is loaded idle.
	want := []string{
		fmt.Sprintf("launchctl bootout gui/%d/%s", h.alice.UID, old),
		fmt.Sprintf("launchctl bootstrap gui/%d %s", h.alice.UID, h.env.P("/Library/LaunchAgents/"+h.env.launchAgentLabel(labelOpenShellGateway)+".plist")),
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

// TestMacOSLaunchAgentReloadStopsTheDaemonBeforeTheDrain: a reload of an
// idle account's loaded jobs stops its gateway, so it runs under the drain,
// and the drain only after the account's sandbox agent is out (a daemon
// an older DefenseClaw started takes no lifecycle lock).
func TestMacOSLaunchAgentReloadStopsTheDaemonBeforeTheDrain(t *testing.T) {
	h, f, cfg := newLaunchdTestHost(t)
	f.jobs[h.alice.UID][h.env.launchAgentLabel(labelOpenShellGateway)] = &launchdJobFixture{loaded: true, state: "running", code: "(never exited)", runs: 1}
	h.ops.status[h.alice.UID] = SandboxStatus{Active: true}
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
	h.ops.order = nil
	requireOK(t, h.ensure(cfg))
	// Its running gateway's MicroVMs are synced under the drain, before the
	// reload boots the gateway agent out (GAP-0380).
	if want := []string{"stop alice:daemon+socket", "drain alice", "sync alice", "release alice"}; !reflect.DeepEqual(h.ops.order, want) {
		t.Fatalf("order = %v, want %v", h.ops.order, want)
	}
	if len(f.mutated) != 2 || !strings.Contains(f.mutated[0], "bootout gui/"+strconv.Itoa(h.alice.UID)+"/"+h.env.launchAgentLabel(labelOpenShellGateway)) {
		t.Fatalf("mutations = %v", f.mutated)
	}

	// A daemon before 1.0.4 is killed, not booted out: its exit stopped the
	// gateway under a MicroVM that completed before the drain could see it.
	h2, f2, cfg2 := newLaunchdTestHost(t)
	f2.jobs[h2.alice.UID][h.env.launchAgentLabel(labelOpenShellGateway)] = &launchdJobFixture{loaded: true, state: "running", code: "(never exited)", runs: 1}
	h2.ops.status[h2.alice.UID] = SandboxStatus{Active: true, Legacy: true}
	path2 := h2.env.P(filepath.Join(h2.env.Layout.BinDir, binGateway))
	data2, err := os.ReadFile(path2)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path2+".new", data2, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path2+".new", path2); err != nil {
		t.Fatal(err)
	}
	h2.ops.order = nil
	requireOK(t, h2.ensure(cfg2))
	if want := []string{"stop alice:kill+daemon+socket", "drain alice", "sync alice", "release alice"}; !reflect.DeepEqual(h2.ops.order, want) {
		t.Fatalf("legacy order = %v, want %v", h2.ops.order, want)
	}
}

// bootoutGoneRunner answers launchctl as for a job the drain booted out
// already: its bootout finds nothing to boot out.
type bootoutGoneRunner struct{ calls []string }

func (r *bootoutGoneRunner) Run(_ context.Context, name string, args ...string) (CommandResult, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	switch args[0] {
	case "bootout":
		return CommandResult{Stderr: []byte("Boot-out failed: 3: No such process\n")}, errors.New("exit status 3")
	case "print":
		return CommandResult{Stdout: []byte(args[1] + " = {\n\tstate = running\n\truns = 1\n}\n")}, nil
	}
	return CommandResult{}, nil
}

// TestMacOSReloadOfAJobTheDrainBootedOut: the reload of the sandbox agent
// the account's drain booted out first loads it again.
func TestMacOSReloadOfAJobTheDrainBootedOut(t *testing.T) {
	h, _, _ := newLaunchdTestHost(t)
	r := &bootoutGoneRunner{}
	h.env.Runner = r
	job := loadedLaunchAgent{domain: "gui/" + strconv.Itoa(h.alice.UID), label: h.env.launchAgentLabel(labelSandbox)}
	if err := h.env.reloadMacOSAgent(context.Background(), job, false); err != nil {
		t.Fatalf("reload = %v (calls %v)", err, r.calls)
	}
	if len(r.calls) < 2 || !strings.HasPrefix(r.calls[1], "launchctl bootstrap gui/") {
		t.Fatalf("calls = %v", r.calls)
	}
}
