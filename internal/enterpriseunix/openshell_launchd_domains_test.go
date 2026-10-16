// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

func sshOnlyLaunchdJob(h *osHost, f *fixtureLaunchdRunner, job *launchdJobFixture) string {
	uid := h.alice.UID
	f.domains[uid] = false
	if f.userDomains == nil {
		f.userDomains = make(map[int]bool)
		f.userJobs = make(map[int]map[string]*launchdJobFixture)
	}
	f.userDomains[uid] = true
	f.userJobs[uid] = map[string]*launchdJobFixture{labelOpenShellGateway: job}
	return "user/" + strconv.Itoa(uid)
}

func TestMacOSUserDomainCodeSigningStatusVerifyRepair(t *testing.T) {
	h, f, _ := newLaunchdTestHost(t)
	domain := sshOnlyLaunchdJob(h, f, &launchdJobFixture{loaded: true, state: "not running", reason: "OS_REASON_CODESIGNING", runs: 5})
	for _, action := range []string{ActionStatus, ActionVerify} {
		r := h.run(Options{Action: action})
		message := messagesOf(r.Errors, codeSandboxUserState)
		if !strings.Contains(message, h.alice.Name) || !strings.Contains(message, domain) || !strings.Contains(message, labelOpenShellGateway) || r.SecurityComplete {
			t.Fatalf("%s missed ssh-only code signing job: errors=%+v security_complete=%v", action, r.Errors, r.SecurityComplete)
		}
	}
	if len(f.mutated) != 0 {
		t.Fatalf("read-only actions mutated launchd: %v", f.mutated)
	}
	r := h.run(Options{Action: ActionRepair})
	if len(r.Errors) != 0 || r.ExitCode != 0 {
		t.Fatalf("repair failed: %+v", r.Errors)
	}
	if got := strings.Join(f.mutated, "\n"); !strings.Contains(got, "bootout "+domain+"/"+labelOpenShellGateway) || !strings.Contains(got, "bootstrap "+domain+" ") || !strings.Contains(got, "kickstart "+domain+"/"+labelOpenShellGateway) {
		t.Fatalf("repair did not restart the user-domain job: %v", f.mutated)
	}
	if r := h.run(Options{Action: ActionVerify}); strings.Contains(messagesOf(r.Errors, codeSandboxUserState), labelOpenShellGateway) {
		t.Fatalf("repaired job still failed verify: %+v", r.Errors)
	}
}

func TestMacOSUserDomainPackageIdentityReloadsOnce(t *testing.T) {
	h, f := newMacOSPackageLaunchdHost(t)
	domain := sshOnlyLaunchdJob(h, f, &launchdJobFixture{loaded: true, state: "not running", reason: "OS_REASON_CODESIGNING", runs: 5})
	replaceMacOSPackageBinaries(t, h, "1.0.2")
	r := h.run(Options{Action: ActionEnsure, FromPackage: true, Reason: "package"})
	if len(r.Errors) != 0 {
		t.Fatalf("package ensure failed: %+v", r.Errors)
	}
	if got := strings.Join(f.mutated, "\n"); !strings.Contains(got, "bootout "+domain+"/"+labelOpenShellGateway) || !strings.Contains(got, "bootstrap "+domain+" ") {
		t.Fatalf("package upgrade did not refresh user-domain job: %v", f.mutated)
	}
	f.mutated = nil
	r = h.run(Options{Action: ActionEnsure, FromPackage: true, Reason: "package"})
	if len(r.Errors) != 0 || len(f.mutated) != 0 {
		t.Fatalf("same identity reloaded job: errors=%+v calls=%v", r.Errors, f.mutated)
	}
}

func TestMacOSLaunchAgentUsesEachLoadedDomain(t *testing.T) {
	h, f, _ := newLaunchdTestHost(t)
	uid := h.alice.UID
	f.userDomains = map[int]bool{uid: true}
	f.userJobs = map[int]map[string]*launchdJobFixture{uid: {labelOpenShellGateway: {loaded: true, state: "not running", reason: "OS_REASON_CODESIGNING", runs: 5}}}
	f.jobs[uid][labelOpenShellGateway] = &launchdJobFixture{loaded: true, state: "running", runs: 1}
	r := h.run(Options{Action: ActionRepair})
	if len(r.Errors) != 0 || len(f.mutated) != 3 {
		t.Fatalf("repair did not reload only stale user job: errors=%+v calls=%v", r.Errors, f.mutated)
	}
	for _, call := range f.mutated {
		if !strings.Contains(call, fmt.Sprintf("user/%d", uid)) || strings.Contains(call, fmt.Sprintf("gui/%d", uid)) {
			t.Fatalf("wrong domain mutated: %v", f.mutated)
		}
	}
	f.jobs[uid][labelOpenShellGateway].state = "not running"
	f.jobs[uid][labelOpenShellGateway].reason = "OS_REASON_CODESIGNING"
	f.jobs[uid][labelOpenShellGateway].runs = 5
	f.userJobs[uid][labelOpenShellGateway].state = "not running"
	f.userJobs[uid][labelOpenShellGateway].reason = "OS_REASON_CODESIGNING"
	f.mutated = nil
	r = h.run(Options{Action: ActionRepair})
	if len(r.Errors) != 0 || len(f.mutated) != 6 {
		t.Fatalf("repair did not reload both failed jobs: errors=%+v calls=%v", r.Errors, f.mutated)
	}
	if !strings.Contains(strings.Join(f.mutated, "\n"), fmt.Sprintf("bootout gui/%d/%s", uid, labelOpenShellGateway)) || !strings.Contains(strings.Join(f.mutated, "\n"), fmt.Sprintf("bootout user/%d/%s", uid, labelOpenShellGateway)) {
		t.Fatalf("both domains were not reloaded: %v", f.mutated)
	}
}

func TestMacOSLaunchAgentDomainErrorIsNotMissing(t *testing.T) {
	h, f, _ := newLaunchdTestHost(t)
	domain := "gui/" + strconv.Itoa(h.alice.UID)
	f.domainErrors = map[string]error{domain: errors.New("permission denied")}
	for _, action := range []string{ActionStatus, ActionVerify, ActionRepair} {
		r := h.run(Options{Action: action})
		if message := messagesOf(r.Errors, codeSandboxUserState); !strings.Contains(message, domain) || !strings.Contains(message, "permission denied") {
			t.Fatalf("%s hid launchctl failure: %+v", action, r.Errors)
		}
	}
	if len(f.mutated) != 0 {
		t.Fatalf("inspection error mutated launchd: %v", f.mutated)
	}
	pack, pf := newMacOSPackageLaunchdHost(t)
	packDomain := "gui/" + strconv.Itoa(pack.alice.UID)
	pf.domainErrors = map[string]error{packDomain: errors.New("permission denied")}
	replaceMacOSPackageBinaries(t, pack, "1.0.2")
	r := pack.run(Options{Action: ActionEnsure, FromPackage: true, Reason: "package"})
	if len(r.Errors) != 0 || !strings.Contains(messagesOf(r.Warnings, codeSandboxUserState), "permission denied") || len(pf.mutated) != 0 {
		t.Fatalf("package ensure failed to warn without mutation: errors=%+v warnings=%+v calls=%v", r.Errors, r.Warnings, pf.mutated)
	}
	delete(f.domainErrors, domain)
	f.domainMissing = map[string]bool{domain: true}
	if r := h.run(Options{Action: ActionStatus}); strings.Contains(messagesOf(r.Errors, codeSandboxUserState), domain) {
		t.Fatalf("missing domain raised an error: %+v", r.Errors)
	}
}
