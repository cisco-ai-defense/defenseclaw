// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// macOSAgentBases are the bases of both LaunchAgent labels.
var macOSAgentBases = []string{labelSandbox, labelOpenShellGateway}

// asMacOSPackageOf103 puts the host back where a 1.0.0 to 1.0.3 package left
// it: both LaunchAgents under their bare labels, no tagged plist.
func asMacOSPackageOf103(t *testing.T, h *osHost) {
	t.Helper()
	dir := h.env.P("/Library/LaunchAgents")
	for _, base := range macOSAgentBases {
		matches, _ := filepath.Glob(filepath.Join(dir, base+".*.plist"))
		bare := filepath.Join(dir, base+".plist")
		for _, tagged := range matches {
			data, err := os.ReadFile(tagged)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(tagged); err != nil {
				t.Fatal(err)
			}
			label := strings.TrimSuffix(filepath.Base(tagged), ".plist")
			writeHostFile(t, h.testHost, "/Library/LaunchAgents/"+base+".plist", strings.Replace(string(data), "<string>"+label+"</string>", "<string>"+base+"</string>", 1))
		}
		if _, err := os.Stat(bare); err != nil {
			t.Fatalf("the 1.0.3 host has no %s: %v", bare, err)
		}
	}
}

// launchAgentPlists lists the DefenseClaw sandbox plists in the host's
// /Library/LaunchAgents.
func launchAgentPlists(t *testing.T, h *osHost) []string {
	t.Helper()
	entries, err := os.ReadDir(h.env.P("/Library/LaunchAgents"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), labelSandbox) || strings.HasPrefix(entry.Name(), labelOpenShellGateway) {
			names = append(names, entry.Name())
		}
	}
	return names
}

// GAP-0206: after a 1.0.2 package was upgraded, macOS killed the sandbox
// daemon of an AD account for code signing (OS_REASON_CODESIGNING) under
// its old label whatever was reloaded. The upgrade installs both agents
// under the label of the new gateway (base.<first 12 digits of its
// SHA-256>), removes the old plists, and replaces the loaded job of the old
// label with an idle job of the new one; the next upgrade does the same
// again.
func TestMacOSUpgradeReplacesTheLaunchAgentLabel(t *testing.T) {
	h, f := newMacOSPackageLaunchdHost(t)
	asMacOSPackageOf103(t, h)
	domain := sshOnlyLaunchdJob(h, f, &launchdJobFixture{loaded: true, state: "running", runs: 1})
	f.userJobs[h.alice.UID][labelSandbox] = &launchdJobFixture{loaded: true, state: "not running", reason: "OS_REASON_CODESIGNING", code: "(never exited)", runs: 3}
	f.userJobs[h.alice.UID][labelOpenShellGateway] = &launchdJobFixture{loaded: true, state: "running", runs: 1}

	previous := map[string]string{labelSandbox: labelSandbox, labelOpenShellGateway: labelOpenShellGateway}
	for _, version := range []string{"1.0.4-rc.1", "1.0.4-rc.2"} {
		replaceMacOSPackageBinaries(t, h, version)
		f.mutated = nil
		r := h.run(Options{Action: ActionEnsure, FromPackage: true, Reason: "package"})
		if len(r.Errors) != 0 {
			t.Fatalf("%s: package ensure failed: %+v", version, r.Errors)
		}
		digest, err := sha256File(h.env.P(filepath.Join(h.env.Layout.BinDir, binGateway)))
		if err != nil {
			t.Fatal(err)
		}
		var want []string
		for _, base := range macOSAgentBases {
			label := base + "." + digest[:12]
			if label == previous[base] {
				t.Fatalf("%s: %s kept the label %s", version, base, label)
			}
			plist, err := os.ReadFile(h.env.P("/Library/LaunchAgents/" + label + ".plist"))
			if err != nil || !strings.Contains(string(plist), "<string>"+label+"</string>") || strings.Contains(string(plist), "<string>"+base+"</string>") {
				t.Fatalf("%s: plist of %s: %v\n%s", version, label, err, plist)
			}
			want = append(want, "launchctl bootout "+domain+"/"+previous[base],
				"launchctl bootstrap "+domain+" "+h.env.P("/Library/LaunchAgents/"+label+".plist"))
			previous[base] = label
		}
		if got := launchAgentPlists(t, h); !slices.Equal(got, []string{previous[labelOpenShellGateway] + ".plist", previous[labelSandbox] + ".plist"}) {
			t.Fatalf("%s: plists %v: the earlier labels' stay", version, got)
		}
		slices.Sort(want)
		got := slices.Clone(f.mutated)
		slices.Sort(got)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: mutations %v, want %v", version, f.mutated, want)
		}
		if entry, waiting := h.env.loadOpenShellState().Pending[strconv.Itoa(h.alice.UID)]; waiting {
			t.Fatalf("%s: the replaced job stayed pending: %+v", version, entry)
		}
		for _, base := range macOSAgentBases {
			if job := f.userJobs[h.alice.UID][previous[base]]; job == nil || !job.loaded || job.state != "not running" || job.reason != "" {
				t.Fatalf("%s: job of %s = %+v, want it loaded and idle", version, previous[base], job)
			}
		}
	}
	f.mutated = nil
	if r := h.run(Options{Action: ActionEnsure, FromPackage: true, Reason: "package"}); len(r.Errors) != 0 || len(f.mutated) != 0 {
		t.Fatalf("an ensure of the same build changed the jobs again: %+v %v", r.Errors, f.mutated)
	}
	if r := h.run(Options{Action: ActionStatus}); strings.Contains(messagesOf(r.Warnings, codeSandboxUserState)+messagesOf(r.Errors, codeSandboxUserState), "earlier") {
		t.Fatalf("status still names an earlier label: %+v %+v", r.Errors, r.Warnings)
	}
}

// A job of the earlier label whose sandboxes still run keeps running until
// they stop; status names it, and the next run with the account idle
// replaces it.
func TestMacOSLaunchAgentLabelWaitsForRunningSandboxes(t *testing.T) {
	h, f := newMacOSPackageLaunchdHost(t)
	asMacOSPackageOf103(t, h)
	f.jobs[h.alice.UID][labelSandbox] = &launchdJobFixture{loaded: true, state: "running", runs: 1}
	h.ops.status[h.alice.UID] = SandboxStatus{Active: true, Running: 1}
	replaceMacOSPackageBinaries(t, h, "1.0.4")
	r := h.run(Options{Action: ActionEnsure, FromPackage: true, Reason: "package"})
	if len(r.Errors) != 0 || len(f.mutated) != 0 {
		t.Fatalf("running sandboxes were interrupted: %+v %v", r.Errors, f.mutated)
	}
	if entry := h.env.loadOpenShellState().Pending[strconv.Itoa(h.alice.UID)]; entry.Kind != "launchd" {
		t.Fatalf("the label change was not pending: %+v", entry)
	}
	current := installedAgentLabel(t, h, labelSandbox)
	status := h.run(Options{Action: ActionStatus})
	if got := messagesOf(status.Warnings, codeSandboxUserState); !strings.Contains(got, labelSandbox+" of alice") || !strings.Contains(got, "earlier DefenseClaw") || !strings.Contains(got, current) {
		t.Fatalf("status did not name the earlier label: %q", got)
	}
	h.ops.status[h.alice.UID] = SandboxStatus{Active: true}
	requireOK(t, h.run(Options{Action: ActionRepair}))
	want := []string{
		"launchctl bootout gui/" + strconv.Itoa(h.alice.UID) + "/" + labelSandbox,
		"launchctl bootstrap gui/" + strconv.Itoa(h.alice.UID) + " " + h.env.P("/Library/LaunchAgents/"+current+".plist"),
	}
	if !reflect.DeepEqual(f.mutated, want) {
		t.Fatalf("idle account: mutations %v, want %v", f.mutated, want)
	}
}

// installedAgentLabel is base tagged with the installed gateway's SHA-256.
func installedAgentLabel(t *testing.T, h *osHost, base string) string {
	t.Helper()
	digest, err := sha256File(h.env.P(filepath.Join(h.env.Layout.BinDir, binGateway)))
	if err != nil {
		t.Fatal(err)
	}
	return base + "." + digest[:12]
}

// listingRunner adds the services listing of `launchctl print <domain>`.
type listingRunner struct {
	bootoutRunner
	listings map[string]string
}

func (r listingRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	if name == "launchctl" && len(args) == 2 && args[0] == "print" && r.listings[args[1]] != "" {
		return CommandResult{Stdout: []byte(r.listings[args[1]])}, nil
	}
	return r.bootoutRunner.Run(ctx, name, args...)
}

// The uninstall boots out the jobs of every label of both agents: the
// installed one, the bare one and an earlier tagged one the domain lists.
func TestUninstallBootsOutTheAgentsOfEveryLabel(t *testing.T) {
	h := newOSHost(t, "darwin")
	requireOK(t, h.ensure(sandboxConfig(t, "darwin", true, setupVMSettings)))
	current := installedAgentLabel(t, h, labelSandbox)
	earlier := labelSandbox + ".aaaaaaaaaaaa"
	var calls []string
	runner := listingRunner{
		bootoutRunner: bootoutRunner{
			Runner: h.env.Runner,
			ps:     "  0\n  501\n",
			mu:     &sync.Mutex{},
			loaded: map[string]bool{"user/501/" + current: true, "user/501/" + earlier: true, "user/501/" + labelOpenShellGateway: true},
			calls:  &calls,
		},
		listings: map[string]string{"user/501": "user/501 = {\n\tservices = {\n\t\t0 -\t" + earlier + "\n\t\t0 -\t" + labelOpenShellGateway + "\n\t}\n}\n"},
	}
	h.env.Runner = runner
	requireOK(t, h.run(Options{Action: ActionUninstall}))
	if len(runner.loaded) != 0 {
		t.Fatalf("still loaded: %v (calls %v)", runner.loaded, calls)
	}
}

// Stopping an account stops the jobs of an earlier label too.
func TestCommandOpsMacOSStopsEveryLabel(t *testing.T) {
	const earlier = labelSandbox + ".aaaaaaaaaaaa"
	ops, runner, alice := opsHost(t, "darwin", func(line string) (CommandResult, error) {
		switch line {
		case "launchctl print gui/1001":
			return CommandResult{}, os.ErrNotExist
		case "launchctl print user/1001":
			return CommandResult{Stdout: []byte("user/1001 = {\n\tservices = {\n\t\t812 -\t" + earlier + "\n\t}\n}\n")}, nil
		case "launchctl print user/1001/" + earlier:
			return CommandResult{Stdout: []byte(earlier + " = {\n\tstate = running\n}\n")}, nil
		}
		return CommandResult{}, nil
	})
	if !ops.unitRunning(context.Background(), alice, userUnitSandboxService, labelSandbox) {
		t.Fatalf("the running daemon of the earlier label is not seen: %v", runner.calls)
	}
	runner.calls = nil
	if err := ops.Stop(context.Background(), alice, StopDaemon|StopKill); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"launchctl kill SIGKILL user/1001/" + earlier, "launchctl bootout user/1001/" + labelSandbox, "launchctl bootout user/1001/" + earlier} {
		if !runner.called(want) {
			t.Errorf("missing %q in %v", want, runner.calls)
		}
	}
}

// The macOS stop sync runs as the account, the sync the Linux unit's second
// ExecStop runs (GAP-0380); a gateway agent that does not run is not asked.
func TestCommandOpsMacOSSyncsTheMicroVMsOfARunningGateway(t *testing.T) {
	running := true
	ops, runner, alice := opsHost(t, "darwin", func(line string) (CommandResult, error) {
		switch line {
		case "launchctl print gui/1001":
			return CommandResult{}, os.ErrNotExist
		case "launchctl print user/1001":
			return CommandResult{Stdout: []byte("user/1001 = {\n\tservices = {\n\t\t812 -\t" + labelOpenShellGateway + "\n\t}\n}\n")}, nil
		case "launchctl print user/1001/" + labelOpenShellGateway:
			if running {
				return CommandResult{Stdout: []byte(labelOpenShellGateway + " = {\n\tstate = running\n}\n")}, nil
			}
			return CommandResult{Stdout: []byte(labelOpenShellGateway + " = {\n\tstate = not running\n}\n")}, nil
		}
		return CommandResult{}, nil
	})
	const syncCall = "sandbox-daemon sync-sandboxes --managed"
	ops.syncBeforeGatewayStop(context.Background(), alice)
	found := false
	for _, c := range runner.calls {
		if strings.HasSuffix(c, syncCall) {
			found = true
			if !strings.HasPrefix(c, "sudo -n -u alice -H /usr/bin/env HOME=/Users/alice ") {
				t.Fatalf("the sync does not run as the account: %q", c)
			}
		}
	}
	if !found {
		t.Fatalf("no sync: %v", runner.calls)
	}
	running = false
	runner.calls = nil
	ops.syncBeforeGatewayStop(context.Background(), alice)
	if runner.called(syncCall) {
		t.Fatalf("a gateway that does not run was synced: %v", runner.calls)
	}
}
