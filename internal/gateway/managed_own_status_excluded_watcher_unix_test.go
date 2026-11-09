// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The watcher retires machine admission and keeps the pinned vendor source in
// separate steps. In between, the pinned vendor hook still sends the calls of
// an excluded account, whether the authorizer admits it (exempt_users) or
// refuses it (no exemption, no ledger target, in either unenrolled_users
// mode), so the status must not say nothing inspects them.
func TestOwnStatusExcludedWatcherRetiresAdmissionBeforePinnedHook(t *testing.T) {
	for _, tc := range []struct {
		name   string
		exempt bool
		deny   bool
	}{
		{"exempt account", true, false},
		{"unexempt account, inspect", false, false},
		{"unexempt account, deny", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) { watcherRetiresAdmissionBeforePinnedHook(t, tc.exempt, tc.deny) })
	}
}

// watcherRig is a gateway whose watcher publishes the view of a real vendor
// machine hook under a temp root, with the runtime descriptor and the live
// config generation under the test's control.
type watcherRig struct {
	api        *APIServer
	authorizer *managedHookAuthorizer
	watch      *managedPolicyViewWatch
	cfg        *config.Config
	live       *Generation
	descriptor *managed.RuntimeDescriptor
	hookFile   string
	lost       bool // the runtime descriptor can no longer be loaded
	path       string
}

func newWatcherRig(t *testing.T, exempt, deny bool) *watcherRig {
	t.Helper()
	opts, dir := claudePolicyViewTestRoot(t, "linux")
	rig := &watcherRig{
		descriptor: &managed.RuntimeDescriptor{MachinePolicyConnectors: []string{"claudecode"}},
		cfg:        &config.Config{DeploymentMode: "managed_enterprise"},
		hookFile:   filepath.Join(dir, "managed-settings.d", enterprisepolicy.DefenseClawDropInName),
	}
	rig.cfg.Enterprise.Profile = managed.ProfileStandalone
	rig.cfg.Enterprise.Enrollment.ExcludeUsers = []string{"carol"}
	if exempt {
		rig.cfg.Enterprise.Enrollment.ExemptUsers = []string{"carol"}
	}
	if deny {
		rig.cfg.Enterprise.Enrollment.UnenrolledUsers = config.EnterpriseUnenrolledDeny
	}
	rig.cfg.Guardrail.Enabled = true
	rig.cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"claudecode": {}}
	rig.live = &Generation{N: 1, ConfigGen: 1, ConfigGenRecorded: true, Config: rig.cfg}
	savedDescriptor, savedOptions := loadStandaloneRuntimeDescriptor, managedPolicyViewOptions
	loadStandaloneRuntimeDescriptor = func(string) (*managed.RuntimeDescriptor, error) {
		if rig.lost {
			return nil, errors.New("runtime descriptor removed")
		}
		copied := *rig.descriptor
		return &copied, nil
	}
	managedPolicyViewOptions = func(string) (enterprisepolicy.Options, string, bool) { return opts, "", true }
	t.Cleanup(func() { loadStandaloneRuntimeDescriptor, managedPolicyViewOptions = savedDescriptor, savedOptions })
	descriptorPath := filepath.Join(t.TempDir(), "runtime.json")
	rig.path = descriptorPath
	rig.authorizer = newManagedHookAuthorizer(rig.cfg.Enterprise.Enrollment, nil,
		func() (managedHookLedger, error) { return managedHookLedger{}, nil })
	rig.api = NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, rig.cfg)
	rig.api.SetGenerationSource(func() *Generation { return rig.live })
	rig.api.managedHookAuthz.Store(rig.authorizer)
	rig.watch = &managedPolicyViewWatch{api: rig.api, authorizer: rig.authorizer, goos: "linux", opts: opts, descriptorPath: descriptorPath}
	publishPolicyViewTestConnector(t, opts, "claudecode")
	pinPolicyView(t, opts, rig.descriptor)
	if err := os.WriteFile(descriptorPath, []byte("version one"), 0o600); err != nil {
		t.Fatal(err)
	}
	rig.watch.refresh()
	if !rig.authorizer.machinePolicy.Load().connectors["claudecode"] || !rig.api.managedPolicyView.Load().provenHook("claudecode", "carol") {
		t.Fatal("initial admission and pinned hook are required")
	}
	return rig
}

// retire drops the connector from the live config generation, as an
// administrator does, and lets the watcher follow.
func (r *watcherRig) retire() {
	retired := *r.cfg
	retired.Enterprise.MachinePolicy.Connectors = map[string]config.EnterpriseConnectorPolicy{
		"claudecode": {Ownership: config.MachinePolicyOwnershipOff},
	}
	r.live = &Generation{N: 2, ConfigGen: 2, ConfigGenRecorded: true, Config: &retired}
	r.watch.refresh()
}

func watcherRetiresAdmissionBeforePinnedHook(t *testing.T, exempt, deny bool) {
	rig := newWatcherRig(t, exempt, deny)
	rig.retire()
	view := rig.api.managedPolicyView.Load()
	if rig.authorizer.machinePolicy.Load().connectors["claudecode"] || view == nil || !view.provenHook("claudecode", "carol") || view.admitted["claudecode"] {
		t.Fatalf("watcher must have retired admission but kept the pinned source: machine=%v view=%+v", rig.authorizer.machinePolicy.Load().connectors, view)
	}
	decision := rig.authorizer.decide(managedHookPeer{UID: 5003, Name: "carol"}, "claudecode", "")
	if exempt && (!decision.Allow || !decision.Exempt) || !exempt && (decision.Allow || decision.Reason != managedHookReasonUIDUnregistered) {
		t.Fatalf("authorizer decision = %+v, want an exempt allow when exempt, else an unregistered refusal", decision)
	}
	rows, _ := ownExcludedRowsOf(t, rig.api, "uid", "5003", "carol")
	requireExcludedReason(t, "claudecode", rows["claudecode"], inspectedCode, inspectedReason)
}

// The runtime descriptor and the admission are not the vendor hook: once both
// are gone the hook can still be installed, and it then refuses its calls. The
// status says DefenseClaw does not inspect the calls only when the vendor files
// were read and hold no hook.
func TestOwnStatusExcludedAfterDescriptorAndAdmissionAreGone(t *testing.T) {
	for _, deny := range []bool{false, true} {
		name := "inspect"
		if deny {
			name = "deny"
		}
		t.Run(name, func(t *testing.T) {
			rig := newWatcherRig(t, false, deny)
			rig.retire()
			rig.lost = true
			if err := os.WriteFile(rig.path, []byte("descriptor removed, stamp moved"), 0o600); err != nil {
				t.Fatal(err)
			}
			rig.watch.refresh()
			if rig.api.managedPolicyView.Load() != nil || rig.authorizer.machinePolicy.Load().connectors["claudecode"] {
				t.Fatal("the view and the admission must both be gone")
			}
			rows, _ := ownExcludedRowsOf(t, rig.api, "uid", "5003", "carol")
			requireExcludedReason(t, "vendor hook still installed", rows["claudecode"], unknownCode, unknownReason)

			// The registration changed in a field the exact ownership check
			// compares (an argument here, the timeout for Codex): the vendor
			// still runs the command, so the status still cannot say none.
			registered, err := os.ReadFile(rig.hookFile)
			if err != nil {
				t.Fatal(err)
			}
			drifted := strings.ReplaceAll(string(registered), `"--enterprise-managed"`, `"--enterprise-managed", "--changed"`)
			if drifted == string(registered) {
				t.Fatal("the drift changed nothing")
			}
			if err := os.WriteFile(rig.hookFile, []byte(drifted), 0o644); err != nil {
				t.Fatal(err)
			}
			rows, _ = ownExcludedRowsOf(t, rig.api, "uid", "5003", "carol")
			requireExcludedReason(t, "vendor hook registration drifted", rows["claudecode"], unknownCode, unknownReason)

			// Benign twin: the vendor hook is gone too, so nothing inspects the calls.
			if err := os.Remove(rig.hookFile); err != nil {
				t.Fatal(err)
			}
			rows, _ = ownExcludedRowsOf(t, rig.api, "uid", "5003", "carol")
			requireExcludedReason(t, "vendor hook removed", rows["claudecode"], nothingCode, nothingReason)
		})
	}
}

// The absence proof reads the vendor files the view options name, whatever
// platform the caller reports: on macOS the own status passes the host
// platform while the view options hold the managed tree. An installed vendor
// hook is never called absent, and a tree that holds none is.
func TestMachineHookAbsentReadsTheViewOptionsTree(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			rig := newWatcherRig(t, false, false)
			if machineHookAbsent(goos, rig.cfg, "claudecode") {
				t.Fatalf("an installed vendor hook was called absent for caller platform %s", goos)
			}
			if err := os.Remove(rig.hookFile); err != nil {
				t.Fatal(err)
			}
			if !machineHookAbsent(goos, rig.cfg, "claudecode") {
				t.Fatalf("a tree holding no vendor hook must be absent for caller platform %s", goos)
			}
		})
	}
}
