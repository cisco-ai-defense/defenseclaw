// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// The single-app MDM command line: Setup /ensure with a staging CONFIG= and
// the first signed BUNDLE= with its TRUSTANCHORS=. Setup refused it before
// ("BUNDLE= cannot be combined with CONFIG="), so an MDM needed a base app
// and a bundle app that depends on it.
func TestStandaloneSetupAcceptsTheSingleAppEnsure(t *testing.T) {
	for _, arguments := range [][]string{
		{"/ensure", `CONFIG=C:\k\config.yaml`, `BUNDLE=C:\k\policy.dcbundle`, `TRUSTANCHORS=C:\k\bundle-anchors.json`, "JSON=1"},
		{"/ensure", `BUNDLE=C:\k\policy.dcbundle`, `CONFIG=C:\k\config.yaml`, `MANIFEST=C:\k\targets.yaml`, "JSON=1"},
	} {
		opts, _, err := parseStandaloneEnterpriseSetupOptions(arguments)
		if err != nil || !standaloneFirstBundleRequested(opts) {
			t.Fatalf("standalone %v: err %v, opts %+v; want the single-app form", arguments, err, opts)
		}
	}
	for _, arguments := range [][]string{
		{"/ensure", `BUNDLE=C:\k\policy.dcbundle`, "--mode=action", "--connector=codex"},
		{"/install", `CONFIG=C:\k\config.yaml`, `MANIFEST=C:\k\targets.yaml`, `BUNDLE=C:\k\policy.dcbundle`},
	} {
		if _, _, err := parseStandaloneEnterpriseSetupOptions(arguments); err == nil {
			t.Errorf("standalone %v was accepted", arguments)
		}
	}
}

func TestSingleAppFirstInstallStagesStoppedThenAppliesTheBundle(t *testing.T) {
	opts, _, err := parseStandaloneEnterpriseSetupOptions([]string{"/ensure", `CONFIG=C:\k\config.yaml`, `MANIFEST=C:\k\targets.yaml`,
		`BUNDLE=C:\k\policy.dcbundle`, `TRUSTANCHORS=C:\k\bundle-anchors.json`, "REFUSECAPABILITYLOSS=1", "JSON=1"})
	if err != nil {
		t.Fatal(err)
	}
	opts.Standalone = true
	plan := planStandaloneEnsure(opts, false)
	if len(plan.steps) != 2 || plan.rollback == nil {
		t.Fatalf("first install plan = %+v", plan)
	}
	stage, apply := plan.steps[0], plan.steps[1]
	if stage.name != "stage" || stage.opts.Action != "ensure" || !stage.opts.NoStart || stage.opts.Config != `C:\k\config.yaml` ||
		stage.opts.Manifest != `C:\k\targets.yaml` || stage.opts.Bundle != "" || stage.opts.TrustAnchors != "" || stage.opts.RefuseCapabilityLoss {
		t.Fatalf("stage run = %+v; want CONFIG= and MANIFEST= with NOSTART=1 and no bundle input", stage.opts)
	}
	if apply.name != "apply" || apply.opts.Action != "ensure" || apply.opts.NoStart || apply.opts.Config != "" || apply.opts.Manifest != "" ||
		apply.opts.Bundle != `C:\k\policy.dcbundle` || apply.opts.TrustAnchors != `C:\k\bundle-anchors.json` || !apply.opts.RefuseCapabilityLoss {
		t.Fatalf("apply run = %+v; want BUNDLE= and TRUSTANCHORS= only, services started", apply.opts)
	}
	if plan.rollback.Action != "uninstall" || plan.rollback.Purge || plan.rollback.Force || !plan.rollback.Standalone {
		t.Fatalf("rollback run = %+v", *plan.rollback)
	}
	installed := planStandaloneEnsure(opts, true)
	if len(installed.steps) != 1 || installed.rollback != nil || installed.steps[0].opts.Config != "" ||
		installed.steps[0].opts.Bundle == "" || installed.steps[0].opts.NoStart {
		t.Fatalf("installed computer plan = %+v; want the bundle run alone", installed)
	}
	plain := opts
	plain.Bundle, plain.TrustAnchors, plain.RefuseCapabilityLoss = "", "", false
	if got := planStandaloneEnsure(plain, false); len(got.steps) != 1 || got.steps[0].name != "" || got.rollback != nil || got.steps[0].opts.NoStart {
		t.Fatalf("plain /ensure CONFIG= plan = %+v; want one unchanged run", got)
	}
}

// mdmDevice models what the issue measured: one managed-hook sample per
// lifecycle boundary and per MDM wait. The managed hook answers a marker
// tool call ALLOW only while a gateway runs on the unsigned base config
// (which does not carry the signed bundle rule); with no running gateway it
// refuses (DENY); with no deployment there is no hook.
type mdmDevice struct {
	installed, running bool
	signed             bool
	// failApply makes the next bundle apply fail (a bad first bundle, or an
	// apply that fails as GAP-0104 did); failUninstall the next uninstall.
	failApply, failUninstall int
	samples                  []string
	runs                     []string
}

func (d *mdmDevice) sample(phase string) {
	verdict := "NOHOOK"
	switch {
	case d.installed && d.running && !d.signed:
		verdict = "ALLOW"
	case d.installed:
		verdict = "DENY"
	}
	d.samples = append(d.samples, phase+"="+verdict)
}

func (d *mdmDevice) result(ok bool, code string) (enterpriseLifecycleChildRun, error) {
	document := map[string]any{"schema_version": 2, "ok": ok, "action": "ensure", "installed": d.installed, "errors": []map[string]string{}}
	var runErr error
	if !ok {
		document["errors"] = []map[string]string{{"code": code, "message": code}}
		runErr = errors.New("exit status 1603")
	}
	raw, _ := json.Marshal(document)
	return enterpriseLifecycleChildRun{output: append(raw, 0x0a), runErr: runErr}, nil
}

// lifecycle applies one lifecycle child run as the Windows lifecycle does:
// an ensure with a config installs and starts on it (or stages it stopped
// with NOSTART=1); an ensure with a bundle on a computer with no deployment
// is refused not_managed, and on an installed computer installs the bundle
// config and starts the services on it.
func (d *mdmDevice) lifecycle(opts enterpriseSetupOptions) (enterpriseLifecycleChildRun, error) {
	d.runs = append(d.runs, fmt.Sprintf("%s config=%t bundle=%t nostart=%t", opts.Action, opts.Config != "", opts.Bundle != "", opts.NoStart))
	switch {
	case opts.Action == "uninstall":
		if d.failUninstall > 0 {
			d.failUninstall--
			return d.result(false, "uninstall_failed")
		}
		d.installed, d.running, d.signed = false, false, false
		document, _ := json.Marshal(map[string]any{"schema_version": 2, "ok": true, "action": "uninstall", "installed": false})
		return enterpriseLifecycleChildRun{output: document}, nil
	case opts.Bundle != "" && !d.installed:
		return d.result(false, "not_managed")
	case opts.Bundle != "":
		if d.failApply > 0 {
			d.failApply--
			return d.result(false, "bundle_apply_failed")
		}
		d.signed, d.running = true, !opts.NoStart
		d.sample("bundle-applied")
		return d.result(true, "")
	case opts.Config != "":
		if !d.installed {
			d.installed, d.signed = true, false
		}
		d.running = !opts.NoStart
		d.sample("config-installed")
		return d.result(true, "")
	}
	return d.result(false, "invalid_arguments")
}

// deliver runs one MDM app install command (one Setup run) on the device.
func (d *mdmDevice) deliver(t *testing.T, arguments ...string) enterpriseLifecycleChildRun {
	t.Helper()
	opts, _, err := parseStandaloneEnterpriseSetupOptions(append(arguments, "JSON=1"))
	if err != nil {
		t.Fatalf("Setup %v refused its command line: %v", arguments, err)
	}
	opts.Standalone = true
	run, _, err := runStandaloneEnsurePlan(planStandaloneEnsure(opts, d.installed), d.lifecycle)
	if err != nil {
		t.Fatal(err)
	}
	// The MDM waits before its next app or retry (14 to 27 minutes in the
	// measured lane); the hook keeps answering meanwhile.
	d.sample("mdm-wait")
	return run
}

func allows(samples []string) int {
	n := 0
	for _, sample := range samples {
		if strings.HasSuffix(sample, "=ALLOW") {
			n++
		}
	}
	return n
}

const (
	kitConfig  = `CONFIG=C:\k\config.yaml`
	kitBundle  = `BUNDLE=C:\k\policy.dcbundle`
	kitAnchors = `TRUSTANCHORS=C:\k\bundle-anchors.json`
)

// The two-app recipe (base app, then a bundle app that depends on it) is the
// delivery order of the issue: the device enforces the unsigned base config
// from hook-live until the bundle app runs, and longer when the first bundle
// apply fails and the MDM waits to retry. The model must show that window,
// or it proves nothing about the single-app order below.
func TestTwoAppDeliveryOrderLeavesAnUnsignedPolicyWindow(t *testing.T) {
	d := &mdmDevice{}
	d.deliver(t, "/ensure", kitConfig)
	d.deliver(t, "/ensure", kitBundle, kitAnchors)
	if allows(d.samples) == 0 {
		t.Fatalf("two-app order: no unsigned-policy window in %v", d.samples)
	}
	retry := &mdmDevice{failApply: 1}
	retry.deliver(t, "/ensure", kitConfig)
	retry.deliver(t, "/ensure", kitBundle, kitAnchors)
	retry.deliver(t, "/ensure", kitBundle, kitAnchors)
	if allows(retry.samples) <= allows(d.samples) {
		t.Fatalf("a failed first apply must widen the two-app window: %v", retry.samples)
	}
}

// The single-app order never runs a service on unsigned policy, in every
// MDM delivery order: a first install, a failed first apply that the MDM
// retries as a whole, a rollback that also fails, a repeated delivery and a
// later bundle version delivered by the same app.
func TestSingleAppDeliveryNeverRunsOnUnsignedPolicy(t *testing.T) {
	single := []string{"/ensure", kitConfig, kitBundle, kitAnchors}
	for _, tc := range []struct {
		name                     string
		failApply, failUninstall int
		deliveries               int
		wantRuns                 []string
		wantErrors               []string
	}{
		{name: "first install", deliveries: 1, wantRuns: []string{
			"ensure config=true bundle=false nostart=true", "ensure config=false bundle=true nostart=false"}},
		{name: "failed first apply, MDM retries the whole install", failApply: 1, deliveries: 2, wantRuns: []string{
			"ensure config=true bundle=false nostart=true", "ensure config=false bundle=true nostart=false", "uninstall config=false bundle=false nostart=false",
			"ensure config=true bundle=false nostart=true", "ensure config=false bundle=true nostart=false"},
			wantErrors: []string{"bundle_apply_failed", "first_install_rolled_back"}},
		{name: "rollback fails too, next delivery completes the staged install", failApply: 1, failUninstall: 1, deliveries: 2, wantRuns: []string{
			"ensure config=true bundle=false nostart=true", "ensure config=false bundle=true nostart=false", "uninstall config=false bundle=false nostart=false",
			"ensure config=false bundle=true nostart=false"},
			wantErrors: []string{"bundle_apply_failed", "first_install_rollback_failed"}},
		{name: "repeated delivery and a later bundle", deliveries: 3, wantRuns: []string{
			"ensure config=true bundle=false nostart=true", "ensure config=false bundle=true nostart=false",
			"ensure config=false bundle=true nostart=false", "ensure config=false bundle=true nostart=false"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &mdmDevice{failApply: tc.failApply, failUninstall: tc.failUninstall}
			var first enterpriseLifecycleChildRun
			for i := 0; i < tc.deliveries; i++ {
				run := d.deliver(t, single...)
				if i == 0 {
					first = run
				}
			}
			if n := allows(d.samples); n != 0 {
				t.Fatalf("%d ALLOW samples on unsigned policy: %v", n, d.samples)
			}
			if !d.installed || !d.running || !d.signed {
				t.Fatalf("device did not end enforcing the signed bundle: %+v", d)
			}
			if strings.Join(d.runs, "\n") != strings.Join(tc.wantRuns, "\n") {
				t.Fatalf("lifecycle runs:\n%s\nwant:\n%s", strings.Join(d.runs, "\n"), strings.Join(tc.wantRuns, "\n"))
			}
			if tc.wantErrors != nil {
				var result struct {
					OK        bool `json:"ok"`
					Installed bool `json:"installed"`
					Errors    []struct {
						Code string `json:"code"`
					} `json:"errors"`
				}
				if err := json.Unmarshal(first.output, &result); err != nil || result.OK || first.runErr == nil {
					t.Fatalf("failed first delivery result %s (err %v, runErr %v)", first.output, err, first.runErr)
				}
				var codes []string
				for _, e := range result.Errors {
					codes = append(codes, e.Code)
				}
				if strings.Join(codes, ",") != strings.Join(tc.wantErrors, ",") {
					t.Fatalf("error codes %v, want %v", codes, tc.wantErrors)
				}
				if removed := tc.failUninstall == 0; result.Installed == removed {
					t.Fatalf("installed=%t after rollback (removed=%t): %s", result.Installed, removed, first.output)
				}
			}
		})
	}
}

func TestSingleAppRollbackNoteKeepsTextOutputReadable(t *testing.T) {
	got := string(annotateStandaloneFirstInstallRollback([]byte("bundle refused\n"), true))
	if !strings.HasPrefix(got, "bundle refused\n") || !strings.Contains(got, "removed the staged first install") {
		t.Fatalf("text output = %q", got)
	}
}
