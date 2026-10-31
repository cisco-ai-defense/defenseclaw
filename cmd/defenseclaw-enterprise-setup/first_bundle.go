// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"strings"
)

// A standalone /ensure that carries both CONFIG= and BUNDLE= is the one
// command an MDM delivers as a single app. On a computer with no standalone
// deployment it is a first install whose first enforced policy is the signed
// bundle, in three lifecycle runs of one Setup process:
//
//  1. stage: ensure CONFIG= [MANIFEST=] NOSTART=1 installs the payload with
//     every service stopped and disabled. No gateway runs on the staging
//     config, so no hook decision is ever made under it: a managed hook whose
//     gateway does not run refuses the call.
//  2. apply: ensure BUNDLE= [TRUSTANCHORS=] verifies the bundle, installs its
//     config (and the anchors) and starts the services on it, then confirms
//     the bundle against the running gateway.
//  3. When the apply fails, Setup removes the staged deployment (uninstall)
//     and fails, so the MDM retries the whole install.
//
// On an installed computer the same command line delivers the bundle only:
// CONFIG= and MANIFEST= are the first install staging inputs, so later
// bundle versions ship as the same app with no app dependency.

// standaloneEnsureStep is one lifecycle run of a standalone Setup /ensure.
type standaloneEnsureStep struct {
	// name is "stage" or "apply" for the single-app form, "" for a plain run.
	name string
	opts enterpriseSetupOptions
}

// standaloneEnsurePlan is the lifecycle runs of one standalone Setup run, in
// order, and the run that removes a staged first install when a later run
// fails (nil when nothing is staged).
type standaloneEnsurePlan struct {
	steps    []standaloneEnsureStep
	rollback *enterpriseSetupOptions
}

// standaloneFirstBundleRequested reports the single-app form: /ensure with
// both a staging CONFIG= and a signed BUNDLE=.
func standaloneFirstBundleRequested(opts enterpriseSetupOptions) bool {
	return opts.Action == "ensure" && strings.TrimSpace(opts.Bundle) != "" && strings.TrimSpace(opts.Config) != ""
}

// planStandaloneEnsure splits a standalone Setup run into its lifecycle runs.
// installed is whether a standalone deployment (in any state but absent or
// removed) was there before the run.
func planStandaloneEnsure(opts enterpriseSetupOptions, installed bool) standaloneEnsurePlan {
	if !standaloneFirstBundleRequested(opts) {
		return standaloneEnsurePlan{steps: []standaloneEnsureStep{{opts: opts}}}
	}
	apply := opts
	apply.Config, apply.Manifest = "", ""
	if installed {
		return standaloneEnsurePlan{steps: []standaloneEnsureStep{{name: "apply", opts: apply}}}
	}
	stage := opts
	stage.Bundle, stage.TrustAnchors, stage.RefuseCapabilityLoss = "", "", false
	stage.NoStart = true
	rollback := enterpriseSetupOptions{
		Action:                 "uninstall",
		JSON:                   true,
		InstallRoot:            opts.InstallRoot,
		StateRoot:              opts.StateRoot,
		GatewayServiceName:     opts.GatewayServiceName,
		GuardianServiceName:    opts.GuardianServiceName,
		CertificationCodexHome: opts.CertificationCodexHome,
		AllowUnsigned:          opts.AllowUnsigned,
		LifecycleTimeout:       opts.LifecycleTimeout,
		Started:                opts.Started,
		AllowedSigners:         opts.AllowedSigners,
		Standalone:             opts.Standalone,
		StandaloneUnsigned:     opts.StandaloneUnsigned,
		ProductVersion:         opts.ProductVersion,
	}
	return standaloneEnsurePlan{
		steps:    []standaloneEnsureStep{{name: "stage", opts: stage}, {name: "apply", opts: apply}},
		rollback: &rollback,
	}
}

// runStandaloneEnsurePlan runs the lifecycle runs of plan in order with
// runChild and returns the run whose result is the result of this Setup run,
// and its options. A run that does not complete ends the plan: its own
// transaction rolled back. When the apply after a completed stage fails,
// the staged first install is removed first and the failed result names it.
func runStandaloneEnsurePlan(
	plan standaloneEnsurePlan,
	runChild func(enterpriseSetupOptions) (enterpriseLifecycleChildRun, error),
) (enterpriseLifecycleChildRun, enterpriseSetupOptions, error) {
	var lifecycle enterpriseLifecycleChildRun
	var last enterpriseSetupOptions
	staged := false
	for index, step := range plan.steps {
		run, err := runChild(step.opts)
		if err != nil {
			return run, step.opts, err
		}
		lifecycle, last = run, step.opts
		if index == len(plan.steps)-1 || run.timedOut || run.runErr != nil || len(run.output) > maximumLifecycleOutput {
			break
		}
		// A completed stage printed only its own result, which the lifecycle
		// log keeps; the result of this Setup run is the next run.
		staged = step.name == "stage"
	}
	if staged && plan.rollback != nil && !lifecycle.timedOut && lifecycle.runErr != nil {
		// The first bundle was not applied. Remove the staged install, which
		// never started a service, so the MDM retries the whole install. A
		// stopped (timed-out) apply is left to its own recovery: the staged
		// install keeps its services stopped and the next run completes it.
		rollback, err := runChild(*plan.rollback)
		removed := err == nil && !rollback.timedOut && rollback.runErr == nil && standaloneLifecycleResultOK(rollback.output)
		if len(lifecycle.output) <= maximumLifecycleOutput {
			lifecycle.output = annotateStandaloneFirstInstallRollback(lifecycle.output, removed)
		}
	}
	return lifecycle, last, nil
}

// standaloneFirstInstallRollbackMessage names what Setup did after the first
// signed bundle of a single-app first install was not applied.
func standaloneFirstInstallRollbackMessage(removed bool) (code, message string) {
	if removed {
		return "first_install_rolled_back", "the signed policy bundle was not applied, so Setup removed the staged first install (no service had started); run the same command again"
	}
	return "first_install_rollback_failed", "the signed policy bundle was not applied and Setup could not remove the staged first install; its services stay stopped and disabled and the next /ensure with BUNDLE= completes or replaces it"
}

// annotateStandaloneFirstInstallRollback adds the rollback outcome to the
// result of the failed apply run. A JSON result gets one more error (and
// installed false when the staged install is gone); text output gets a line.
func annotateStandaloneFirstInstallRollback(output []byte, removed bool) []byte {
	code, message := standaloneFirstInstallRollbackMessage(removed)
	trimmed := bytes.TrimSpace(output)
	var document map[string]json.RawMessage
	if len(trimmed) == 0 || trimmed[0] != 0x7b || json.Unmarshal(trimmed, &document) != nil {
		return append(append(append([]byte{}, output...), []byte(message)...), 0x0a)
	}
	var errs []map[string]string
	if raw, ok := document["errors"]; ok {
		_ = json.Unmarshal(raw, &errs)
	}
	errs = append(errs, map[string]string{"code": code, "message": message})
	if raw, err := json.Marshal(errs); err == nil {
		document["errors"] = raw
	}
	document["ok"] = json.RawMessage("false")
	if removed {
		document["installed"] = json.RawMessage("false")
	}
	annotated, err := json.Marshal(document)
	if err != nil {
		return output
	}
	return append(annotated, 0x0a)
}

// standaloneLifecycleResultOK reports whether a lifecycle child result (JSON
// output) says ok.
func standaloneLifecycleResultOK(output []byte) bool {
	document, _ := splitStandaloneLifecycleJSON(output)
	var result struct {
		OK bool `json:"ok"`
	}
	return json.Unmarshal(bytes.TrimSpace(document), &result) == nil && result.OK
}
