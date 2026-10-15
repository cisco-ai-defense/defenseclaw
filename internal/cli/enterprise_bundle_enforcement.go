// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// bundleNotAppliedCode is the lifecycle error of a bundle-mode device whose
// confirmed signed policy bundle does not enforce: config.yaml is not the
// bundle's config, or the running gateway reports another policy. status,
// verify and every changing action report it, so an MDM health check never
// reads compliant while the gateway enforces a policy nobody signed
// (GAP-0114). ensure and repair re-apply the bundle first.
const bundleNotAppliedCode = "bundle_not_applied"

// bundleEnforcement is what decides whether the confirmed bundle of a
// bundle-mode device enforces. It is filled by the platform lifecycle and
// kept free of I/O so the decision is tested on every platform.
type bundleEnforcement struct {
	// Current is the confirmed bundle; nil when none is confirmed (a
	// base-only device, or bundle mode before the first bundle).
	Current *enterprisebundle.Ref
	// CurrentConfig is the config.yaml rendered from the current bundle in
	// the bundle store; nil when it could not be rendered (CurrentErr says
	// why).
	CurrentConfig []byte
	CurrentErr    error
	// InstalledConfig is the installed config.yaml; nil when it could not
	// be read.
	InstalledConfig []byte
	// GatewayReady says the gateway service is ready; Policy is the policy
	// block of the run, nil when the gateway was not asked.
	GatewayReady bool
	Policy       *enterprisestatus.PolicyState
}

// bundleLabel names the confirmed bundle in messages.
func bundleLabel(ref *enterprisebundle.Ref) string {
	return fmt.Sprintf("signed policy bundle %s version %d", ref.BundleID, ref.Version)
}

// ConfigReplaced reports a confirmed bundle whose rendered config is not the
// installed config.yaml: ensure and repair must re-apply the bundle from the
// bundle store before anything starts the gateway on the installed file.
func (e bundleEnforcement) ConfigReplaced() bool {
	return e.Current != nil && e.CurrentErr == nil && e.CurrentConfig != nil &&
		!bytes.Equal(e.CurrentConfig, e.InstalledConfig)
}

// Problem is why the confirmed bundle does not enforce, or "" when it does or
// when no bundle is confirmed. A gateway that is not ready is reported by
// the lifecycle's own readiness errors; the config is checked all the same.
func (e bundleEnforcement) Problem() string {
	if e.Current == nil {
		return ""
	}
	label := bundleLabel(e.Current)
	switch {
	case e.CurrentErr != nil || e.CurrentConfig == nil:
		detail := "it could not be rendered"
		if e.CurrentErr != nil {
			detail = boundedPolicyMessage(e.CurrentErr.Error())
		}
		return fmt.Sprintf("%s is confirmed, but its config cannot be read from the bundle store (%s), so the device cannot prove it enforces it; deliver the bundle again or a newer one", label, detail)
	case e.InstalledConfig == nil:
		return fmt.Sprintf("%s is confirmed, but the installed config.yaml cannot be read; run ensure to re-apply the bundle", label)
	case e.ConfigReplaced():
		return fmt.Sprintf("config.yaml is not the config of %s (it was changed outside the lifecycle), so the gateway does not enforce the signed policy; ensure re-applies the bundle from the bundle store", label)
	case !e.GatewayReady:
		return ""
	case e.Policy == nil || e.Policy.GatewayReportedDigest == "":
		return fmt.Sprintf("the running gateway did not report its policy, so %s is not confirmed as enforced", label)
	case e.Policy.LastReloadError != "":
		return fmt.Sprintf("the gateway rejected its last reload (%s) and keeps enforcing an earlier policy, not %s", e.Policy.LastReloadError, label)
	case !strings.EqualFold(e.Policy.GatewayReportedDigest, e.Current.EffectivePolicyDigest):
		return fmt.Sprintf("the gateway enforces effective policy %s, not %s of %s", enterprisestatus.ShortDigest(e.Policy.GatewayReportedDigest),
			enterprisestatus.ShortDigest(e.Current.EffectivePolicyDigest), label)
	}
	return ""
}

// bundleEnforcementCheckedAction reports the lifecycle actions whose result
// says whether the deployment is healthy, so they carry bundle_not_applied.
// Install has no bundle yet and uninstall removes the deployment.
func bundleEnforcementCheckedAction(action string) bool {
	switch action {
	case "status", "verify", "ensure", "repair", "upgrade":
		return true
	}
	return false
}
