// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package fleet

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// CheckBundles is the check id of the signed policy bundle state.
const CheckBundles = "bundle_state"

// The states of a stage's bundle.
const (
	// BundleVerified: the bundle verifies against the current trust anchors.
	BundleVerified = "verified"
	// BundleUnverified: it no longer does (Problem is the code); the
	// controller no longer enforces it.
	BundleUnverified = "unverified"
	// BundleUnchecked: it could not be verified from here (Bundles.Note).
	BundleUnchecked = "unchecked"
)

// Bundles is what the CLI read of the signed policy bundles (GAP-0429,
// GAP-0432): every stage with the bundle in force there, re-verified against
// the current trust anchors as the controller does on every pass. Note says
// why the stages could not be verified from here ("" when they were).
// Managed is a managed install: there a stage that no longer verifies keeps
// only the DefenseClaw rule, else its atespaces fall back to config.yaml.
type Bundles struct {
	Stages  []BundleStage
	Note    string
	Managed bool
}

// BundleStage is one stage and its active bundle, as the status and verify
// documents carry it. ReceiptID names the apply receipt (ReceiptID); Source says where the apply came from, so a bundle
// delivered by another source (a registry) fills the same fields.
type BundleStage struct {
	Stage          string   `json:"stage"`
	Atespaces      []string `json:"atespaces"`
	BundleID       string   `json:"bundle_id"`
	Version        uint64   `json:"version"`
	KeyID          string   `json:"key_id"`
	ManifestSHA256 string   `json:"manifest_sha256"`
	AppliedAt      string   `json:"applied_at"`
	Source         string   `json:"source"`
	ReceiptID      string   `json:"receipt_id"`
	State          string   `json:"state"`
	Problem        string   `json:"problem,omitempty"`
}

// ReceiptID names an apply receipt, which carries no id of its own: r- and
// the first 16 hex digits of the SHA-256 of applied_at, source, stage and
// manifest_sha256 joined with newlines. Anyone holding the receipt can
// compute it, whatever the source.
func ReceiptID(appliedAt, source, stage, manifestSHA256 string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{appliedAt, source, stage, manifestSHA256}, "\n")))
	return "r-" + hex.EncodeToString(sum[:8])
}

// bundleStages is the documents' bundles member: nil (left out) when
// bundles are off, never null when they are on.
func bundleStages(o Observed) []BundleStage {
	if o.Bundles == nil {
		return nil
	}
	return append([]BundleStage{}, o.Bundles.Stages...)
}

// CheckBundleState: every stage's bundle still verifies against the trust
// anchors. One that does not is no longer enforced, and only the
// controller's log said so (GAP-0429).
func CheckBundleState(o Observed) Check {
	b := o.Bundles
	if b == nil {
		return result(CheckBundles, Skip, "", "signed policy bundles are off (substrate.bundles.enabled)")
	}
	var bad, unchecked []string
	for _, s := range b.Stages {
		switch s.State {
		case BundleUnverified:
			bad = append(bad, fmt.Sprintf("stage %s (%s version %d, key %s): %s", s.Stage, s.BundleID, s.Version, s.KeyID, s.Problem))
		case BundleUnchecked:
			unchecked = append(unchecked, s.Stage)
		}
	}
	switch {
	case len(bad) > 0:
		then := "its atespaces fall back to config.yaml"
		if b.Managed {
			then = "its atespaces keep only the DefenseClaw rule (deny-only)"
		}
		return result(CheckBundles, Fail, "", "%d stage bundle(s) no longer verify against the trust anchors, so %s until a "+
			"trusted bundle is applied: %s. Apply a bundle signed with a key in the current anchors (defenseclaw substrate "+
			"bundle apply FILE), or put the trust anchors Secret back", len(bad), then, strings.Join(bad, "; "))
	case len(b.Stages) == 0 && b.Note != "":
		return result(CheckBundles, Warn, "", "the bundle state could not be read from here (%s)", b.Note)
	case len(unchecked) > 0:
		return result(CheckBundles, Warn, "", "the bundles of %d stage(s) (%s) could not be verified from here (%s)", len(unchecked),
			strings.Join(unchecked, ", "), b.Note)
	case len(b.Stages) == 0:
		return result(CheckBundles, Pass, "", "no bundle is applied: every atespace uses config.yaml")
	}
	return result(CheckBundles, Pass, "", "%d stage(s) enforce bundles that verify against the trust anchors", len(b.Stages))
}
