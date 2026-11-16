// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// windowsHotBundleIdentity is the signed bundle the gateway must report
// (/health bundle ID and version) before ensure reports a hot-applied bundle
// config as adopted. A digest and a generation alone never prove it: they
// are the same for a config the record names as some other bundle.
//
// A new delivery names its verified receipt. A repeated delivery of the
// confirmed bundle has no receipt (Prepare discarded it): it names the
// confirmed current bundle, read again from the store, which must still
// render the config the run installs. written is the bundle the config
// record names after the write; it must be the same bundle. A run that
// cannot name one fails before anything is written. Any other run (no
// bundle) needs no identity: the zero BundleRef.
func windowsHotBundleIdentity(p *enterprisebundle.Prepared, written configwrite.BundleRef, current []byte, ref *enterprisebundle.Ref) (configwrite.BundleRef, error) {
	var want configwrite.BundleRef
	switch {
	case p == nil:
		return configwrite.BundleRef{}, nil
	case p.Receipt != nil:
		if !enterprisebundle.ValidBundleID(p.Receipt.BundleID) || p.Receipt.Version == 0 {
			return configwrite.BundleRef{}, fmt.Errorf("the staged policy bundle has no bundle ID and version")
		}
		want = configwrite.BundleRef{ID: p.Receipt.BundleID, Version: p.Receipt.Version}
	case p.AlreadyApplied:
		if ref == nil || !enterprisebundle.ValidBundleID(ref.BundleID) || ref.Version == 0 {
			return configwrite.BundleRef{}, fmt.Errorf("the bundle store has no confirmed current bundle to apply again")
		}
		if len(p.Config) == 0 || !bytes.Equal(current, p.Config) {
			return configwrite.BundleRef{}, fmt.Errorf("the confirmed bundle %s version %d no longer renders the config this run applies", ref.BundleID, ref.Version)
		}
		want = configwrite.BundleRef{ID: ref.BundleID, Version: ref.Version}
	default:
		return configwrite.BundleRef{}, nil
	}
	if written.ID != want.ID || written.Version != want.Version {
		return configwrite.BundleRef{}, fmt.Errorf("the config record would name bundle %q version %d, not bundle %s version %d",
			written.ID, written.Version, want.ID, want.Version)
	}
	return want, nil
}

// windowsHotConfigReportAdopted reports whether the installed CLI's policy
// digest (with --check-gateway) shows the gateway enforcing the installed
// config: the effective policy, no rejected reload, the recorded generation
// and, for a bundle config, that bundle's ID and version.
func windowsHotConfigReportAdopted(report policyDigestReport, bundle configwrite.BundleRef) bool {
	if bundle.ID != "" && (report.GatewayReportedBundleID != bundle.ID || report.GatewayReportedBundleVersion != bundle.Version) {
		return false
	}
	return report.Digest != "" && report.Digest == report.GatewayReportedDigest &&
		report.GatewayLastReloadError == "" && report.ConfigGeneration > 0 && report.ConfigGenerationRecorded &&
		report.GatewayReportedConfigGeneration == report.ConfigGeneration
}

// windowsBundleRollbackIdentity is the bundle a rollback to the confirmed
// bundle must see the gateway name: the confirmed reference, which the
// config record names too.
func windowsBundleRollbackIdentity(ref *enterprisebundle.Ref, written configwrite.BundleRef) (configwrite.BundleRef, error) {
	if ref == nil || !enterprisebundle.ValidBundleID(ref.BundleID) || ref.Version == 0 {
		return configwrite.BundleRef{}, errors.New("the confirmed rollback bundle has no bundle ID and version")
	}
	if written.ID != ref.BundleID || written.Version != ref.Version {
		return configwrite.BundleRef{}, fmt.Errorf("the config record would name bundle %q version %d, not the confirmed bundle %s version %d",
			written.ID, written.Version, ref.BundleID, ref.Version)
	}
	return configwrite.BundleRef{ID: ref.BundleID, Version: ref.Version}, nil
}
