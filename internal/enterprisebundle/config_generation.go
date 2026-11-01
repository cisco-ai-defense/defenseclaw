// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
)

// ConfigGenerationOptions binds exact config bytes to an admitted bundle's
// principal. An ordinary administrator config has no bundle attribution.
func (d *Driver) ConfigGenerationOptions(raw []byte) (configwrite.Options, bool, error) {
	receipts, err := d.Store.Receipts()
	if err != nil {
		return configwrite.Options{}, false, err
	}
	sum := configwrite.SHA256Hex(raw)
	var staged []*Receipt
	for _, receipt := range receipts {
		if receipt.State == StateStaged && strings.EqualFold(receipt.ConfigSHA256, sum) {
			staged = append(staged, receipt)
		}
	}
	matched, err := d.stagedGenerationOwner(staged, sum)
	if err != nil {
		return configwrite.Options{}, false, err
	}
	var floor uint64
	dir := ""
	if matched == nil {
		current, ref, err := d.CurrentConfig()
		if err != nil {
			return configwrite.Options{}, false, err
		}
		if ref == nil || !bytes.Equal(current, raw) {
			return configwrite.Options{}, false, nil
		}
		bundle, err := d.Store.ReadVersion(ref)
		if err != nil {
			return configwrite.Options{}, false, err
		}
		manifest, err := DecodeManifest(bundle.Manifest)
		if err != nil {
			return configwrite.Options{}, false, err
		}
		if manifest.BundleID != ref.BundleID || manifest.Version != ref.Version || ref.SignerKeyID == "" {
			return configwrite.Options{}, false, fmt.Errorf("confirmed policy bundle identity is incomplete")
		}
		floor, dir = ref.ConfigGeneration, ref.Dir
		matched = &Receipt{BundleID: ref.BundleID, Version: ref.Version, Principal: manifest.CreatedBy,
			SignerKeyID: ref.SignerKeyID, ChangeSummary: manifest.ChangeSummary}
	}
	opt, ok := GenerationOptions(matched)
	if !ok {
		return opt, false, fmt.Errorf("policy bundle %s has no principal", matched.ReceiptID)
	}
	opt.GenerationFloor = floor
	if dir != "" {
		opt.Bundle.Dir = dir
	}
	return opt, true, nil
}

// stagedGenerationOwner picks, of the staged receipts whose rendered config
// is these bytes, the one whose signed identity the generation record
// takes. Several can match: a retry of a bundle whose committed receipt waits
// behind a gateway outage, or another signed bundle that renders the same
// settings. The delivery this process installs (CurrentReceiptID) owns the
// bytes; the installer child process Setup starts does not know it, and
// there the newest staged receipt is that delivery: a run holds the bundle
// lock from Prepare to Finish, the store numbers deliveries in order, and an
// older staged receipt is a pending commit of an earlier run. The record
// naming that pending commit used to keep the bytes, so a higher bundle
// with the same settings committed nothing of its own until the pending one
// settled (GAP-1187).
func (d *Driver) stagedGenerationOwner(staged []*Receipt, _ string) (*Receipt, error) {
	if len(staged) == 0 {
		return nil, nil
	}
	owner := staged[0]
	for _, rc := range staged[1:] {
		if rc.Sequence > owner.Sequence {
			owner = rc
		}
	}
	for _, rc := range staged {
		if d.CurrentReceiptID != "" && rc.ReceiptID == d.CurrentReceiptID {
			owner = rc
		}
	}
	return owner, nil
}
