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
		floor = ref.ConfigGeneration
		matched = &Receipt{BundleID: ref.BundleID, Version: ref.Version, Principal: manifest.CreatedBy,
			SignerKeyID: ref.SignerKeyID, ChangeSummary: manifest.ChangeSummary}
	}
	opt, ok := GenerationOptions(matched)
	if !ok {
		return opt, false, fmt.Errorf("policy bundle %s has no principal", matched.ReceiptID)
	}
	opt.GenerationFloor = floor
	return opt, true, nil
}

// stagedGenerationOwner picks, of the staged receipts whose rendered config
// is these bytes (sum), the one whose signed identity the generation record
// takes. Several can match: a retry of a bundle whose committed receipt waits
// behind a gateway outage, or another signed bundle that renders the same
// settings. The record already naming one of them for these bytes keeps it
// (a pending commit is never re-attributed); receipts of one signed identity
// record the same attribution; otherwise the delivery this process installs
// (CurrentReceiptID) owns the bytes. Any other overlap is refused.
func (d *Driver) stagedGenerationOwner(staged []*Receipt, sum string) (*Receipt, error) {
	if len(staged) <= 1 {
		if len(staged) == 0 {
			return nil, nil
		}
		return staged[0], nil
	}
	if d.ConfigPath != "" {
		if record, err := configwrite.ReadGenerationState(d.ConfigPath); err == nil && strings.EqualFold(record.ConfigSHA256, sum) {
			for _, rc := range staged {
				if record.BundleID == rc.BundleID && record.BundleVersion == rc.Version &&
					record.SignerKeyID == rc.SignerKeyID && record.Actor == rc.Principal {
					return rc, nil
				}
			}
		}
	}
	same := true
	for _, rc := range staged[1:] {
		same = same && sameGenerationIdentity(staged[0], rc)
	}
	if same {
		return staged[0], nil
	}
	for _, rc := range staged {
		if d.CurrentReceiptID != "" && rc.ReceiptID == d.CurrentReceiptID {
			return rc, nil
		}
	}
	return nil, fmt.Errorf("multiple staged policy bundles match installed config")
}

// sameGenerationIdentity reports receipts whose GenerationOptions record the
// same bundle attribution.
func sameGenerationIdentity(a, b *Receipt) bool {
	return a.BundleID == b.BundleID && a.Version == b.Version && a.Principal == b.Principal &&
		a.SignerKeyID == b.SignerKeyID && a.ChangeSummary == b.ChangeSummary
}
