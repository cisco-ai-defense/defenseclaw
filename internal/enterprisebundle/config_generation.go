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
	var matched *Receipt
	var floor uint64
	for _, receipt := range receipts {
		if receipt.State != StateStaged || !strings.EqualFold(receipt.ConfigSHA256, sum) {
			continue
		}
		if matched != nil {
			return configwrite.Options{}, false, fmt.Errorf("multiple staged policy bundles match installed config")
		}
		matched = receipt
	}
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
