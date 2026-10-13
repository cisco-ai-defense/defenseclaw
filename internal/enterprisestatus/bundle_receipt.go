// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	// PublicReceiptName is the public summary of the last finished policy
	// bundle receipt: <etc>/bundles/receipt.json. The enterprise lifecycle
	// writes it (mode 0644, no secrets, no error message) whenever a receipt
	// ends confirmed or failed; the gateway reads it to emit the
	// config.bundle.receipt audit event and the bundle metrics.
	PublicReceiptName = "receipt.json"
	// PublicReceiptSchemaVersion is the receipt.json schema.
	PublicReceiptSchemaVersion = 1

	maxPublicReceiptBytes = 16 << 10
)

// PublicReceipt is receipt.json. Decoding is lenient so an older gateway
// reads the file of a newer lifecycle; readers validate every field again.
type PublicReceipt struct {
	SchemaVersion int    `json:"schema_version"`
	ReceiptID     string `json:"receipt_id"`
	BundleID      string `json:"bundle_id,omitempty"`
	Version       uint64 `json:"version,omitempty"`
	SignerKeyID   string `json:"signer_key_id,omitempty"`
	// Principal is the manifest created_by (control-plane:<tenant>/<admin>
	// or operator:<os-admin>).
	Principal     string `json:"principal,omitempty"`
	ChangeSummary string `json:"change_summary,omitempty"`
	// State is BundleConfirmed or BundleFailed; ErrorCode is the closed
	// code of a failed receipt.
	State                 string   `json:"state"`
	ErrorCode             string   `json:"error_code,omitempty"`
	EffectivePolicyDigest string   `json:"effective_policy_digest,omitempty"`
	WarningCodes          []string `json:"warning_codes,omitempty"`
	EnforcingDigest       string   `json:"enforcing_digest,omitempty"`
	ConfigGeneration      uint64   `json:"config_generation,omitempty"`
	AppliedAt             string   `json:"applied_at,omitempty"`
	ConfirmedAt           string   `json:"confirmed_at,omitempty"`
	// FinishedAt is the time of the terminal transition.
	FinishedAt string `json:"finished_at"`
	RolledBack bool   `json:"rolled_back,omitempty"`
	Restart    bool   `json:"restart,omitempty"`
	// CurrentBundleID and CurrentVersion name the confirmed bundle that
	// enforces after this receipt (absent when none does).
	CurrentBundleID string `json:"current_bundle_id,omitempty"`
	CurrentVersion  uint64 `json:"current_version,omitempty"`
}

// PublicReceiptPath is receipt.json for the configuration directory
// configDir (the directory of config.yaml).
func PublicReceiptPath(configDir string) string {
	return filepath.Join(configDir, "bundles", PublicReceiptName)
}

// Key identifies one terminal receipt: a new delivery or a retry of the same
// bundle gets a new key.
func (r PublicReceipt) Key() string {
	return r.ReceiptID + "|" + r.State + "|" + r.FinishedAt
}

// ReadPublicReceipt reads receipt.json at path. It refuses a link, a file
// over 16 KiB and a receipt that is not terminal.
func ReadPublicReceipt(path string) (PublicReceipt, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return PublicReceipt{}, err
	}
	if !info.Mode().IsRegular() {
		return PublicReceipt{}, fmt.Errorf("%s is not a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return PublicReceipt{}, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxPublicReceiptBytes+1))
	if err != nil {
		return PublicReceipt{}, err
	}
	if len(raw) > maxPublicReceiptBytes {
		return PublicReceipt{}, fmt.Errorf("%s is larger than %d bytes", path, maxPublicReceiptBytes)
	}
	var r PublicReceipt
	if err := json.Unmarshal(raw, &r); err != nil {
		return PublicReceipt{}, fmt.Errorf("%s: %w", path, err)
	}
	switch {
	case r.SchemaVersion < 1:
		return PublicReceipt{}, errors.New("bundle receipt.json has no schema_version")
	case strings.TrimSpace(r.ReceiptID) == "" || strings.TrimSpace(r.FinishedAt) == "":
		return PublicReceipt{}, errors.New("bundle receipt.json names no receipt")
	case r.State != BundleConfirmed && r.State != BundleFailed:
		return PublicReceipt{}, fmt.Errorf("bundle receipt.json state %q is not terminal", r.State)
	}
	return r, nil
}
