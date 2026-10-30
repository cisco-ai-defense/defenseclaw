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
	"regexp"
	"strings"
)

const (
	// PublicReceiptName is the public status summary of the last receipt that
	// reached staging, with the last pre-staging refusal recorded separately.
	// It has no secrets or error message. The gateway uses it as a fallback
	// for lifecycle versions that predate the per-receipt audit spool.
	PublicReceiptName = "receipt.json"
	// PublicReceiptEventsDirName holds one immutable public receipt per
	// terminal delivery for the gateway's audit reporter.
	PublicReceiptEventsDirName = "receipt-events"
	// PublicReceiptSchemaVersion is the receipt.json schema.
	PublicReceiptSchemaVersion = 1

	maxPublicReceiptBytes = 16 << 10

	// MaxDeliveryIDBytes bounds the delivery id of `enterprise bundle apply
	// --delivery-id`.
	MaxDeliveryIDBytes = 128
)

var receiptIDPattern = regexp.MustCompile(`^[br]-[0-7][0-9A-HJKMNP-TV-Z]{25}$`)

// PublicReceipt is receipt.json. Decoding is lenient so an older gateway
// reads the file of a newer lifecycle; readers validate every field again.
type PublicReceipt struct {
	SchemaVersion int    `json:"schema_version"`
	ReceiptID     string `json:"receipt_id"`
	// DeliveryID is the caller-supplied --delivery-id of this delivery
	// (CheckDeliveryID), absent without the flag.
	DeliveryID  string `json:"delivery_id,omitempty"`
	BundleID    string `json:"bundle_id,omitempty"`
	Version     uint64 `json:"version,omitempty"`
	SignerKeyID string `json:"signer_key_id,omitempty"`
	// Seq is the delivery sequence of this device (1.0.6): one more for each
	// new delivery, so receipts order without a clock. Absent on a receipt
	// written by an earlier build.
	Seq uint64 `json:"seq,omitempty"`
	// Principal is the manifest created_by (control-plane:<tenant>/<admin>
	// or operator:<os-admin>).
	Principal string `json:"principal,omitempty"`
	// Actor is the local OS account that received this bundle.
	Actor         string `json:"actor,omitempty"`
	ChangeSummary string `json:"change_summary,omitempty"`
	RollbackOf    string `json:"rollback_of,omitempty"`
	// State is BundleConfirmed or BundleFailed; ErrorCode is the closed
	// code of a failed receipt.
	State                   string   `json:"state"`
	ErrorCode               string   `json:"error_code,omitempty"`
	EffectivePolicyDigest   string   `json:"effective_policy_digest,omitempty"`
	WarningCodes            []string `json:"warning_codes,omitempty"`
	DisabledByBundle        []string `json:"disabled_by_bundle,omitempty"`
	EnforcingDigest         string   `json:"enforcing_digest,omitempty"`
	ConfigGeneration        uint64   `json:"config_generation,omitempty"`
	AppliedAt               string   `json:"applied_at,omitempty"`
	ConfirmedAt             string   `json:"confirmed_at,omitempty"`
	SessionsRestartRequired int      `json:"sessions_restart_required"`
	// FinishedAt is the time of the terminal transition.
	FinishedAt      string `json:"finished_at"`
	RolledBack      bool   `json:"rolled_back,omitempty"`
	Restart         bool   `json:"restart,omitempty"`
	RestartRequired bool   `json:"restart_required,omitempty"`
	// CurrentBundleID and CurrentVersion name the confirmed bundle that
	// enforces after this receipt (absent when none does).
	CurrentBundleID string         `json:"current_bundle_id,omitempty"`
	CurrentVersion  uint64         `json:"current_version,omitempty"`
	LastRefusal     *BundleRefusal `json:"last_refusal,omitempty"`
}

// BundleRefusal is a delivery stopped before staging changed the enforcing
// policy. Its terminal receipt remains in the root-only receipt history.
type BundleRefusal struct {
	ReceiptID        string   `json:"receipt_id"`
	DeliveryID       string   `json:"delivery_id,omitempty"`
	BundleID         string   `json:"bundle_id,omitempty"`
	Version          uint64   `json:"version,omitempty"`
	ErrorCode        string   `json:"error_code"`
	Time             string   `json:"time"`
	WarningCodes     []string `json:"warning_codes,omitempty"`
	DisabledByBundle []string `json:"disabled_by_bundle,omitempty"`
}

// PublicReceiptPath is receipt.json for the configuration directory
// configDir (the directory of config.yaml).
func PublicReceiptPath(configDir string) string {
	return filepath.Join(configDir, "bundles", PublicReceiptName)
}

// ValidReceiptID permits only lifecycle receipt IDs in spool file names.
func ValidReceiptID(id string) bool { return receiptIDPattern.MatchString(id) }

// ReceiptEventReported reports whether the gateway with data_dir dataDir
// reported the receipt event id (its marker file exists). The lifecycle
// keeps an event the gateway has not reported when it trims
// receipt-events/.
func ReceiptEventReported(dataDir, id string) bool {
	if !ValidReceiptID(id) || dataDir == "" {
		return false
	}
	info, err := os.Lstat(filepath.Join(dataDir, ReportedMarkersDirName, id))
	return err == nil && info.Mode().IsRegular()
}

// CheckDeliveryID explains why id is not a delivery id `enterprise bundle
// apply --delivery-id` accepts: 1 to MaxDeliveryIDBytes bytes of A-Z, a-z,
// 0-9 and . _ : - (ASCII, no space or control character). The value is
// opaque and supplied by the caller (an MDM wrapper, a management agent or
// an administrator alike); nil when id is valid.
func CheckDeliveryID(id string) error {
	switch {
	case id == "":
		return errors.New("--delivery-id needs a value of 1 to 128 characters; leave the flag out for none")
	case len(id) > MaxDeliveryIDBytes:
		return fmt.Errorf("--delivery-id takes at most %d bytes, not %d", MaxDeliveryIDBytes, len(id))
	}
	for i := 0; i < len(id); i++ {
		if c := id[i]; !deliveryIDByte(c) {
			return fmt.Errorf("--delivery-id takes only A-Z, a-z, 0-9, dot, underscore, colon and hyphen; byte %d is 0x%02x", i+1, c)
		}
	}
	return nil
}

// ValidDeliveryID reports whether CheckDeliveryID accepts id.
func ValidDeliveryID(id string) bool { return CheckDeliveryID(id) == nil }

// deliveryIDChars is the delivery id alphabet.
const deliveryIDChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-"

func deliveryIDByte(c byte) bool { return strings.IndexByte(deliveryIDChars, c) >= 0 }

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
	case r.DeliveryID != "" && !ValidDeliveryID(r.DeliveryID):
		return PublicReceipt{}, errors.New("bundle receipt.json delivery_id is not a valid delivery id")
	}
	return r, nil
}
