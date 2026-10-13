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

package gateway

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// The gateway reports the signed policy bundle receipts of a standalone
// managed device: it reads the public receipt.json the enterprise lifecycle
// writes when a receipt ends, emits one config.bundle.receipt audit event
// (with the defenseclaw.policy.bundle.applies counter) per terminal receipt,
// and records the defenseclaw.policy.bundle.version gauge for the bundle the
// live generation runs. Reporting only: nothing here changes what is
// enforced.

var (
	// bundleReceiptPollInterval is how often receipt.json is looked at.
	bundleReceiptPollInterval = 5 * time.Second
	// bundleReceiptRetries bounds how often one receipt is offered to an
	// audit logger that refuses it before the reporter waits for the next
	// receipt.
	bundleReceiptRetries = 12
)

// bundleReceiptMarkerName, in the data directory, holds the key of the last
// receipt reported, so a gateway restart does not report it again.
const bundleReceiptMarkerName = "bundle-receipt.reported"
const bundleRefusalMarkerName = "bundle-refusal.reported"

// bundleReceiptSink is the audit surface the reporter uses (*audit.Logger).
type bundleReceiptSink interface {
	LogPolicyBundleReceipt(principal string, bundle audit.PolicyBundle, receipt audit.PolicyBundleReceipt) error
	RecordPolicyBundleVersion(ctx context.Context, bundleVersion uint64) error
}

type bundleReceiptReporter struct {
	receiptPath, markerPath, refusalMarkerPath string
	sink                                       bundleReceiptSink
	// enforcedVersion is the bundle version the live generation runs.
	enforcedVersion func() uint64

	lastModTime     time.Time
	lastSize        int64
	reported        string
	reportedRefusal string
	attempts        int
	gaugeVersion    uint64
}

// newBundleReceiptReporter returns the reporter of a standalone enterprise
// gateway, nil on every other profile (per-user, Secure Client) and without
// an audit logger.
func newBundleReceiptReporter(cfg *config.Config, configPath string, logger *audit.Logger) *bundleReceiptReporter {
	if cfg == nil || logger == nil || !cfg.StandaloneEnterprise() || cfg.SecureClientIntegration() ||
		strings.TrimSpace(configPath) == "" || strings.TrimSpace(cfg.DataDir) == "" {
		return nil
	}
	return &bundleReceiptReporter{
		receiptPath:       enterprisestatus.PublicReceiptPath(filepath.Dir(configPath)),
		markerPath:        filepath.Join(cfg.DataDir, bundleReceiptMarkerName),
		refusalMarkerPath: filepath.Join(cfg.DataDir, bundleRefusalMarkerName),
		sink:              logger,
		enforcedVersion:   liveBundleVersion,
	}
}

func liveBundleVersion() uint64 {
	if g := currentGeneration(); g != nil {
		return g.BundleVersion
	}
	return 0
}

func (r *bundleReceiptReporter) run(ctx context.Context) {
	r.reported = r.readMarker()
	r.reportedRefusal = r.readRefusalMarker()
	ticker := time.NewTicker(bundleReceiptPollInterval)
	defer ticker.Stop()
	for {
		r.poll(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// poll records the version gauge when the enforced bundle changed and
// reports receipt.json once per terminal receipt.
func (r *bundleReceiptReporter) poll(ctx context.Context) {
	if v := r.enforcedVersion(); v != 0 && v != r.gaugeVersion {
		if r.sink.RecordPolicyBundleVersion(ctx, v) == nil {
			r.gaugeVersion = v
		}
	}
	info, err := os.Lstat(r.receiptPath)
	if err != nil || !info.Mode().IsRegular() {
		return
	}
	if info.ModTime().Equal(r.lastModTime) && info.Size() == r.lastSize {
		return
	}
	seen := func() { r.lastModTime, r.lastSize, r.attempts = info.ModTime(), info.Size(), 0 }
	receipt, err := enterprisestatus.ReadPublicReceipt(r.receiptPath)
	if err != nil {
		seen()
		return
	}
	key := receipt.Key()
	if key == r.reported {
		// The public receipt remains confirmed when a pre-staging delivery
		// is refused. Its separate refusal still needs an audit event.
	} else {
		if err := r.report(receipt); err != nil {
			if r.attempts++; r.attempts >= bundleReceiptRetries {
				seen()
			}
			return
		}
		r.reported = key
		_ = configwrite.WriteFileDurable(r.markerPath, []byte(key+"\n"), 0o600)
	}
	if refusal := receipt.LastRefusal; refusal != nil && refusal.ReceiptID == receipt.ReceiptID {
		r.reportedRefusal = refusal.ReceiptID + "|" + refusal.Time
		if r.refusalMarkerPath != "" {
			_ = configwrite.WriteFileDurable(r.refusalMarkerPath, []byte(r.reportedRefusal+"\n"), 0o600)
		}
	}
	if refusal := receipt.LastRefusal; refusal != nil && refusal.ReceiptID != receipt.ReceiptID {
		refusalKey := refusal.ReceiptID + "|" + refusal.Time
		if refusalKey != r.reportedRefusal {
			if err := r.report(enterprisestatus.PublicReceipt{ReceiptID: refusal.ReceiptID,
				BundleID: refusal.BundleID, Version: refusal.Version, State: enterprisestatus.BundleFailed,
				ErrorCode: refusal.ErrorCode, FinishedAt: refusal.Time,
				WarningCodes: refusal.WarningCodes, DisabledByBundle: refusal.DisabledByBundle,
				CurrentBundleID: receipt.CurrentBundleID, CurrentVersion: receipt.CurrentVersion}); err != nil {
				if r.attempts++; r.attempts >= bundleReceiptRetries {
					seen()
				}
				return
			}
			r.reportedRefusal = refusalKey
			if r.refusalMarkerPath != "" {
				_ = configwrite.WriteFileDurable(r.refusalMarkerPath, []byte(refusalKey+"\n"), 0o600)
			}
		}
	}
	seen()
}

func (r *bundleReceiptReporter) report(p enterprisestatus.PublicReceipt) error {
	bundle := audit.PolicyBundle{ID: p.BundleID, Version: p.Version, SignerKeyID: p.SignerKeyID, ChangeSummary: p.ChangeSummary}
	err := r.sink.LogPolicyBundleReceipt(p.Principal, bundle, audit.PolicyBundleReceipt{
		ReceiptID: p.ReceiptID, State: p.State, ErrorCode: p.ErrorCode,
		EffectivePolicyDigest: p.EffectivePolicyDigest, EnforcingDigest: p.EnforcingDigest,
		ConfigGeneration: p.ConfigGeneration, RolledBack: p.RolledBack, Restart: p.Restart,
		EnforcingVersion: p.CurrentVersion,
		WarningCodes:     p.WarningCodes, DisabledByBundle: p.DisabledByBundle,
	})
	if err == nil && p.CurrentVersion != 0 {
		r.gaugeVersion = p.CurrentVersion
	}
	return err
}

func (r *bundleReceiptReporter) readMarker() string {
	return readBundleMarker(r.markerPath)
}

func (r *bundleReceiptReporter) readRefusalMarker() string {
	return readBundleMarker(r.refusalMarkerPath)
}

func readBundleMarker(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	raw, _ := io.ReadAll(io.LimitReader(f, 512))
	return strings.TrimSpace(string(raw))
}
