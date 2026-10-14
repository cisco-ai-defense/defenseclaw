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
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// The gateway reports the signed policy bundle receipts of a standalone
// managed device: it reads the public receipt-events spool the enterprise
// lifecycle writes when a receipt ends, emits one config.bundle.receipt audit event
// (with the defenseclaw.policy.bundle.applies counter) per terminal receipt,
// and records the defenseclaw.policy.bundle.version gauge for the bundle the
// live generation runs. Reporting only: nothing here changes what is
// enforced.

var (
	// bundleReceiptPollInterval is how often the receipt spool is read.
	bundleReceiptPollInterval = 5 * time.Second
	// bundleReceiptRetries bounds how often one receipt is offered to an
	// audit logger that refuses it before the reporter waits for the next
	// receipt.
	bundleReceiptRetries = 12
)

// These legacy single-slot markers also let a new reporter recognize events
// emitted before the per-receipt marker directory existed.
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
	seen            map[string]bool
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

// poll records the version gauge and drains every terminal receipt in the
// spool. receipt.json remains a fallback for lifecycle versions without it.
func (r *bundleReceiptReporter) poll(ctx context.Context) {
	if v := r.enforcedVersion(); v != 0 && v != r.gaugeVersion {
		if r.sink.RecordPolicyBundleVersion(ctx, v) == nil {
			r.gaugeVersion = v
		}
	}
	r.reportSpool()
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
	if key == r.reported || r.hasSeen(receipt.ReceiptID) {
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
		r.markSeen(receipt.ReceiptID)
	}
	if refusal := receipt.LastRefusal; refusal != nil && refusal.ReceiptID == receipt.ReceiptID {
		r.reportedRefusal = refusal.ReceiptID + "|" + refusal.Time
		if r.refusalMarkerPath != "" {
			_ = configwrite.WriteFileDurable(r.refusalMarkerPath, []byte(r.reportedRefusal+"\n"), 0o600)
		}
	}
	if refusal := receipt.LastRefusal; refusal != nil && refusal.ReceiptID != receipt.ReceiptID {
		refusalKey := refusal.ReceiptID + "|" + refusal.Time
		if refusalKey != r.reportedRefusal && !r.hasSeen(refusal.ReceiptID) {
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
			r.markSeen(refusal.ReceiptID)
			if r.refusalMarkerPath != "" {
				_ = configwrite.WriteFileDurable(r.refusalMarkerPath, []byte(refusalKey+"\n"), 0o600)
			}
		}
	}
	seen()
}

func (r *bundleReceiptReporter) spoolDir() string {
	return filepath.Join(filepath.Dir(r.receiptPath), enterprisestatus.PublicReceiptEventsDirName)
}

func (r *bundleReceiptReporter) seenDir() string { return r.markerPath + ".d" }

func (r *bundleReceiptReporter) hasSeen(id string) bool {
	if !enterprisestatus.ValidReceiptID(id) {
		return false
	}
	if r.seen[id] {
		return true
	}
	info, err := os.Lstat(filepath.Join(r.seenDir(), id))
	return err == nil && info.Mode().IsRegular()
}

func (r *bundleReceiptReporter) markSeen(id string) {
	if !enterprisestatus.ValidReceiptID(id) {
		return
	}
	if r.seen == nil {
		r.seen = make(map[string]bool)
	}
	r.seen[id] = true
	if err := os.MkdirAll(r.seenDir(), 0o700); err == nil {
		_ = configwrite.WriteFileDurable(filepath.Join(r.seenDir(), id), []byte("reported\n"), 0o600)
	}
}

func (r *bundleReceiptReporter) reportSpool() {
	info, err := os.Lstat(r.spoolDir())
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return
	}
	entries, err := os.ReadDir(r.spoolDir())
	if err != nil {
		return
	}
	var receipts []enterprisestatus.PublicReceipt
	for _, entry := range entries {
		id, ok := strings.CutSuffix(entry.Name(), ".json")
		if !ok || !enterprisestatus.ValidReceiptID(id) || !entry.Type().IsRegular() || r.hasSeen(id) {
			continue
		}
		receipt, err := enterprisestatus.ReadPublicReceipt(filepath.Join(r.spoolDir(), entry.Name()))
		if err == nil && receipt.ReceiptID == id {
			receipts = append(receipts, receipt)
		}
	}
	sort.Slice(receipts, func(i, j int) bool {
		if receipts[i].FinishedAt != receipts[j].FinishedAt {
			return receipts[i].FinishedAt < receipts[j].FinishedAt
		}
		return receipts[i].ReceiptID < receipts[j].ReceiptID
	})
	for _, receipt := range receipts {
		if receipt.Key() == r.reported || receipt.ReceiptID+"|"+receipt.FinishedAt == r.reportedRefusal {
			r.markSeen(receipt.ReceiptID)
			continue
		}
		if r.report(receipt) == nil {
			r.markSeen(receipt.ReceiptID)
		}
	}
}

func (r *bundleReceiptReporter) report(p enterprisestatus.PublicReceipt) error {
	bundle := audit.PolicyBundle{ID: p.BundleID, Version: p.Version, SignerKeyID: p.SignerKeyID, ChangeSummary: p.ChangeSummary}
	err := r.sink.LogPolicyBundleReceipt(p.Principal, bundle, audit.PolicyBundleReceipt{
		ReceiptID: p.ReceiptID, Actor: p.Actor, State: p.State, ErrorCode: p.ErrorCode,
		EffectivePolicyDigest: p.EffectivePolicyDigest, EnforcingDigest: p.EnforcingDigest,
		ConfigGeneration: p.ConfigGeneration, RolledBack: p.RolledBack, Restart: p.Restart,
		RestartRequired:  p.RestartRequired,
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
