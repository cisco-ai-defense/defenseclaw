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
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// The gateway reports the signed policy bundle receipts of a standalone
// managed device: it reads the public receipt-events spool the enterprise
// lifecycle writes when a receipt ends, emits one config.bundle.receipt audit event
// (with the defenseclaw.policy.bundle.applies counter) per terminal receipt,
// and records the defenseclaw.policy.bundle.version gauge for the bundle the
// live generation runs. It also drains the change spool the root trust
// anchor and credential commands write (enterprisestatus.ChangeEvent) and
// emits one config.trust_anchors.changed, config.secret.changed or
// config.secret.change_failed audit event per change, so a change made
// while the gateway was stopped is reported at its next start. Reporting
// only: nothing here changes what is enforced.

var (
	// bundleReceiptPollInterval is how often the receipt spool is read.
	bundleReceiptPollInterval = 5 * time.Second
	// bundleReceiptRetries bounds how often one receipt is offered to an
	// audit logger that refuses it before the reporter waits for the next
	// receipt.
	bundleReceiptRetries = 12
	// bundleChangeDeliveryWait bounds how long the reporter waits for the
	// remote destinations of one change offer to answer before it offers
	// the change again.
	bundleChangeDeliveryWait = 10 * time.Minute
)

// These legacy single-slot markers also let a new reporter recognize events
// emitted before the per-receipt marker directory existed.
const bundleReceiptMarkerName = "bundle-receipt.reported"
const bundleRefusalMarkerName = "bundle-refusal.reported"

// bundleAcknowledgedDirName keeps the remote acknowledgements of the change
// events not reported yet (bundleReceiptReporter.acknowledgedDir).
const bundleAcknowledgedDirName = "bundle-receipt.acknowledged.d"

// bundleReceiptSink is the audit surface the reporter uses (*audit.Logger).
type bundleReceiptSink interface {
	LogPolicyBundleReceipt(principal string, bundle audit.PolicyBundle, receipt audit.PolicyBundleReceipt) error
	RecordPolicyBundleVersion(ctx context.Context, bundleVersion uint64) error
	LogConfigChange(change audit.ConfigChange, delivery *observability.RemoteDelivery) error
}

// changeDelivery is the reporter's state of one change event it offered.
type changeDelivery struct {
	delivery *observability.RemoteDelivery
	offered  time.Time
	// retry is set when the audit logger refused the last offer.
	retry bool
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
	// changes holds the change events offered and not reported yet.
	changes map[string]*changeDelivery
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
	r.reportChanges()
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
			if err := r.report(enterprisestatus.PublicReceipt{ReceiptID: refusal.ReceiptID, DeliveryID: refusal.DeliveryID,
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

func (r *bundleReceiptReporter) changeDir() string {
	return filepath.Join(filepath.Dir(r.receiptPath), enterprisestatus.ChangeEventsDirName)
}

// seenDir is <data_dir>/bundle-receipt.reported.d, one marker per reported
// receipt and change event: the lifecycle reads it before it removes a
// receipt event (enterprisestatus.ReceiptEventReported), the change commands
// before they remove a change event (enterprisestatus.ChangeReported).
func (r *bundleReceiptReporter) seenDir() string {
	return filepath.Join(filepath.Dir(r.markerPath), enterprisestatus.ReportedMarkersDirName)
}

// reportableID accepts a receipt id or a change event id as a marker name.
func reportableID(id string) bool {
	return enterprisestatus.ValidReceiptID(id) || enterprisestatus.ValidChangeEventID(id)
}

func (r *bundleReceiptReporter) hasSeen(id string) bool {
	if !reportableID(id) {
		return false
	}
	if r.seen[id] {
		return true
	}
	info, err := os.Lstat(filepath.Join(r.seenDir(), id))
	return err == nil && info.Mode().IsRegular()
}

func (r *bundleReceiptReporter) markSeen(id string) {
	if !reportableID(id) {
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

// reportChanges emits one audit event per change event not reported yet,
// oldest first, then one per reservation whose command ended before it
// wrote its event (failed, interrupted): a change interrupted after it was
// made is reported at the next poll, a gateway restart included, even when
// no later command writes the spool. A file that does not validate is
// skipped. A reservation the next command moves into the spool keeps its
// id, so it is not reported again. The spool event is the change's durable
// outbox: reportChange marks it reported, which lets the change commands
// remove it, only once its audit row survives a power loss and every
// remote destination acknowledged it.
func (r *bundleReceiptReporter) reportChanges() {
	dir := r.changeDir()
	for _, id := range enterprisestatus.ListChangeEventIDs(dir) {
		if r.hasSeen(id) {
			continue
		}
		ev, err := enterprisestatus.ReadChangeEvent(filepath.Join(dir, id+".json"))
		if err != nil || ev.EventID != id {
			continue
		}
		r.reportChange(ev)
	}
	for _, ev := range enterprisestatus.EndedChangeReservations(dir) {
		if !r.hasSeen(ev.EventID) {
			r.reportChange(ev)
		}
	}
}

// reportChange offers ev to the audit logger until it is reported. The
// logger stores each change event id once and returns nil only once the
// row survives a power loss; an offer it refuses is made again at the next
// poll, and one whose store write failed exported nothing. The change's
// RemoteDelivery, kept across offers, says when every remote destination
// acknowledged it. While its deliveries are in flight the change is not
// offered again; once one failed (refused, dropped, abandoned at shutdown)
// the next poll offers it again, and the logger sends the stored record to
// the destinations that do not have it. Each acknowledgement is recorded on
// disk as it arrives, scoped to the effective transport and routing identity,
// so a restart does not send it again to the same destination (GAP-0526)
// but reoffers it to a replacement that uses the same name.
func (r *bundleReceiptReporter) reportChange(ev enterprisestatus.ChangeEvent) {
	state := r.changes[ev.EventID]
	if state == nil {
		id := ev.EventID
		state = &changeDelivery{delivery: observability.NewRecordedRemoteDelivery(
			id, r.acknowledgedDestinations(id), func(destination string) { r.recordAcknowledged(id, destination) })}
		if r.changes == nil {
			r.changes = make(map[string]*changeDelivery)
		}
		r.changes[ev.EventID] = state
	} else if !state.retry {
		settled, _ := state.delivery.Settled()
		if !settled && time.Since(state.offered) < bundleChangeDeliveryWait {
			return
		}
		// Acknowledgement can finish after a graph reload. Reoffer once
		// against the current graph before marking reported: unchanged
		// destination identities are skipped, while a replacement gets it.
	}
	state.offered = time.Now()
	err := r.sink.LogConfigChange(audit.ConfigChange{
		EventID: ev.EventID, Kind: ev.Kind, Action: ev.Action, Outcome: ev.Outcome, ReasonCode: ev.ReasonCode,
		Actor: ev.Actor, ChangedAt: ev.Time, SHA256: ev.SHA256, PreviousSHA256: ev.PreviousSHA256,
		KeyIDsAdded: ev.KeyIDsAdded, KeyIDsRemoved: ev.KeyIDsRemoved, SecretName: ev.SecretName,
	}, state.delivery)
	state.retry = err != nil
	if err != nil {
		return
	}
	if settled, delivered := state.delivery.Settled(); settled && delivered {
		r.changeReported(ev.EventID)
	}
}

func (r *bundleReceiptReporter) changeReported(id string) {
	delete(r.changes, id)
	r.markSeen(id)
	if r.hasSeen(id) {
		_ = os.RemoveAll(filepath.Join(r.acknowledgedDir(), id))
	}
}

// acknowledgedDir is <data_dir>/bundle-receipt.acknowledged.d: per change
// event not reported yet, one file per acknowledged destination identity.
func (r *bundleReceiptReporter) acknowledgedDir() string {
	return filepath.Join(filepath.Dir(r.markerPath), bundleAcknowledgedDirName)
}

// acknowledgedDestinations returns the event-scoped destination identities
// recorded as having change event id. Earlier name-only and v2 records are
// ignored; they cannot prove which resolved recipient received the change.
func (r *bundleReceiptReporter) acknowledgedDestinations(id string) []string {
	if !enterprisestatus.ValidChangeEventID(id) {
		return nil
	}
	dir := filepath.Join(r.acknowledgedDir(), id)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var destinations []string
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		raw, err := safefile.ReadRegularFileBounded(filepath.Join(dir, entry.Name()), 1<<10)
		if name := string(raw); err == nil && observability.ValidRecordedDeliveryKey(name) && acknowledgedFileName(name) == entry.Name() {
			destinations = append(destinations, name)
		}
	}
	return destinations
}

// recordAcknowledged records that an effective destination has change event
// id. It runs on the destination's queue.
func (r *bundleReceiptReporter) recordAcknowledged(id, destination string) {
	if !enterprisestatus.ValidChangeEventID(id) || !observability.ValidRecordedDeliveryKey(destination) {
		return
	}
	dir := filepath.Join(r.acknowledgedDir(), id)
	if err := os.MkdirAll(dir, 0o700); err == nil {
		_ = configwrite.WriteFileDurable(filepath.Join(dir, acknowledgedFileName(destination)), []byte(destination), 0o600)
	}
}

// acknowledgedFileName names a tracking key's file without treating the key
// as a path component.
func acknowledgedFileName(destination string) string {
	sum := sha256.Sum256([]byte(destination))
	return hex.EncodeToString(sum[:16])
}

func (r *bundleReceiptReporter) report(p enterprisestatus.PublicReceipt) error {
	bundle := audit.PolicyBundle{ID: p.BundleID, Version: p.Version, SignerKeyID: p.SignerKeyID, ChangeSummary: p.ChangeSummary}
	err := r.sink.LogPolicyBundleReceipt(p.Principal, bundle, audit.PolicyBundleReceipt{
		ReceiptID: p.ReceiptID, DeliveryID: p.DeliveryID, Actor: p.Actor, State: p.State, ErrorCode: p.ErrorCode,
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
