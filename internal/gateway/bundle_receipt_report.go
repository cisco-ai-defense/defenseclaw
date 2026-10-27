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
	"errors"
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

// changeRecordPinsDirName holds the record pin of each change event not
// reported yet (audit.ConfigChangePin), in the gateway's data directory.
const changeRecordPinsDirName = "change-record-pins"

// bundleReceiptSink is the audit surface the reporter uses (*audit.Logger).
type bundleReceiptSink interface {
	LogPolicyBundleReceipt(principal string, bundle audit.PolicyBundle, receipt audit.PolicyBundleReceipt,
		delivery *observability.RemoteDelivery, pins *audit.ConfigChangePins) error
	RecordPolicyBundleVersion(ctx context.Context, bundleVersion uint64) error
	LogConfigChange(change audit.ConfigChange, delivery *observability.RemoteDelivery, pins *audit.ConfigChangePins) error
}

// changeDelivery is the reporter's state of one change event or terminal
// receipt it offered.
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
	// seen holds the ids whose reported marker is on disk.
	seen map[string]bool
	// unmarked holds the ids reported by this process whose marker write
	// failed. They are not reported again, and every poll writes their
	// marker again: the change commands remove a change event from the
	// spool only once its marker is on disk.
	unmarked map[string]bool
	// changes holds the change events and receipts offered and not
	// reported yet.
	changes map[string]*changeDelivery
	// pins keeps the record of each change and receipt the same on every
	// offer.
	pins *audit.ConfigChangePins
	// spoolAtStart holds the ids of the change events and reservations in
	// the change spool, and of the receipts in the receipt spool, when this
	// reporter first read them (spoolScanned). Only one that entered a spool
	// later, on its first offer, is one no earlier gateway process can have
	// offered (audit.ConfigChange.FirstOffer).
	spoolAtStart map[string]bool
	spoolScanned bool
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
		pins:              audit.NewConfigChangePins(filepath.Join(cfg.DataDir, changeRecordPinsDirName)),
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
	r.pins.Prune(r.reportedOnDisk)
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
	r.retryMarkers()
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
		if !r.report(receipt, false) {
			if r.attempts++; r.attempts >= bundleReceiptRetries {
				seen()
			}
			return
		}
		r.reported = key
		_ = configwrite.WriteFileDurable(r.markerPath, []byte(key+"\n"), 0o600)
		r.changeReported(receipt.ReceiptID)
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
			if ok := r.report(enterprisestatus.PublicReceipt{ReceiptID: refusal.ReceiptID, DeliveryID: refusal.DeliveryID,
				BundleID: refusal.BundleID, Version: refusal.Version, State: enterprisestatus.BundleFailed,
				ErrorCode: refusal.ErrorCode, FinishedAt: refusal.Time,
				WarningCodes: refusal.WarningCodes, DisabledByBundle: refusal.DisabledByBundle,
				CurrentBundleID: receipt.CurrentBundleID, CurrentVersion: receipt.CurrentVersion}, false); !ok {
				if r.attempts++; r.attempts >= bundleReceiptRetries {
					seen()
				}
				return
			}
			r.reportedRefusal = refusalKey
			r.changeReported(refusal.ReceiptID)
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
	if r.seen[id] || r.unmarked[id] {
		return true
	}
	info, err := os.Lstat(filepath.Join(r.seenDir(), id))
	return err == nil && info.Mode().IsRegular()
}

// mkdirMarkers is configwrite.MkdirDurable; a test replaces it.
var mkdirMarkers = configwrite.MkdirDurable

// markSeen records that id is reported and reports whether its marker is on
// disk. An id whose marker write failed is kept in unmarked, so it is not
// reported again, and retryMarkers writes its marker at the next poll.
func (r *bundleReceiptReporter) markSeen(id string) bool {
	if !reportableID(id) {
		return false
	}
	// Made durably: the record pin of a change goes once its marker is on
	// disk (markedChange), so a marker folder a power loss took back would
	// leave the change unreported and unpinned.
	err := mkdirMarkers(r.seenDir())
	if err == nil {
		err = configwrite.WriteFileDurable(filepath.Join(r.seenDir(), id), []byte("reported\n"), 0o600)
	}
	if err != nil {
		if r.unmarked == nil {
			r.unmarked = make(map[string]bool)
		}
		r.unmarked[id] = true
		return false
	}
	if r.seen == nil {
		r.seen = make(map[string]bool)
	}
	r.seen[id] = true
	delete(r.unmarked, id)
	return true
}

// retryMarkers writes the marker of each id reported without one. A change
// or receipt keeps its delivery state and its record pin until its marker
// is on disk.
func (r *bundleReceiptReporter) retryMarkers() {
	for id := range r.unmarked {
		if r.markSeen(id) {
			r.markedChange(id)
		}
	}
}

// reportSpool offers each terminal receipt in the receipt spool not
// reported yet, oldest first, as reportChanges offers a change: its record
// keeps one id and one pin across offers, and it is marked reported only
// once every sink confirmed it. A receipt the audit store could not write
// is offered again at the next poll, but goes only to the remote
// destinations that do not have it.
func (r *bundleReceiptReporter) reportSpool() {
	r.scanSpools()
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
			r.changeReported(receipt.ReceiptID)
			continue
		}
		if r.report(receipt, true) {
			r.changeReported(receipt.ReceiptID)
		}
	}
}

// reportChanges is the one sender of the change spool, the durable record
// of every change (its command flushed the event before it made the
// change). It offers each change event not reported yet, oldest first,
// once the event is on disk to stay (enterprisestatus.ReportableChangeEvents),
// then the event of each reservation whose command ended before it wrote
// its outcome (failed, interrupted), also once it is flushed: a change
// interrupted after it was made is reported at the next poll, a gateway
// restart included, even when no later command writes the spool. A file
// that does not validate (its id is not the hash of its content, for one)
// is skipped. A reservation the next command moves into the spool keeps
// its id, and an outcome that settles it names it, so it is not reported
// twice. reportChange marks an event reported, which lets the change
// commands remove it, only once every sink confirmed it.
func (r *bundleReceiptReporter) reportChanges() {
	dir := r.changeDir()
	r.scanSpools()
	for _, ev := range enterprisestatus.ReportableChangeEvents(dir, r.hasSeen) {
		r.reportChange(ev)
	}
	for _, ev := range enterprisestatus.EndedChangeReservations(dir) {
		if !r.hasSeen(ev.EventID) {
			r.reportChange(ev)
		}
	}
}

// reportChange offers ev to its sinks, the audit store and every remote
// destination, until each confirmed it. The record is built from the event
// and its record pin (r.pins), so every offer sends the same record,
// and each sink gets it on its own: a destination does not wait for the
// audit row, nor the row for a destination. The audit logger stores each
// change event id once and returns nil only once the row survives a power
// loss; an offer it refuses is made again at the next poll. The change's
// RemoteDelivery, kept across offers (and across config reloads: the
// reporter lives as long as the gateway), says which destinations
// acknowledged it: a later offer goes only to the destinations that do not
// have it and have nothing of it in flight. While its deliveries are in
// flight the change is not offered again; once one failed (refused,
// dropped, abandoned at shutdown or by a reload) the next poll offers it
// again. After a restart the delivery state is gone and an unreported
// change goes to every destination again, under the same record id.
func (r *bundleReceiptReporter) reportChange(ev enterprisestatus.ChangeEvent) {
	if r.offer(ev.EventID, true, func(delivery *observability.RemoteDelivery, firstOffer bool) error {
		return r.sink.LogConfigChange(audit.ConfigChange{
			EventID: ev.EventID, Kind: ev.Kind, Action: ev.Action, Outcome: ev.Outcome, ReasonCode: ev.ReasonCode,
			Actor: ev.Actor, ChangedAt: ev.Time, SHA256: ev.SHA256, PreviousSHA256: ev.PreviousSHA256,
			KeyIDsAdded: ev.KeyIDsAdded, KeyIDsRemoved: ev.KeyIDsRemoved, SecretName: ev.SecretName,
			FirstOffer: firstOffer,
		}, delivery, r.pins)
	}) {
		r.changeReported(ev.EventID)
	}
}

// offer makes one offer of the spooled change or receipt id with log, and
// reports whether every sink confirmed it. Its delivery state lives as
// long as the reporter: while its remote deliveries are in flight it is
// not offered again, and after a refused offer, a failed delivery or
// bundleChangeDeliveryWait it is. spooled says id is read from a spool
// scanned at start, so its first offer is one no earlier gateway process
// made when it was not there then (log's firstOffer).
func (r *bundleReceiptReporter) offer(
	id string, spooled bool, log func(delivery *observability.RemoteDelivery, firstOffer bool) error,
) bool {
	state := r.changes[id]
	firstOffer := false
	if state == nil {
		firstOffer = spooled && r.spoolScanned && !r.spoolAtStart[id]
		state = &changeDelivery{delivery: observability.NewRemoteDelivery()}
		if r.changes == nil {
			r.changes = make(map[string]*changeDelivery)
		}
		r.changes[id] = state
	} else if !state.retry {
		settled, delivered := state.delivery.Settled()
		if settled && delivered {
			return true
		}
		if !settled && time.Since(state.offered) < bundleChangeDeliveryWait {
			return false
		}
	}
	state.offered = time.Now()
	err := log(state.delivery, firstOffer)
	state.retry = err != nil
	if err != nil {
		return false
	}
	settled, delivered := state.delivery.Settled()
	return settled && delivered
}

// scanSpools reads, once, the ids in the change and receipt spools
// (spoolAtStart).
func (r *bundleReceiptReporter) scanSpools() {
	if !r.spoolScanned {
		r.spoolAtStart, r.spoolScanned = changeSpoolIDs(r.changeDir(), r.spoolDir())
	}
}

// changeReported marks a change or receipt every sink confirmed. Its delivery state
// and record pin go once the marker is on disk: until then a restart offers
// it again, and its pin keeps that offer the same record.
func (r *bundleReceiptReporter) changeReported(id string) {
	if r.markSeen(id) {
		r.markedChange(id)
	}
}

// markedChange drops the delivery state and the record pin of a change or
// receipt whose marker is on disk.
func (r *bundleReceiptReporter) markedChange(id string) {
	if _, ok := r.changes[id]; !ok && !reportableID(id) {
		return
	}
	delete(r.changes, id)
	delete(r.spoolAtStart, id)
	_ = r.pins.Remove(id)
}

// changeSpoolIDs is the id of every change event and reservation in the
// change spool dir and of every receipt in receiptDir, and whether the
// spools could be read. A spool that does not exist holds none.
func changeSpoolIDs(dir, receiptDir string) (map[string]bool, bool) {
	ids := map[string]bool{}
	for _, folder := range []string{dir, filepath.Join(dir, enterprisestatus.ChangeReservedDirName), receiptDir} {
		entries, err := os.ReadDir(folder)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, false
		}
		for _, entry := range entries {
			if id, ok := strings.CutSuffix(entry.Name(), ".json"); ok {
				ids[id] = true
			}
		}
	}
	return ids, true
}

// reportedOnDisk reports whether the reported marker of id is on disk.
func (r *bundleReceiptReporter) reportedOnDisk(id string) bool {
	if !reportableID(id) {
		return false
	}
	info, err := os.Lstat(filepath.Join(r.seenDir(), id))
	return err == nil && info.Mode().IsRegular()
}

// report offers the terminal receipt p (offer; spooled when it is read
// from the receipt spool) and reports whether every sink confirmed it.
func (r *bundleReceiptReporter) report(p enterprisestatus.PublicReceipt, spooled bool) bool {
	bundle := audit.PolicyBundle{ID: p.BundleID, Version: p.Version, SignerKeyID: p.SignerKeyID, ChangeSummary: p.ChangeSummary}
	return r.offer(p.ReceiptID, spooled, func(delivery *observability.RemoteDelivery, firstOffer bool) error {
		err := r.sink.LogPolicyBundleReceipt(p.Principal, bundle, audit.PolicyBundleReceipt{
			ReceiptID: p.ReceiptID, DeliveryID: p.DeliveryID, Actor: p.Actor, State: p.State, ErrorCode: p.ErrorCode,
			EffectivePolicyDigest: p.EffectivePolicyDigest, EnforcingDigest: p.EnforcingDigest,
			ConfigGeneration: p.ConfigGeneration, RolledBack: p.RolledBack, Restart: p.Restart,
			RestartRequired:  p.RestartRequired,
			EnforcingVersion: p.CurrentVersion,
			WarningCodes:     p.WarningCodes, DisabledByBundle: p.DisabledByBundle,
			FinishedAt: p.FinishedAt, FirstOffer: firstOffer,
		}, delivery, r.pins)
		if err == nil && p.CurrentVersion != 0 {
			r.gaugeVersion = p.CurrentVersion
		}
		return err
	})
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
