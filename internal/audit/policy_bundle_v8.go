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

package audit

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// PolicyBundle names the signed policy bundle a config.change.applied
// record or a bundle receipt is about. Invalid values are left out of the
// record, never rejected: the bundle fields are reporting only.
type PolicyBundle struct {
	ID            string
	Version       uint64
	SignerKeyID   string
	ChangeSummary string
}

// PolicyBundleReceipt is the terminal receipt of one policy bundle delivery
// on a standalone managed device (log.config.bundle.receipt).
type PolicyBundleReceipt struct {
	// Actor is the local OS account that received this bundle.
	Actor string
	// ReceiptID is the bundle id, or r-<ULID> for a delivery whose manifest
	// could not be read.
	ReceiptID string
	// DeliveryID is the caller-supplied --delivery-id of the apply, "" for
	// none. It is opaque and not authenticated.
	DeliveryID string
	// State is PolicyBundleConfirmed or PolicyBundleFailed.
	State string
	// ErrorCode is the closed receipt code of a failed receipt.
	ErrorCode             string
	EffectivePolicyDigest string
	// EnforcingDigest is the policy the gateway enforced when the receipt
	// ended: for a failed receipt the last good policy.
	EnforcingDigest  string
	ConfigGeneration uint64
	RolledBack       bool
	Restart          bool
	RestartRequired  bool
	// EnforcingVersion is the version of the bundle the device enforces
	// after this receipt (0 when none): the defenseclaw.policy.bundle.version
	// gauge.
	EnforcingVersion uint64
	WarningCodes     []string
	DisabledByBundle []string
	// FinishedAt is the time of the terminal transition (RFC 3339), the
	// time of the receipt's record when the receipt is offered from the
	// receipt spool (LogPolicyBundleReceipt with record pins).
	FinishedAt string
	// FirstOffer says no gateway process can have offered this receipt
	// before (audit.ConfigChange.FirstOffer has the same meaning).
	FirstOffer bool
}

// Terminal receipt states (defenseclaw.policy.bundle.state).
const (
	PolicyBundleConfirmed = "confirmed"
	PolicyBundleFailed    = "failed"
)

const (
	maxPolicyBundleVersion       = 1<<53 - 1
	maxPolicyBundleChangeSummary = 512
)

var (
	policyBundleIDPattern        = lazyregexp.New(`^b-[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
	policyBundleReceiptIDPattern = lazyregexp.New(`^[br]-[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
	// policyBundleDeliveryIDPattern is the --delivery-id of bundle apply
	// (enterprisestatus.CheckDeliveryID).
	policyBundleDeliveryIDPattern = lazyregexp.New(`^[A-Za-z0-9._:-]{1,128}$`)
	policyBundleKeyIDPattern      = lazyregexp.New(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	policyBundleCodePattern       = lazyregexp.New(`^[a-z][a-z0-9_]{0,63}$`)
	policyBundleDigestPattern     = lazyregexp.New(`^sha256:[0-9a-f]{64}$`)
)

// policyBundleV8Fields are the typed bundle attributes of a record.
type policyBundleV8Fields struct {
	id, signerKeyID, changeSummary observability.Optional[string]
	version                        observability.Optional[int64]
}

func policyBundleV8FieldsFor(b *PolicyBundle) policyBundleV8Fields {
	out := policyBundleV8Fields{
		id: observability.Absent[string](), signerKeyID: observability.Absent[string](),
		changeSummary: observability.Absent[string](), version: observability.Absent[int64](),
	}
	if b == nil {
		return out
	}
	if policyBundleIDPattern.MatchString(b.ID) {
		out.id = observability.Present(b.ID)
	}
	if b.Version >= 1 && b.Version <= maxPolicyBundleVersion {
		out.version = observability.Present(int64(b.Version))
	}
	if policyBundleKeyIDPattern.MatchString(b.SignerKeyID) {
		out.signerKeyID = observability.Present(b.SignerKeyID)
	}
	if summary := strings.TrimSpace(b.ChangeSummary); summary != "" && utf8.ValidString(summary) {
		out.changeSummary = observability.Present(truncateUTF8(summary, maxPolicyBundleChangeSummary))
	}
	return out
}

// policyBundleReceiptV8Fields are the typed receipt attributes.
type policyBundleReceiptV8Fields struct {
	receiptID, state                            string
	deliveryID                                  observability.Optional[string]
	errorCode, effectiveDigest, enforcingDigest observability.Optional[string]
	generation                                  observability.Optional[int64]
	rolledBack, restart                         observability.Optional[bool]
	outcome                                     observability.Outcome
}

func policyBundleReceiptV8FieldsFor(r *PolicyBundleReceipt) (policyBundleReceiptV8Fields, error) {
	if r == nil {
		return policyBundleReceiptV8Fields{}, fmt.Errorf("audit: bundle receipt record needs a receipt")
	}
	if !policyBundleReceiptIDPattern.MatchString(r.ReceiptID) {
		return policyBundleReceiptV8Fields{}, fmt.Errorf("audit: bundle receipt id is not b-<ULID> or r-<ULID>")
	}
	out := policyBundleReceiptV8Fields{
		receiptID: r.ReceiptID, state: r.State, deliveryID: observability.Absent[string](),
		errorCode: observability.Absent[string](), effectiveDigest: observability.Absent[string](),
		enforcingDigest: observability.Absent[string](), generation: observability.Absent[int64](),
		rolledBack: observability.Present(r.RolledBack), restart: observability.Present(r.Restart),
	}
	switch r.State {
	case PolicyBundleConfirmed:
		out.outcome = observability.OutcomeApplied
	case PolicyBundleFailed:
		out.outcome = observability.OutcomeFailed
		if policyBundleCodePattern.MatchString(r.ErrorCode) {
			out.errorCode = observability.Present(r.ErrorCode)
		}
	default:
		return policyBundleReceiptV8Fields{}, fmt.Errorf("audit: bundle receipt state %q is not terminal", r.State)
	}
	if policyBundleDeliveryIDPattern.MatchString(r.DeliveryID) {
		out.deliveryID = observability.Present(r.DeliveryID)
	}
	if policyBundleDigestPattern.MatchString(r.EffectivePolicyDigest) {
		out.effectiveDigest = observability.Present(r.EffectivePolicyDigest)
	}
	if policyBundleDigestPattern.MatchString(r.EnforcingDigest) {
		out.enforcingDigest = observability.Present(r.EnforcingDigest)
	}
	if r.ConfigGeneration > 0 && r.ConfigGeneration <= math.MaxInt64 {
		out.generation = observability.Present(int64(r.ConfigGeneration))
	}
	return out, nil
}

// LogPolicyBundleReceipt records the terminal receipt of a signed policy
// bundle: one config.bundle.receipt record, the
// defenseclaw.policy.bundle.applies counter and, when the device enforces a
// bundle, the defenseclaw.policy.bundle.version gauge. principal is the
// bundle principal the receipt names (control-plane:<tenant>/<admin> or
// operator:<os-admin>), "" when the manifest could not be read. It reports
// only; nothing here changes what is enforced.
//
// With pins, the receipt is a spooled occurrence, as a change is
// (LogConfigChange): its record id is stable (the receipt id), its record
// is built from the receipt and its pin, so every offer is the same record,
// the audit store keeps it once, and delivery, kept by the caller across
// offers, sends it only to the remote destinations that do not have it. A
// store that cannot write the row fails the call, so the caller offers the
// receipt again, but a remote destination that has it does not get it
// again. Without pins (or a FinishedAt that does not parse) the receipt is
// one record under a new id.
func (l *Logger) LogPolicyBundleReceipt(
	principal string, bundle PolicyBundle, receipt PolicyBundleReceipt,
	delivery *observability.RemoteDelivery, pins *ConfigChangePins,
) error {
	if l == nil {
		return nil
	}
	if _, err := policyBundleReceiptV8FieldsFor(&receipt); err != nil {
		return err
	}
	severity := "INFO"
	reason := "policy bundle confirmed"
	if receipt.State == PolicyBundleFailed {
		severity = "MEDIUM"
		reason = "policy bundle failed (" + receipt.ErrorCode + "); the last good policy keeps enforcing"
	}
	after := map[string]any{
		"state":             receipt.State,
		"bundle_id":         bundle.ID,
		"bundle_version":    bundle.Version,
		"signer_key_id":     bundle.SignerKeyID,
		"config_generation": receipt.ConfigGeneration,
		"rolled_back":       receipt.RolledBack,
		"restart":           receipt.Restart,
		"restart_required":  receipt.RestartRequired,
	}
	if receipt.ErrorCode != "" {
		after["error_code"] = receipt.ErrorCode
	}
	if policyBundleDeliveryIDPattern.MatchString(receipt.DeliveryID) {
		after["delivery_id"] = receipt.DeliveryID
	}
	if len(receipt.WarningCodes) > 0 {
		after["warning_codes"] = receipt.WarningCodes
	}
	if len(receipt.DisabledByBundle) > 0 {
		after["disabled_by_bundle"] = receipt.DisabledByBundle
	}
	if receipt.EffectivePolicyDigest != "" {
		after["effective_policy_digest"] = receipt.EffectivePolicyDigest
	}
	if receipt.EnforcingDigest != "" {
		after["enforcing_digest"] = receipt.EnforcingDigest
	}
	actor := strings.TrimSpace(receipt.Actor)
	if actor == "" {
		actor = strings.TrimSpace(principal)
	}
	in := ActivityInput{
		Actor: actor, Principal: strings.TrimSpace(principal), Action: ActionConfigBundleReceipt,
		TargetType: "policy_bundle", TargetID: receipt.ReceiptID, Reason: reason,
		After: after, Severity: severity, Bundle: &bundle, BundleReceipt: &receipt,
	}
	if finishedAt, err := time.Parse(time.RFC3339Nano, receipt.FinishedAt); err == nil && pins != nil {
		in.OccurrenceID = stableOccurrenceID(string(ActionConfigBundleReceipt), receipt.ReceiptID)
		in.OccurredAt, in.RemoteDelivery = finishedAt, delivery
		in.Pins, in.PinKey = pins, receipt.ReceiptID
	}
	return l.logActivityImpl(in)
}

// RecordPolicyBundleVersion records the defenseclaw.policy.bundle.version
// gauge: the version of the bundle the device enforces. The gateway calls it
// at start and when the enforced bundle changes; 0 records nothing.
func (l *Logger) RecordPolicyBundleVersion(ctx context.Context, bundleVersion uint64) error {
	if l == nil || bundleVersion == 0 || bundleVersion > maxPolicyBundleVersion {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	binding := l.runtimeV8BindingSnapshot()
	if binding.emitter == nil {
		return fmt.Errorf("audit: v8 runtime is unavailable")
	}
	return l.recordRuntimeV8GeneratedMetricBatch(ctx, binding, []RuntimeV8GeneratedMetric{
		policyBundleVersionMetric(time.Now().UTC(), string(ActionConfigBundleReceipt), bundleVersion),
	})
}

// policyBundleReceiptMetrics are the companion metrics of a receipt record.
func policyBundleReceiptMetrics(event Event, receipt *PolicyBundleReceipt) []RuntimeV8GeneratedMetric {
	if receipt == nil {
		return nil
	}
	result, code := observability.Present(receipt.State), observability.Absent[string]()
	if receipt.State == PolicyBundleFailed && policyBundleCodePattern.MatchString(receipt.ErrorCode) {
		code = observability.Present(receipt.ErrorCode)
	}
	metrics := []RuntimeV8GeneratedMetric{policyBundleMetric(event.Timestamp, event.Action,
		observability.EventName(observability.TelemetryInstrumentDefenseClawPolicyBundleApplies),
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawPolicyBundleApplies(observability.MetricDefenseClawPolicyBundleAppliesInput{
				Envelope: envelope, Value: 1,
				DefenseClawMetricPolicyBundleResult: result, DefenseClawMetricPolicyBundleErrorCode: code,
			})
		})}
	if receipt.EnforcingVersion > 0 && receipt.EnforcingVersion <= maxPolicyBundleVersion {
		metrics = append(metrics, policyBundleVersionMetric(event.Timestamp, event.Action, receipt.EnforcingVersion))
	}
	return metrics
}

func policyBundleVersionMetric(at time.Time, action string, bundleVersion uint64) RuntimeV8GeneratedMetric {
	return policyBundleMetric(at, action,
		observability.EventName(observability.TelemetryInstrumentDefenseClawPolicyBundleVersion),
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawPolicyBundleVersion(observability.MetricDefenseClawPolicyBundleVersionInput{
				Envelope: envelope, Value: int64(bundleVersion),
			})
		})
}

func policyBundleMetric(
	at time.Time,
	action string,
	family observability.EventName,
	build func(*observability.FamilyBuilder, observability.FamilyEnvelopeInput) (observability.Record, error),
) RuntimeV8GeneratedMetric {
	return RuntimeV8GeneratedMetric{
		family: family,
		build: func(snapshot RuntimeV8BuildContext) (observability.Record, error) {
			if snapshot.ConfigGeneration > math.MaxInt64 || !observability.IsStableToken(snapshot.ConfigDigest) {
				return observability.Record{}, fmt.Errorf("audit: invalid v8 bundle metric build context")
			}
			builder, err := observability.NewFamilyBuilder(
				observability.ClockFunc(func() time.Time { return at.UTC() }),
				observability.TimeOrderedOccurrenceIDs,
			)
			if err != nil {
				return observability.Record{}, err
			}
			return build(builder, observability.FamilyEnvelopeInput{
				ObservedAt: observability.Present(at.UTC()),
				Source:     observability.SourceSystem, Action: action, Phase: "apply",
				Provenance: observability.FamilyProvenanceInput{
					Producer: "audit_logger", BinaryVersion: version.Current().BinaryVersion,
					ConfigGeneration: int64(snapshot.ConfigGeneration), ConfigDigest: snapshot.ConfigDigest,
				},
			})
		},
	}
}
