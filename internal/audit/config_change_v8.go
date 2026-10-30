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
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// ConfigChange is one trust anchor install or protected credential set or
// removal on a standalone managed device, as the root command recorded it
// in the change spool (enterprisestatus.ChangeEvent). It never carries a
// credential value or a hash of one.
type ConfigChange struct {
	EventID string
	// Kind is ConfigChangeTrustAnchors or ConfigChangeSecret; Action is
	// install, set or remove; Outcome is ConfigChangeApplied,
	// ConfigChangeRefused or ConfigChangeFailed with ReasonCode.
	Kind, Action, Outcome, ReasonCode string
	// Actor is the local OS account that ran the command; ChangedAt the
	// time of the change (RFC 3339), which is the time of its record.
	Actor, ChangedAt string
	// SHA256 and PreviousSHA256 are the installed and the replaced anchor
	// file; KeyIDsAdded and KeyIDsRemoved the signing keys that changed.
	SHA256, PreviousSHA256     string
	KeyIDsAdded, KeyIDsRemoved []string
	// SecretName is the credential name ("" when the command refused it).
	SecretName string
	// FirstOffer says no gateway process can have offered this change
	// before: it entered the change spool while this gateway's reporter ran,
	// and this is its first offer. Only then may an offer of a change
	// without a record pin go to the remote destinations while the audit
	// store cannot say whether it holds the change's row.
	FirstOffer bool
}

// configChangeMetricActor is the only actor label of the activity counters
// of a change (defenseclaw.activity.total, defenseclaw.activity.diff_entries).
// Actor, the OS account with its uid or SID, stays in the audit record.
const configChangeMetricActor = "local_account"

// Kinds and outcomes of a ConfigChange (enterprisestatus.ChangeEvent).
const (
	ConfigChangeTrustAnchors = "trust_anchors"
	ConfigChangeSecret       = "secret"
	ConfigChangeApplied      = "applied"
	ConfigChangeRefused      = "refused"
	ConfigChangeFailed       = "failed"
)

var (
	configChangeIDPattern     = lazyregexp.New(`^c-[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
	configChangeSHA256Pattern = lazyregexp.New(`^[0-9a-f]{64}$`)
	configChangeSecretPattern = lazyregexp.New(`^[a-z0-9][a-z0-9-]{0,62}$`)
)

// configChangeV8Fields are the typed attributes of a change record.
type configChangeV8Fields struct {
	id                  string
	outcome             observability.Outcome
	reasonCode          observability.Optional[string]
	sha256, previous    observability.Optional[string]
	keysAdded, keysGone observability.Optional[[]string]
	secretName          observability.Optional[string]
	secretAction        string
}

// configChangeAction is the audit action of a change.
func configChangeAction(change ConfigChange) (Action, error) {
	switch change.Kind {
	case ConfigChangeTrustAnchors:
		return ActionConfigTrustAnchorsChanged, nil
	case ConfigChangeSecret:
		if change.Outcome == ConfigChangeApplied {
			return ActionConfigSecretChanged, nil
		}
		return ActionConfigSecretChangeFailed, nil
	}
	return "", fmt.Errorf("audit: config change kind %q is not registered", change.Kind)
}

func configChangeV8FieldsFor(change *ConfigChange) (configChangeV8Fields, error) {
	if change == nil {
		return configChangeV8Fields{}, fmt.Errorf("audit: config change record needs a change")
	}
	if !configChangeIDPattern.MatchString(change.EventID) {
		return configChangeV8Fields{}, fmt.Errorf("audit: config change id is not c-<ULID>")
	}
	out := configChangeV8Fields{
		id: change.EventID, reasonCode: observability.Absent[string](),
		sha256: observability.Absent[string](), previous: observability.Absent[string](),
		keysAdded: observability.Absent[[]string](), keysGone: observability.Absent[[]string](),
		secretName: observability.Absent[string](), secretAction: change.Action,
	}
	switch change.Outcome {
	case ConfigChangeApplied:
		out.outcome = observability.OutcomeApplied
	case ConfigChangeRefused:
		out.outcome = observability.OutcomeRejected
	case ConfigChangeFailed:
		out.outcome = observability.OutcomeFailed
	default:
		return configChangeV8Fields{}, fmt.Errorf("audit: config change outcome %q is not registered", change.Outcome)
	}
	if change.Outcome != ConfigChangeApplied {
		if !policyBundleCodePattern.MatchString(change.ReasonCode) {
			return configChangeV8Fields{}, fmt.Errorf("audit: a refused or failed config change needs a reason code")
		}
		out.reasonCode = observability.Present(change.ReasonCode)
	}
	switch change.Kind {
	case ConfigChangeTrustAnchors:
		if change.Action != "install" {
			return configChangeV8Fields{}, fmt.Errorf("audit: trust anchor change action %q is not install", change.Action)
		}
		if configChangeSHA256Pattern.MatchString(change.SHA256) {
			out.sha256 = observability.Present(change.SHA256)
		}
		if configChangeSHA256Pattern.MatchString(change.PreviousSHA256) {
			out.previous = observability.Present(change.PreviousSHA256)
		}
		out.keysAdded, out.keysGone = configChangeKeyIDs(change.KeyIDsAdded), configChangeKeyIDs(change.KeyIDsRemoved)
	case ConfigChangeSecret:
		if change.Action != "set" && change.Action != "remove" {
			return configChangeV8Fields{}, fmt.Errorf("audit: credential change action %q is not set or remove", change.Action)
		}
		if configChangeSecretPattern.MatchString(change.SecretName) {
			out.secretName = observability.Present(change.SecretName)
		} else if change.Outcome == ConfigChangeApplied {
			return configChangeV8Fields{}, fmt.Errorf("audit: an applied credential change names the credential")
		}
	default:
		return configChangeV8Fields{}, fmt.Errorf("audit: config change kind %q is not registered", change.Kind)
	}
	return out, nil
}

func configChangeKeyIDs(ids []string) observability.Optional[[]string] {
	var out []string
	for _, id := range ids {
		if policyBundleKeyIDPattern.MatchString(id) {
			out = append(out, id)
		}
	}
	if len(out) == 0 {
		return observability.Absent[[]string]()
	}
	sort.Strings(out)
	return observability.Present(out)
}

// LogConfigChange records one trust anchor or protected credential change:
// config.trust_anchors.changed, config.secret.changed or
// config.secret.change_failed. It reports only. The record is built from
// the change (its id, time and content) and its pin in pins (the run,
// sidecar, binary and config of its first offer, flushed before any sink
// got it), so every offer of the same change, after a restart or a reload
// too, is the same record. It returns nil once the audit row survives a
// power loss; delivery, kept by the caller across offers of the same
// change, tells when every remote destination has it. The two are separate
// sinks of the change: a store that cannot answer fails the call but not
// the remote offer.
func (l *Logger) LogConfigChange(
	change ConfigChange, delivery *observability.RemoteDelivery, pins *ConfigChangePins,
) error {
	if l == nil {
		return nil
	}
	action, err := configChangeAction(change)
	if err != nil {
		return err
	}
	if _, err := configChangeV8FieldsFor(&change); err != nil {
		return err
	}
	changedAt, err := time.Parse(time.RFC3339Nano, change.ChangedAt)
	if err != nil {
		return fmt.Errorf("audit: config change time is not RFC 3339")
	}
	after := map[string]any{"event_id": change.EventID, "kind": change.Kind, "action": change.Action,
		"outcome": change.Outcome, "changed_at": change.ChangedAt}
	if change.ReasonCode != "" {
		after["reason_code"] = change.ReasonCode
	}
	targetType, targetID := "trust_anchors", change.EventID
	var reason string
	switch change.Kind {
	case ConfigChangeTrustAnchors:
		for key, value := range map[string]string{"sha256": change.SHA256, "previous_sha256": change.PreviousSHA256} {
			if value != "" {
				after[key] = value
			}
		}
		if len(change.KeyIDsAdded) > 0 {
			after["key_ids_added"] = change.KeyIDsAdded
		}
		if len(change.KeyIDsRemoved) > 0 {
			after["key_ids_removed"] = change.KeyIDsRemoved
		}
		reason = "trust anchors " + change.Outcome
	case ConfigChangeSecret:
		targetType = "secret"
		if change.SecretName != "" {
			after["secret_name"] = change.SecretName
			targetID = change.SecretName
		}
		reason = "credential " + change.Action + " " + change.Outcome
	}
	if change.ReasonCode != "" {
		reason += " (" + change.ReasonCode + ")"
	}
	severity := "INFO"
	if change.Outcome != ConfigChangeApplied {
		severity = "MEDIUM"
	}
	actor := strings.TrimSpace(change.Actor)
	return l.logActivityImpl(ActivityInput{
		Actor: actor, Action: action, TargetType: targetType, TargetID: targetID, Reason: reason,
		After: after, Severity: severity, ConfigChange: &change,
		OccurrenceID:   stableOccurrenceID("config.change", change.EventID),
		OccurredAt:     changedAt,
		RemoteDelivery: delivery,
		Pins:           pins, PinKey: change.EventID,
	})
}

// stableOccurrenceID is the audit event id of a producer event with its own
// durable id (a change event), so the store records it once however often
// it is offered.
func stableOccurrenceID(kind, id string) string {
	return uuid.NewSHA1(stableOccurrenceNamespace, []byte(kind+"\x00"+id)).String()
}

var stableOccurrenceNamespace = uuid.MustParse("5b1f9a0e-3c2d-5e8f-9a41-0d6c2b7e4f13")
