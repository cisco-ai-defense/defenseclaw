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
	"regexp"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// SubstrateSecretOperation is what one Substrate secret change did to a
// person's value or binding. The values are the closed enum of
// defenseclaw.substrate.secret.operation.
type SubstrateSecretOperation string

const (
	SubstrateSecretSet             SubstrateSecretOperation = "set"
	SubstrateSecretRemoved         SubstrateSecretOperation = "removed"
	SubstrateSecretBindingAdded    SubstrateSecretOperation = "binding_added"
	SubstrateSecretBindingApproved SubstrateSecretOperation = "binding_approved"
	SubstrateSecretBindingDenied   SubstrateSecretOperation = "binding_denied"
	SubstrateSecretExpired         SubstrateSecretOperation = "expired"
)

func (operation SubstrateSecretOperation) valid() bool {
	switch operation {
	case SubstrateSecretSet, SubstrateSecretRemoved, SubstrateSecretBindingAdded,
		SubstrateSecretBindingApproved, SubstrateSecretBindingDenied, SubstrateSecretExpired:
		return true
	}
	return false
}

// SubstrateSecretChangeEvent is one log.substrate.secret.changed record. It
// names the secret, the host it is bound to and the owner's keyed pseudonym;
// it never carries the value, a prefix or a placeholder.
type SubstrateSecretChangeEvent struct {
	Name      string
	Operation SubstrateSecretOperation
	// Host is the bound host ("" when the change is not about one host).
	Host string
	// SubjectKey is the owner's keyed pseudonym (hmac-sha256:<64 hex>), ""
	// when the gateway has no key.
	SubjectKey string
	// Failed marks a change the store refused.
	Failed    bool
	Timestamp time.Time
}

var substrateSecretSubjectKey = regexp.MustCompile(`^hmac-sha256:[0-9a-f]{64}$`)

// RecordSubstrateSecretChange emits one log.substrate.secret.changed record
// under the substrate.secret.changed producer.
func (recorder *SandboxRecorder) RecordSubstrateSecretChange(ctx context.Context, input SubstrateSecretChangeEvent) error {
	if err := recorder.ready(); err != nil {
		return err
	}
	if !input.Operation.valid() {
		return fmt.Errorf("audit: substrate secret operation %q is not registered", input.Operation)
	}
	name := strings.TrimSpace(input.Name)
	if name == "" {
		return fmt.Errorf("audit: substrate secret change names no secret")
	}
	outcome, severity := observability.OutcomeApplied, "INFO"
	if input.Failed {
		outcome, severity = observability.OutcomeFailed, "LOW"
	}
	target := observability.Absent[string]()
	if host := strings.ToLower(strings.TrimSpace(input.Host)); host != "" {
		target = optionalNetworkIdentifier(host + ":443")
	}
	subject := observability.Absent[string]()
	if substrateSecretSubjectKey.MatchString(input.SubjectKey) {
		subject = observability.Present(input.SubjectKey)
	}
	event := recorder.newEvent(ctx, ActionSubstrateSecretChanged, SandboxIdentity{}, name, severity, input.Timestamp)
	return recorder.emit(ctx, sandboxV8Log{
		action: ActionSubstrateSecretChanged, event: event, bucket: observability.BucketComplianceActivity,
		eventName: observability.TelemetryEventSubstrateSecretChanged, phase: "secret", outcome: outcome,
		build: func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput,
			severity observability.Optional[observability.Severity], logLevel observability.Optional[observability.LogLevel],
		) (observability.Record, error) {
			return builder.BuildLogSubstrateSecretChanged(observability.LogSubstrateSecretChangedInput{
				Envelope: envelope, Severity: severity, LogLevel: logLevel, Outcome: outcome,
				DefenseClawSecretName: name, DefenseClawSubstrateSecretOperation: string(input.Operation),
				DefenseClawNetworkTargetRef: target, DefenseClawSubjectKey: subject,
			})
		},
	}, nil)
}
