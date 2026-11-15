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

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// Actor identity on hook records (GAP-0121, PLAN 11): a Substrate hook's
// audit row and its v8 hook decision carry the actor (atespace, name,
// UID, template, batch, kit, parent) and the run mode, all from the
// registration the gateway verified, never from the actor. The person is
// already on the record as its verified subject (contextWithSubstratePerson).

// hookV8SubstrateFields are the correlation.sandbox Substrate attributes.
type hookV8SubstrateFields struct {
	Runtime, Atespace, Actor, ActorUID, Template, BatchID, KitVersion, ParentUID, RunMode observability.Optional[string]
}

func hookV8Substrate(ctx context.Context) hookV8SubstrateFields {
	var f hookV8SubstrateFields
	if _, ok := substrateActorFrom(ctx); !ok {
		return f
	}
	reg, ok := substrateRegistrationFrom(ctx)
	if !ok {
		return f
	}
	f.Runtime = observability.Present("substrate")
	f.Atespace = hookV8OptionalIdentifier(reg.Atespace)
	f.Actor = hookV8OptionalIdentifier(reg.Name)
	f.ActorUID = hookV8OptionalIdentifier(reg.UID)
	f.Template = hookV8OptionalIdentifier(reg.Template)
	f.BatchID = hookV8OptionalIdentifier(reg.BatchID)
	f.KitVersion = hookV8OptionalIdentifier(reg.KitVersion)
	f.ParentUID = hookV8OptionalIdentifier(reg.ParentUID)
	f.RunMode = observability.Present(substrateMode(reg))
	return f
}

// hookActorAuditExtra is the identity every hook audit row of a request
// carries: the sandbox binding's and the verified Substrate actor's. A path
// that builds an envelope outside hookRequestAuditExtra (the recovered-panic
// finalization) takes it from here, so no row names less than the others.
func hookActorAuditExtra(ctx context.Context) map[string]string {
	return mergeHookEnvelopeExtra(sandboxHookAuditExtra(ctx), substrateHookAuditExtra(ctx))
}

// substrateHookAuditExtra is the same identity on the hook's audit row.
func substrateHookAuditExtra(ctx context.Context) map[string]string {
	actor, ok := substrateActorFrom(ctx)
	if !ok {
		return nil
	}
	reg, ok := substrateRegistrationFrom(ctx)
	if !ok {
		// The actor the gateway verified names itself: atespace, name and
		// UID are the token's claims it already checked (no new input). The
		// person and run mode need the registration.
		return map[string]string{
			"sandbox_runtime":     "substrate",
			"substrate_atespace":  actor.Atespace,
			"substrate_actor":     actor.Name,
			"substrate_actor_uid": actor.UID,
		}
	}
	extra := map[string]string{
		"sandbox_runtime":       "substrate",
		"substrate_atespace":    reg.Atespace,
		"substrate_actor":       reg.Name,
		"substrate_actor_uid":   reg.UID,
		"substrate_run_mode":    substrateMode(reg),
		"substrate_person":      reg.Person.ID(),
		"substrate_person_kind": reg.Person.Kind,
	}
	for k, v := range map[string]string{"substrate_template": reg.Template, "substrate_batch_id": reg.BatchID,
		"substrate_kit_version": reg.KitVersion, "substrate_parent_uid": reg.ParentUID} {
		if v != "" {
			extra[k] = v
		}
	}
	if reg.Attributed {
		extra["substrate_person"], extra["substrate_person_kind"] = "", "atespace"
	}
	return extra
}
