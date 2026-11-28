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
	"path"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// Actor identity on hook records (GAP-0121, PLAN 11): a Substrate hook's
// audit row and its v8 hook decision carry the actor (atespace, name,
// UID, template, batch, kit, parent) and the run mode, all from the
// registration the gateway verified, never from the actor. The person is
// already on the record as its verified subject (contextWithSubstratePerson).

// hookV8SubstrateFields are the correlation.sandbox Substrate attributes.
type hookV8SubstrateFields struct {
	Runtime, Driver, Atespace, Actor, ActorUID, Template, BatchID, KitVersion, ParentUID, RunMode observability.Optional[string]
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
	f.Driver = substrateDriver(reg.SandboxClass)
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
		extra := map[string]string{
			"sandbox_runtime":     "substrate",
			"substrate_atespace":  actor.Atespace,
			"substrate_actor":     actor.Name,
			"substrate_actor_uid": actor.UID,
		}
		if firstHookAfterResume(ctx) {
			extra["substrate_first_hook_after_resume"] = "true"
		}
		return extra
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
	if a := reg.Person.Assurance(); a != "" {
		extra["substrate_person_assurance"] = a
	}
	if reg.Attributed {
		extra["substrate_person"], extra["substrate_person_kind"] = "", "atespace"
	}
	if firstHookAfterResume(ctx) {
		// The actor's first hook call after a resume (GAP-0486).
		extra["substrate_first_hook_after_resume"] = "true"
	}
	for k, v := range substrateFactsAuditExtra(ctx) {
		extra[k] = v
	}
	return extra
}

// substrateDriver is the defenseclaw.sandbox.driver of an actor's class
// (GAP-0454): gvisor or microvm; absent when the registration names none.
func substrateDriver(class string) observability.Optional[string] {
	switch class = strings.ToLower(strings.TrimSpace(class)); class {
	case config.SubstrateSandboxGVisor, config.SubstrateSandboxMicroVM:
		return observability.Present(class)
	}
	return observability.Absent[string]()
}

// maxSubstrateFactsAuditPaths bounds the resolved paths one hook row lists.
const maxSubstrateFactsAuditPaths = 8

// substrateFactsAuditExtra says what the kit claimed about the actor's file
// system on a hook post (substrate-1 GAP-0475): substrate_facts=none for a
// post with no facts, else substrate_facts=claimed with the source (the
// kit, code that runs as the agent's user), the proofs it made and each
// path argument it resolved through a link, as spelling->target. The
// gateway checks none of it; a claim only ever adds a finding (GAP-0471).
func substrateFactsAuditExtra(ctx context.Context) map[string]string {
	env, ok := substrateEnvelopeFrom(ctx)
	if !ok {
		return nil
	}
	facts := env.Facts
	if facts == nil || (len(facts.Paths) == 0 && len(facts.Files) == 0 && len(facts.Skills) == 0 &&
		len(facts.Proofs) == 0 && !facts.Truncated) {
		return map[string]string{"substrate_facts": "none"}
	}
	extra := map[string]string{
		"substrate_facts": "claimed", "substrate_facts_assurance": "claimed", "substrate_facts_source": "kit",
		"substrate_facts_paths": strconv.Itoa(len(facts.Paths)),
	}
	if len(facts.Proofs) > 0 {
		extra["substrate_facts_proofs"] = auditFactToken(strings.Join(facts.Proofs, ","))
	}
	var resolved []string
	for _, fact := range facts.Paths {
		if fact.Resolved == "" || path.Clean(fact.Resolved) == path.Clean(fact.Abs) {
			continue
		}
		if len(resolved) == maxSubstrateFactsAuditPaths {
			resolved = append(resolved, "...")
			break
		}
		resolved = append(resolved, auditFactToken(fact.Path)+"->"+auditFactToken(fact.Resolved))
	}
	if len(resolved) > 0 {
		extra["substrate_facts_resolved_path"] = strings.Join(resolved, ",")
	}
	if facts.Truncated {
		extra["substrate_facts_truncated"] = "true"
	}
	return extra
}

// auditFactToken is a kit-claimed value made safe for a key=value audit
// field: no spaces, separators, control or format runes (C0, C1, bidi
// controls, zero-width marks), line or paragraph separators or invalid
// UTF-8, at most 256 bytes cut on a rune boundary (substrate-1 GAP-0549).
func auditFactToken(value string) string {
	value = strings.Map(func(r rune) rune {
		if r <= ' ' || r == 0x7f || r == ',' || r == '=' || r == '"' || r == '\\' || r == utf8.RuneError ||
			unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			return '_'
		}
		return r
	}, value)
	if len(value) > 256 {
		cut := 256
		for cut > 0 && !utf8.RuneStart(value[cut]) {
			cut--
		}
		value = value[:cut]
	}
	return value
}
