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
	"slices"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/asks"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
	"github.com/defenseclaw/defenseclaw/internal/substrate/render"
	"github.com/defenseclaw/defenseclaw/internal/substrate/secretbind"
)

// Statuses of a self-service binding that keep it out of every policy
// (B1 2.1, 2.4), beside set, not set, managed, unknown and waiting.
const (
	substrateSecretDenied     = "denied"
	substrateSecretAskExpired = "ask expired"
	substrateSecretExpired    = "expired"
	substrateSecretUncovered  = "not covered"
	substrateSecretNotApplied = "approved, not applied"
	substrateSecretLocked     = "locked"
	substrateSecretFormChange = "template changed"
)

// substrateSecretEntry is one secret as list and test show it to the
// caller: the substrate.secrets entry, the caller's own binding behind it
// (nil for an administrator's entry) and the profiles it is bound to.
type substrateSecretEntry struct {
	sec      config.SubstrateSecret
	binding  *secretbind.Binding
	profiles []string
	// uncovered: an unapproved binding whose template is gone or no
	// longer covers any of its hosts, so it does not render (RV3 P2-2).
	uncovered bool
	// formChanged: the template's form (or basic user) is not the one the
	// stored value was formed with, so the header would be invalid (RV3 P4-3).
	formChanged bool
}

// substrateSecretEntries are the secrets the caller may see: the
// administrator's entries bound to their profile (every entry for an
// administrator), then their own bindings in every state. An own binding
// keeps its template's profiles, which decide which agents get it.
func (a *APIServer) substrateSecretEntries(st *substrateState, c substrateCaller, profile string) []substrateSecretEntry {
	var out []substrateSecretEntry
	for _, sec := range st.cfg.Secrets {
		if substrateSecretBound(sec, profile, c.admin) {
			out = append(out, substrateSecretEntry{sec: sec, profiles: sec.Profiles})
		}
	}
	if st.cfg.Bindings == nil || c.person.Subject == "" || st.selfService().EffectiveMode() == config.SelfServiceOff {
		return out
	}
	catalog := secretbind.Catalog(st.secretTemplates())
	ss := st.selfService()
	for _, b := range st.cfg.Bindings.ForOwner(render.PersonKey(c.person.Subject)) {
		t, found := secretbind.Find(catalog, b.Template)
		sec := secretbind.SecretFor(t, ss.EffectiveProvider(), ss.EffectiveNamespace(), b, ss.AllowEchoBindings)
		uncovered := !found || (b.AskID == "" && !slices.ContainsFunc(b.Hosts, t.Covers))
		changed := found && b.StoredForm != "" && t.FormStamp(b) != b.StoredForm
		out = append(out, substrateSecretEntry{sec: sec, binding: &b, profiles: sec.Profiles, uncovered: uncovered, formChanged: changed})
	}
	return out
}

// substrateBindingAsks maps the ids of the caller's binding asks to their
// state. nil means the ask store did not answer (or there is none): a
// waiting binding then stays "waiting on admin".
func (a *APIServer) substrateBindingAsks(ctx context.Context, st *substrateState, c substrateCaller) map[string]string {
	if st.cfg.Asks == nil {
		return nil
	}
	list, err := st.cfg.Asks.List(ctx, asks.ListRequest{OwnerID: ownerOf(c.person).ID()})
	if err != nil {
		return nil
	}
	out := make(map[string]string, len(list))
	for _, ask := range list {
		if ask.Kind == asks.KindSecretBinding {
			out[ask.ID] = ask.State
		}
	}
	return out
}

// substrateSecretState is the status of one secret for the person whose
// subject is given, and the reason code of a status that keeps it out of
// a policy (B1 2.4). A waiting binding whose ask expired, was denied or is
// gone can never become active: it says so instead of waiting on admin.
// A Kubernetes source with no secret store is unknown
// (secret_store_unavailable), never "managed outside DefenseClaw".
func (a *APIServer) substrateSecretState(ctx context.Context, st *substrateState, e substrateSecretEntry, subject string,
	askStates map[string]string, now time.Time) (status, reason string) {
	if b := e.binding; b != nil {
		switch {
		case st.selfService().EffectiveMode() != config.SelfServiceBindings:
			// values_only renders no binding, whatever its state (RV4 F3).
			return substrateSecretLocked, "secret_bindings_locked"
		case b.State == secretbind.Denied:
			return substrateSecretDenied, "secret_binding_denied"
		case b.State == secretbind.Waiting:
			if askStates == nil {
				return substrateSecretWaiting, "secret_binding_outside_templates"
			}
			switch state, ok := askStates[b.AskID]; {
			case ok && state == asks.StateDenied:
				return substrateSecretDenied, "secret_binding_denied"
			case ok && state == asks.StateApproved:
				// The approval did not reach the binding store (RV4 F2).
				return substrateSecretNotApplied, "secret_binding_not_applied"
			case !ok || state == asks.StateExpired:
				return substrateSecretAskExpired, "secret_binding_ask_expired"
			}
			return substrateSecretWaiting, "secret_binding_outside_templates"
		case b.Expired(now):
			return substrateSecretExpired, "secret_expired"
		case e.uncovered:
			return substrateSecretUncovered, "secret_binding_not_covered"
		case e.formChanged:
			return substrateSecretFormChange, "secret_binding_form_changed"
		}
	}
	ns, name, key, ok := substrateK8sSource(substrateSecretFor(e.sec, subject))
	switch {
	case !ok:
		return substrateSecretManaged, ""
	case st.cfg.SecretStore == nil:
		return substrateSecretUnknown, "secret_store_unavailable"
	}
	found, err := st.cfg.SecretStore.Exists(ctx, ns, name, key)
	switch {
	case err != nil:
		return substrateSecretUnknown, "secret_store_unavailable"
	case !found:
		return substrateSecretNotSet, ""
	}
	return substrateSecretSet, ""
}

// substrateSecretUsable reports a status under which the cluster adds the
// value to an agent's requests.
func substrateSecretUsable(status string) bool {
	return status == substrateSecretSet || status == substrateSecretManaged
}

// substrateSecretForActor says why the actor's policy leaves the secret out
// before looking at the policy: its profile is not one the secret is for,
// or a personal secret meets an actor without a signed-in person. These
// are the render's own checks (render.bindSecrets), in its order.
func substrateSecretForActor(e substrateSecretEntry, reg registry.Registration) string {
	matched := false
	for _, g := range e.profiles {
		if ok, err := path.Match(g, reg.Profile); err == nil && ok {
			matched = true
			break
		}
	}
	switch {
	case e.binding != nil && reg.Person.Subject != "" && render.PersonKey(reg.Person.Subject) != e.binding.Owner:
		// An own binding reaches only its owner's agents (the controller
		// renders it per person).
		return "secret_binding_other_person"
	case !matched:
		return render.ReasonSecretProfile
	case e.sec.Scope == render.ScopePerPerson && reg.Person.Subject == "":
		return render.ReasonSecretNoPerson
	}
	return ""
}

// substrateSecretAgents names the caller's live agents that get the secret:
// those whose profile it is for, when its status is usable. nil when the
// registrations do not answer.
func substrateSecretAgents(e substrateSecretEntry, status string, regs []registry.Registration) []string {
	out := []string{}
	if !substrateSecretUsable(status) {
		return out
	}
	for _, reg := range regs {
		if !reg.Deleted && substrateSecretForActor(e, reg) == "" {
			out = append(out, reg.Name)
		}
	}
	return out
}

// substratePolicyCarries reports whether an egress policy adds the secret
// source uri on some host.
func substratePolicyCarries(p *ateapi.EgressPolicy, uri string) bool {
	for _, r := range p.GetRules() {
		for _, h := range r.GetHttps().GetEffects().GetReplaceHeaders() {
			if h.GetCredentialUri() == uri {
				return true
			}
		}
	}
	return false
}

// substrateSecretInPolicy answers test --agent: whether the actor's policy
// in force carries the secret, and the reason code when it does not. in is
// nil when it is not known (no policy reader, or the control API did not
// answer).
func (a *APIServer) substrateSecretInPolicy(ctx context.Context, st *substrateState, e substrateSecretEntry,
	status, statusReason string, reg registry.Registration) (in *bool, reason string) {
	no, yes := false, true
	switch {
	case !substrateSecretUsable(status):
		if statusReason == "" {
			statusReason = "secret_not_set"
		}
		return &no, statusReason
	case substrateSecretForActor(e, reg) != "":
		return &no, substrateSecretForActor(e, reg)
	case st.cfg.Policies == nil:
		return nil, ""
	}
	pol, err := st.cfg.Policies.GetActorEgressPolicy(ctx, ateapi.Ref(reg.Atespace, reg.Name))
	switch {
	case ateapi.IsNotFound(err):
		return &no, "secret_not_in_policy"
	case err != nil:
		return nil, ""
	case substratePolicyCarries(pol, substrateSecretFor(e.sec, reg.Person.Subject)):
		return &yes, ""
	}
	return &no, "secret_not_in_policy"
}
