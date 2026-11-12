// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// GAP-0121: a Substrate hook's audit row and v8 hook decision carry the
// actor and the run mode from the registration; a host hook carries none.
func TestSubstrateHookRecordsCarryTheActor(t *testing.T) {
	key, err := sandboxreg.SubstrateKey("eng-web", subUID2)
	if err != nil {
		t.Fatal(err)
	}
	reg := registry.Registration{Key: key, Atespace: "eng-web", Name: "bob-1", UID: subUID2, Connector: "codex",
		Template: "eng-web/codex", BatchID: "b1", KitVersion: "0.1.0", Unattended: true, Person: ownerOf(bob)}
	ctx := withSubstrateActor(context.Background(), verifiedSubstrateActor("eng-web", "bob-1", subUID2, "actor/eng-web/bob-1", key))
	ctx = context.WithValue(ctx, substrateRegistrationKey{}, reg)

	extra := substrateHookAuditExtra(ctx)
	for k, want := range map[string]string{"substrate_atespace": "eng-web", "substrate_actor": "bob-1", "substrate_actor_uid": subUID2,
		"substrate_template": "eng-web/codex", "substrate_batch_id": "b1", "substrate_run_mode": "unattended",
		"substrate_person": bob.ID(), "sandbox_runtime": "substrate"} {
		if extra[k] != want {
			t.Errorf("audit extra %s = %q, want %q", k, extra[k], want)
		}
	}
	f := hookV8Substrate(ctx)
	for name, opt := range map[string]struct {
		got  string
		want string
	}{
		"atespace": {get(f.Atespace), "eng-web"}, "actor": {get(f.Actor), "bob-1"}, "uid": {get(f.ActorUID), subUID2},
		"batch": {get(f.BatchID), "b1"}, "run mode": {get(f.RunMode), "unattended"}, "runtime": {get(f.Runtime), "substrate"},
	} {
		if opt.got != opt.want {
			t.Errorf("v8 %s = %q, want %q", name, opt.got, opt.want)
		}
	}
	if f.ParentUID.IsPresent() {
		t.Error("parent uid on a first actor")
	}
	// A host hook has no actor: nothing is added.
	if substrateHookAuditExtra(context.Background()) != nil || hookV8Substrate(context.Background()).ActorUID.IsPresent() {
		t.Fatal("host hook carries actor fields")
	}
	// A registration without the verified actor (an unsealed context) adds nothing either.
	bare := context.WithValue(context.Background(), substrateRegistrationKey{}, reg)
	if substrateHookAuditExtra(bare) != nil {
		t.Fatal("unsealed context carries actor fields")
	}
}

func get(o observability.Optional[string]) string {
	v, _ := o.Get()
	return v
}
