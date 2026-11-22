//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi/ateapifake"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
)

// GAP-0182: a refused create answers with the refusal code, its reason and
// the actor UID (the launcher used to print only "actor refused").
func TestSubstrateRefusedCreateNamesReasonAndUID(t *testing.T) {
	fake := ateapifake.New()
	fake.PutTemplate(&ateapi.ActorTemplate{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: "cc"}})
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.Profiles = func(identity.Person, string, string, bool) (string, string, error) { return "eng", "eng-web", nil }
	})
	st := f.api.substrateState()
	var uid string
	st.cfg.Actions = &SubstrateATEActions{Client: fake, Ensure: func(ctx context.Context, atespace, name string) error {
		a, err := fake.GetActor(ctx, ateapi.Ref(atespace, name))
		if err != nil {
			return err
		}
		uid = a.GetMetadata().GetUid()
		return fmt.Errorf("%w: %w", ErrSubstrateActorRefused, &controller.RefusedError{Atespace: atespace, Name: name, UID: uid,
			Code: controller.EventTemplateUnverified, Reason: "template eng-web/cc is not attested: no signature"})
	}}
	rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors", "p-alice", `{"template":"cc","connector":"claudecode","name":"alice-0182"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("create %d %s", rec.Code, rec.Body)
	}
	var e struct{ Reason, Refusal, Detail, Actor, ActorUID string }
	var raw map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &raw)
	_ = json.Unmarshal(rec.Body.Bytes(), &e)
	e.ActorUID, _ = raw["actor_uid"].(string)
	if e.Reason != "actor_refused" || e.Refusal != controller.EventTemplateUnverified || e.Detail != "template eng-web/cc is not attested: no signature" ||
		e.Actor != "eng-web/alice-0182" || e.ActorUID == "" || e.ActorUID != uid {
		t.Fatalf("answer %s", rec.Body)
	}
	if _, err := fake.GetActor(context.Background(), ateapi.Ref("eng-web", "alice-0182")); !ateapi.IsNotFound(err) {
		t.Errorf("the refused actor stayed: %v", err)
	}
}
