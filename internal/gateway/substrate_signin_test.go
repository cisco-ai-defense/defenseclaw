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

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// signinActions creates actors whose template runs connector, and counts
// what the gateway does with them.
type signinActions struct {
	f         *substrateFixture
	connector string
	attestErr error
	created   int
	deleted   int
}

func (a *signinActions) Create(_ context.Context, req SubstrateCreate) (SubstrateCreated, error) {
	a.created++
	a.f.live[req.Atespace+"/new-1"] = identity.LiveActor{UID: subUIDOther, State: "SUSPENDED"}
	return SubstrateCreated{Atespace: req.Atespace, Name: "new-1", UID: subUIDOther, Template: req.Template, Connector: a.connector}, nil
}

// TemplateConnector is the connector label of the template ("" = none).
func (a *signinActions) TemplateConnector(context.Context, string, string) (string, error) {
	if a.attestErr != nil {
		return "", a.attestErr
	}
	return a.connector, nil
}

func (a *signinActions) Resume(context.Context, string, string) error { return nil }

func (a *signinActions) Delete(context.Context, string, string) error {
	a.deleted++
	return nil
}

func signinFixture(t *testing.T, managed bool, connector string) (*substrateFixture, *signinActions) {
	t.Helper()
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.Managed = managed
		c.SecretPlaceholders = func(names []string) []string {
			var out []string
			for _, n := range names {
				if n == "cursor-key" {
					out = append(out, "CURSOR_API_KEY")
				}
			}
			return out
		}
		c.Profiles = func(_ identity.Person, requested, _ string, _ bool) (string, string, error) {
			if requested != "eng" {
				return "", "", errors.New("no")
			}
			return "eng", "eng-web", nil
		}
	})
	acts := &signinActions{f: f, connector: connector}
	f.api.substrateState().cfg.Actions = acts
	return f, acts
}

func create(t *testing.T, f *substrateFixture, body string) (int, map[string]any) {
	t.Helper()
	rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors", "p-alice", body)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestSubstrateManagedRefusesASigninConnectorAtCreate(t *testing.T) {
	// The launcher names the connector: refused before an actor exists.
	f, acts := signinFixture(t, true, "cursor")
	code, out := create(t, f, `{"profile":"eng","template":"cursor-tpl","connector":"cursor"}`)
	if code != http.StatusForbidden || out["reason"] != "subscription_signin_refused" {
		t.Fatalf("create cursor in managed: %d %v", code, out)
	}
	if msg, _ := out["message"].(string); !strings.Contains(msg, "managed") || !strings.Contains(msg, "CURSOR_API_KEY") {
		t.Fatalf("refusal message %q does not explain the rule or the fix", msg)
	}
	if acts.created != 0 {
		t.Fatalf("an actor was created (%d) for a refused request", acts.created)
	}

	// The launcher omits the connector: the template's connector decides,
	// and the refusal comes before any actor exists (GAP-0160).
	f, acts = signinFixture(t, true, "devin")
	code, out = create(t, f, `{"profile":"eng","template":"devin-tpl"}`)
	if code != http.StatusForbidden || out["reason"] != "subscription_signin_refused" {
		t.Fatalf("create devin (template connector) in managed: %d %v", code, out)
	}
	if acts.created != 0 || acts.deleted != 0 {
		t.Fatalf("created %d, deleted %d: a refused create makes no actor", acts.created, acts.deleted)
	}
	if _, ok, _ := f.regs.Get(context.Background(), "eng-web", subUIDOther); ok {
		t.Fatal("a refused create left a registration")
	}
}

// One create rule (GAP-0160): a named connector must equal the template's,
// an omitted one is the template's, and neither is connector_required.
func TestSubstrateCreateConnectorRule(t *testing.T) {
	f, acts := signinFixture(t, false, "claudecode")
	if code, out := create(t, f, `{"profile":"eng","template":"claude-wave1","connector":"cursor"}`); code != http.StatusBadRequest || out["reason"] != "connector_mismatch" {
		t.Fatalf("named cursor on a claudecode template: %d %v", code, out)
	}
	if acts.created != 0 {
		t.Fatalf("a mismatch made %d actors", acts.created)
	}
	if code, out := create(t, f, `{"profile":"eng","template":"claude-wave1"}`); code != http.StatusCreated {
		t.Fatalf("omitted connector, template claudecode: %d %v", code, out)
	}
	f, _ = signinFixture(t, false, "")
	if code, out := create(t, f, `{"profile":"eng","template":"unlabelled"}`); code != http.StatusBadRequest || out["reason"] != "connector_required" {
		t.Fatalf("no connector anywhere: %d %v", code, out)
	}
}

func TestSubstrateManagedAllowsAVendorKeyAndTheGatewayRoute(t *testing.T) {
	f, _ := signinFixture(t, true, "cursor")
	code, out := create(t, f, `{"profile":"eng","template":"cursor-tpl","connector":"cursor","secrets":["cursor-key"]}`)
	if code != http.StatusCreated {
		t.Fatalf("cursor with its vendor key bound: %d %v", code, out)
	}
	if _, has := out["warnings"]; has {
		t.Fatalf("a vendor key route carries a warning: %v", out)
	}
	f, _ = signinFixture(t, true, "claudecode")
	if code, out := create(t, f, `{"profile":"eng","template":"claude-wave1","connector":"claudecode"}`); code != http.StatusCreated {
		t.Fatalf("claudecode in managed: %d %v", code, out)
	}
}

func TestSubstrateOpenSourceWarnsAboutASignin(t *testing.T) {
	f, acts := signinFixture(t, false, "cursor")
	code, out := create(t, f, `{"profile":"eng","template":"cursor-tpl","connector":"cursor"}`)
	if code != http.StatusCreated {
		t.Fatalf("create cursor in open source: %d %v", code, out)
	}
	warnings, _ := out["warnings"].([]any)
	if len(warnings) != 1 || !strings.Contains(warnings[0].(string), "snapshot") {
		t.Fatalf("warnings %v: want one that says the token is kept in snapshots", out["warnings"])
	}
	if acts.created != 1 || acts.deleted != 0 {
		t.Fatalf("created %d, deleted %d", acts.created, acts.deleted)
	}
}

// An actor made some other way (kubectl ate) is still refused by a managed
// gateway on every actor route, with the E9 reason; an open-source gateway
// serves it.
func TestSubstrateManagedRefusesASigninActorOnItsRoutes(t *testing.T) {
	for _, managed := range []bool{true, false} {
		f := newSubstrateFixture(t, func(c *SubstrateConfig) { c.Managed = managed })
		reg := registry.Registration{Atespace: "eng-web", Name: "orphan", UID: subUIDOther, Connector: "devin", Profile: "eng", Person: ownerOf(alice)}
		if err := f.regs.Put(context.Background(), reg); err != nil {
			t.Fatal(err)
		}
		ev := map[string]any{"hook_event_name": "PreToolUse", "tool_name": "exec", "tool_input": map[string]any{"command": "ls"}, "session_id": "s1", "cwd": "/work"}
		rec := f.do(t, f.actor, http.MethodPost, "/api/v1/substrate/hook/devin", "tok-orphan", envelope("devin", ev))
		got := reasonOf(t, rec)
		if managed {
			if rec.Code != http.StatusForbidden || got != "subscription_signin_refused" {
				t.Fatalf("managed: %d %s %s", rec.Code, got, rec.Body)
			}
			if !strings.Contains(rec.Body.String(), "snapshot") {
				t.Fatalf("managed refusal does not say why: %s", rec.Body)
			}
			continue
		}
		if got == "subscription_signin_refused" {
			t.Fatalf("open source refused a sign-in actor: %s", rec.Body)
		}
	}
}

// GAP-0181 (R3a, STEER 03:40Z): an attestation that cannot be read at
// create never lets the launcher's named connector decide the sign-in
// check in managed: refused before any actor exists, even when the named
// connector would pass. Open source warns and goes on.
func TestSubstrateCreateAttestationErrorFailsClosedInManaged(t *testing.T) {
	attErr := fmt.Errorf("%w: rekor unreachable", ErrSubstrateTemplateAttestation)
	f, acts := signinFixture(t, true, "cursor")
	acts.attestErr = attErr
	for _, body := range []string{
		`{"profile":"eng","template":"cursor-tpl","connector":"claudecode"}`,
		`{"profile":"eng","template":"cursor-tpl"}`,
	} {
		code, out := create(t, f, body)
		if code != http.StatusForbidden || out["reason"] != "template_attestation_unreadable" || out["message"] != "template attestation could not be read" {
			t.Fatalf("managed, %s: %d %v", body, code, out)
		}
	}
	if acts.created != 0 {
		t.Fatalf("managed: %d actors made with an unread attestation", acts.created)
	}
	f, acts = signinFixture(t, false, "claudecode")
	acts.attestErr = attErr
	code, out := create(t, f, `{"profile":"eng","template":"claude-wave1","connector":"claudecode"}`)
	warnings, _ := out["warnings"].([]any)
	if code != http.StatusCreated || len(warnings) == 0 || !strings.Contains(warnings[0].(string), "attestation could not be read") {
		t.Fatalf("open source: %d %v", code, out)
	}
	if code, out := create(t, f, `{"profile":"eng","template":"claude-wave1"}`); code != http.StatusBadRequest || out["reason"] != "connector_required" {
		t.Fatalf("open source, no connector named: %d %v", code, out)
	}
}
