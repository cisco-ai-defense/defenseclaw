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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/render"
	"github.com/defenseclaw/defenseclaw/internal/substrate/secretbind"
)

// TestB1SecretAuditSubjectRV3P24: every secret change record names who made
// it, as a keyed pseudonym (hmac-sha256:<64 hex>): the owner on add, set and
// rm, the administrator on an ask decision, never the subject in clear.
func TestB1SecretAuditSubjectRV3P24(t *testing.T) {
	orig := substratePayloadHMAC
	substratePayloadHMAC = func(v any) string {
		b, _ := json.Marshal(v)
		s := sha256.Sum256(append([]byte("test-key:"), b...))
		return hex.EncodeToString(s[:])
	}
	t.Cleanup(func() { substratePayloadHMAC = orig })

	bf := newBindingFixture(t, nil)
	if code, out := bf.add(t, "p-alice", `{"name":"gl-work","template":"gitlab","host":"gitlab.com","value":"v1"}`); code != http.StatusCreated {
		t.Fatalf("add: %d %v", code, out)
	}
	if rec := bf.do(t, bf.admin, http.MethodPut, "/api/v1/substrate/secrets/gl-work", "p-alice", `{"value":"v2"}`); rec.Code != http.StatusOK {
		t.Fatalf("set: %d %s", rec.Code, rec.Body.String())
	}
	if rec := bf.do(t, bf.admin, http.MethodDelete, "/api/v1/substrate/secrets/gl-work", "p-alice", ""); rec.Code != http.StatusOK {
		t.Fatalf("rm: %d %s", rec.Code, rec.Body.String())
	}
	code, out := bf.add(t, "p-alice", `{"name":"gl-lab","template":"gitlab","host":"git.lab.example","value":"v3"}`)
	id, _ := out["ask_id"].(string)
	if code != http.StatusAccepted || id == "" {
		t.Fatalf("outside add: %d %v", code, out)
	}
	if code, out := bf.decide(t, "p-admin", id, "approve"); code != http.StatusOK {
		t.Fatalf("approve: %d %v", code, out)
	}

	keyRE := regexp.MustCompile(`^hmac-sha256:[0-9a-f]{64}$`)
	alice, admin := "", ""
	for _, ev := range bf.audits {
		if ev.Failed {
			continue
		}
		if !keyRE.MatchString(ev.SubjectKey) {
			t.Fatalf("%s %s: SubjectKey %q", ev.Operation, ev.Name, ev.SubjectKey)
		}
		switch ev.Operation {
		case audit.SubstrateSecretBindingApproved:
			admin = ev.SubjectKey
		default:
			if alice != "" && alice != ev.SubjectKey {
				t.Fatalf("alice's records carry two keys: %q %q", alice, ev.SubjectKey)
			}
			alice = ev.SubjectKey
		}
	}
	if alice == "" || admin == "" || alice == admin {
		t.Fatalf("alice %q admin %q audits %+v", alice, admin, bf.audits)
	}
}

// TestB1RemoveShadowedBindingValueRV3P33: an admin per_person secret added
// later with a binding's name shadows the binding; rm then removes the
// admin secret's value and the binding, and the binding's own value too,
// so no value is left in the person's Secret without a binding.
func TestB1RemoveShadowedBindingValueRV3P33(t *testing.T) {
	bf := newBindingFixture(t, func(c *SubstrateConfig) {
		c.Secrets = append(c.Secrets, config.SubstrateSecret{Name: "gl-work", Scope: "per_person",
			Source: "ate-secret://k8s.io/default/dc-people/{person}-gl/token",
			Inject: config.SubstrateSecretInject{Hosts: []string{"gitlab.com"}, Header: "Authorization"}, Profiles: []string{"eng"}})
	})
	alice := render.PersonKey("alice")
	if err := bf.store.Update(t.Context(), func(d *secretbind.Doc) error {
		d.Bindings = append(d.Bindings, secretbind.Binding{ID: "b-00000000c3", Name: "gl-work", Owner: alice, Template: "gitlab",
			Hosts: []string{"gitlab.com"}, State: secretbind.Active, Created: time.Now()})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	vkey := "defenseclaw-user-secrets/" + secretbind.ValueSecretName(alice) + "/b-00000000c3"
	_ = bf.values.Set(t.Context(), "defenseclaw-user-secrets", secretbind.ValueSecretName(alice), "b-00000000c3", []byte("Bearer v"))
	if rec := bf.do(t, bf.admin, http.MethodDelete, "/api/v1/substrate/secrets/gl-work", "p-alice", ""); rec.Code != http.StatusOK {
		t.Fatalf("rm: %d %s", rec.Code, rec.Body.String())
	}
	bf.values.mu.Lock()
	_, left := bf.values.m[vkey]
	bf.values.mu.Unlock()
	if left || len(bf.store.ForOwner(alice)) != 0 {
		t.Fatalf("value left %v, bindings %+v", left, bf.store.ForOwner(alice))
	}
}

// TestSubstrateSecretBindingStoreCheckRV3P32: the doctor row passes on a
// good store, warns and names an entry a hand edit made invalid, and fails
// when the ConfigMap does not read at all.
func TestSubstrateSecretBindingStoreCheckRV3P32(t *testing.T) {
	if c := SubstrateSecretBindingStoreCheck(nil); c.Status != "pass" || c.ID != "substrate.secret_bindings" {
		t.Fatalf("off: %+v", c)
	}
	good := `{"version":1,"bindings":[{"id":"b-00000000a1","name":"gl-work","owner":"` + render.PersonKey("alice") +
		`","template":"gitlab","hosts":["gitlab.com"],"state":"active","created":"2026-11-22T00:00:00Z"}]}`
	bad := strings.Replace(good, `]}`, `,{"id":"b-00000000a2","name":"gl-bad","owner":"`+render.PersonKey("alice")+
		`","template":"gitlab","hosts":["GitLab.COM"],"state":"active","created":"2026-11-22T00:00:00Z"}]}`, 1)
	for name, tc := range map[string]struct{ raw, status, has string }{
		"good":      {good, "pass", ""},
		"hand edit": {bad, "warn", "b-00000000a2"},
		"no parse":  {`{"bindings":`, "fail", "do not read"},
	} {
		s := secretbind.New(&memBindings{raw: []byte(tc.raw)})
		_ = s.Refresh(t.Context())
		if c := SubstrateSecretBindingStoreCheck(s); c.Status != tc.status || !strings.Contains(c.Detail, tc.has) {
			t.Errorf("%s: %+v", name, c)
		}
	}
}
