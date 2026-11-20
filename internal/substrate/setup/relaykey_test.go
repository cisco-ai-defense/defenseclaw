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

package setup

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// TestEnsureRelaySessionKey (F4 follow-up): the hook creates the relay
// session key Secret once. The gateway signer loads its private half, the
// relay's key id of its public half (what template build bakes) is the
// signer's, the private key is never in the report, and a second run keeps
// the pair.
func TestEnsureRelaySessionKey(t *testing.T) {
	f := &fakeSecrets{m: map[string]map[string][]byte{}}
	plan := testPlan()
	r, err := EnsureRelaySessionKey(context.Background(), plan, f)
	if err != nil {
		t.Fatal(err)
	}
	s := f.m[plan.Namespace+"/"+DefaultRelaySessionSecret]
	priv, pub := s[RelaySessionPrivateKey], s[RelaySessionPublicKey]
	if len(priv) == 0 || len(pub) == 0 {
		t.Fatalf("secret keys %v", s)
	}
	file := filepath.Join(t.TempDir(), "private.pem")
	if err := os.WriteFile(file, priv, 0o600); err != nil {
		t.Fatal(err)
	}
	signer, err := identity.LoadSessionSigner(file, "https://defenseclaw-admin.example")
	if err != nil {
		t.Fatalf("gateway signer: %v", err)
	}
	kid, err := kit.SessionKeyID(pub)
	if err != nil || kid != signer.KeyID() {
		t.Fatalf("public half kid %q (%v), signer kid %q", kid, err, signer.KeyID())
	}
	if notes := strings.Join(r.Notes, " "); strings.Contains(notes, "PRIVATE") || strings.Contains(notes, string(priv)) {
		t.Fatalf("report shows the private key: %v", r.Notes)
	}
	if _, err := EnsureRelaySessionKey(context.Background(), plan, f); err != nil {
		t.Fatal(err)
	}
	if string(f.m[plan.Namespace+"/"+DefaultRelaySessionSecret][RelaySessionPrivateKey]) != string(priv) {
		t.Fatal("an existing relay session key was replaced")
	}
	// The chart's name for the Secret is used.
	plan.RelaySessionSecret = "dc-relay"
	if _, err := EnsureRelaySessionKey(context.Background(), plan, f); err != nil || f.m[plan.Namespace+"/dc-relay"] == nil {
		t.Fatalf("named secret: %v", err)
	}
}
