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

package config

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

// GAP-0723: substrate.identity.actor_cert_oid is read by nothing. A config
// that still sets it must load whatever it holds (it used to be refused when
// it was not a dotted OID), and says the key is retired until 1.0.14.
func TestRetiredSubstrateActorCertOIDWarnsAndIsNotValidated(t *testing.T) {
	var buffer bytes.Buffer
	restoreOutput, restoreFlags := log.Writer(), log.Flags()
	log.SetOutput(&buffer)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(restoreOutput); log.SetFlags(restoreFlags) })

	cfg := &Config{}
	warnRetiredSubstrateKeys(cfg)
	if got := buffer.String(); got != "" {
		t.Fatalf("an unset key warned: %q", got)
	}

	cfg.Substrate.Identity.ActorCertOID = "not-an-oid"
	if err := cfg.Substrate.Validate(); err != nil && strings.Contains(err.Error(), "actor_cert_oid") {
		t.Fatalf("a retired key is still validated: %v", err)
	}
	warnRetiredSubstrateKeys(cfg)
	got := buffer.String()
	if !strings.Contains(got, "substrate.identity.actor_cert_oid") || !strings.Contains(got, "retired") || !strings.Contains(got, "1.0.14") {
		t.Fatalf("retired-key warning = %q", got)
	}
}
