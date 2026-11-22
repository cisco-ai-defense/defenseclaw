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
	"strings"
	"testing"
	"time"
)

// B5.1: substrate.identity.revocation defaults, bounds and the managed rule.
func TestSubstrateRevocationConfig(t *testing.T) {
	var zero SubstrateRevocationConfig
	if !zero.EffectiveEnabled() || zero.EffectiveSyncInterval() != 5*time.Second ||
		zero.EffectiveMaxStale() != time.Minute || zero.EffectiveMaxTokensPerPerson() != 64 {
		t.Fatalf("defaults: %v %v %v %v", zero.EffectiveEnabled(), zero.EffectiveSyncInterval(), zero.EffectiveMaxStale(), zero.EffectiveMaxTokensPerPerson())
	}
	off := false
	for name, tc := range map[string]struct {
		r    SubstrateRevocationConfig
		want string
	}{
		"ok":            {SubstrateRevocationConfig{Enabled: &off, SyncInterval: "2s", MaxStale: "30s", MaxTokensPerPerson: 10}, ""},
		"sync too fast": {SubstrateRevocationConfig{SyncInterval: "500ms"}, "identity.revocation.sync_interval"},
		"sync too slow": {SubstrateRevocationConfig{SyncInterval: "2m"}, "identity.revocation.sync_interval"},
		"stale < sync":  {SubstrateRevocationConfig{SyncInterval: "10s", MaxStale: "5s"}, "identity.revocation.max_stale"},
		"stale = sync":  {SubstrateRevocationConfig{SyncInterval: "5s", MaxStale: "5s"}, "identity.revocation.max_stale"},
		"stale < 2sync": {SubstrateRevocationConfig{SyncInterval: "5s", MaxStale: "9s"}, "identity.revocation.max_stale"},
		"stale = 2sync": {SubstrateRevocationConfig{SyncInterval: "5s", MaxStale: "10s"}, ""},
		"stale > 1h":    {SubstrateRevocationConfig{MaxStale: "2h"}, "identity.revocation.max_stale"},
		"tokens":        {SubstrateRevocationConfig{MaxTokensPerPerson: 5000}, "identity.revocation.max_tokens_per_person"},
	} {
		s := &SubstrateConfig{Identity: SubstrateIdentityConfig{Revocation: tc.r}}
		err := s.Validate()
		got := ""
		if err != nil {
			got = err.Error()
		}
		if tc.want == "" && strings.Contains(got, "identity.revocation") || tc.want != "" && !strings.Contains(got, tc.want) {
			t.Errorf("%s: err %q, want %q", name, got, tc.want)
		}
	}
	s := &SubstrateConfig{Identity: SubstrateIdentityConfig{Revocation: SubstrateRevocationConfig{Enabled: &off}}}
	if err := s.ValidateManaged(string(DeploymentModeManagedEnterprise)); err == nil || !strings.Contains(err.Error(), "identity.revocation.enabled") {
		t.Fatalf("managed may not turn revocation off: %v", err)
	}
	if err := s.ValidateManaged("standalone"); err != nil {
		t.Fatalf("standalone may: %v", err)
	}
}

// RV1-09: unset, max_stale is 60s or 2 x sync_interval, whichever is longer.
func TestRV109MaxStaleDefaultFollowsSyncInterval(t *testing.T) {
	if got := (SubstrateRevocationConfig{SyncInterval: "40s"}).EffectiveMaxStale(); got != 80*time.Second {
		t.Fatalf("sync 40s: max_stale %v, want 80s", got)
	}
	if got := (SubstrateRevocationConfig{SyncInterval: "2s"}).EffectiveMaxStale(); got != time.Minute {
		t.Fatalf("sync 2s: max_stale %v, want 60s", got)
	}
}
