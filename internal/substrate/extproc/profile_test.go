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

package extproc

import (
	"context"
	"errors"
	"testing"
)

// TestStaticPoliciesNeverPickByOrder is GAP-0069: overlapping atespace
// globs are not resolved by configuration order.
func TestStaticPoliciesNeverPickByOrder(t *testing.T) {
	for _, order := range [][]ProfileConfig{
		{{Name: "eng", Atespaces: []string{"eng-*"}}, {Name: "web", Atespaces: []string{"eng-web"}}, {Name: "all", Atespaces: []string{"*-ops"}}},
		{{Name: "all", Atespaces: []string{"*-ops"}}, {Name: "web", Atespaces: []string{"eng-web"}}, {Name: "eng", Atespaces: []string{"eng-*"}}},
	} {
		cfg := &Config{Profiles: order}
		if err := cfg.normalize(); err != nil {
			t.Fatal(err)
		}
		sp, err := NewStaticPolicies(cfg)
		if err != nil {
			t.Fatal(err)
		}
		pick := func(atespace string) (string, error) {
			p, err := sp.PolicyFor(context.Background(), ActorRef{Atespace: atespace, Name: "a"})
			if err != nil {
				return "", err
			}
			return p.Name, nil
		}
		if n, err := pick("eng-web"); err != nil || n != "web" {
			t.Errorf("exact name: %s %v", n, err)
		}
		if n, err := pick("eng-api"); err != nil || n != "eng" {
			t.Errorf("one glob: %s %v", n, err)
		}
		if _, err := pick("eng-ops"); !errors.Is(err, ErrAmbiguousProfile) {
			t.Errorf("two globs: %v", err)
		}
		if n, err := pick("sales"); err != nil || n != "default" {
			t.Errorf("fallback: %s %v", n, err)
		}
	}
	// The engine refuses (closed) instead of guessing.
	h := newHarness(t, func(c *Config, _ *Options) {
		c.Profiles = append(c.Profiles, ProfileConfig{Name: "dup", Atespaces: []string{"eng-w*"}, UnattendedAsks: "deny"})
	})
	if v := h.eng.DecideHeaders(context.Background(), req("eng-web", "GET", "example.com", "/")); v.Allow || v.Category != CategoryCalloutError {
		t.Errorf("ambiguous profile: %+v", v)
	}
}
