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

package bundle

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	eb "github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

func gap0572Policy(key, hosts string) string {
	return fmt.Sprintf(`config_version: 9
deployment_mode: managed_enterprise
guardrail:
  profiles:
    eng:
      sandbox:
        %s: [%s]
  profile_assignments:
    - profile: eng
      match:
        substrate:
          atespaces: [team-a]
`, key, hosts)
}

// GAP-0572: a bundle whose profile listed a model provider host in
// egress_allow_only or ask_hosts was applied (result applied, a receipt)
// and the render then dropped the host under the provider-host rule (D2)
// without a word. Apply now refuses it (config_invalid, a refused receipt,
// no active bundle), naming the host and the rule; an ordinary allow-only
// list and a broad wildcard that is not a provider host still apply.
func TestGAP0572ProviderHostInABundleProfileIsRefused(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.store.Base.LLMProviders.Custom = []config.LLMCustomProvider{{Name: "corp", BaseURL: "https://llm.corp.example.test/v1"}}
	v := uint64(0)
	apply := func(body string) (*Receipt, error) {
		v++
		return e.store.Apply(ctx, buildBundle(t, e.key, v, body), "s1", []string{"team-a"}, SourceAdmin)
	}
	for _, tc := range []struct{ key, hosts, host string }{
		{"egress_allow_only", "api.anthropic.com", "api.anthropic.com"},
		{"egress_allow_only", "github.com, \"*.openai.com\"", "*.openai.com"},
		{"egress_allow_only", "bedrock-runtime.us-east-1.amazonaws.com", "bedrock-runtime.us-east-1.amazonaws.com"},
		{"egress_allow_only", "llm.corp.example.test", "llm.corp.example.test"},
		{"ask_hosts", "api.anthropic.com", "api.anthropic.com"},
	} {
		rc, err := apply(gap0572Policy(tc.key, tc.hosts))
		var ee *eb.Error
		if !errors.As(err, &ee) || ee.Code != eb.CodeConfigInvalid {
			t.Fatalf("%s %s: err = %v, want config_invalid", tc.key, tc.hosts, err)
		}
		if ee.Path != "guardrail.profiles.eng.sandbox."+tc.key || !strings.Contains(ee.Detail, tc.host+" is a model provider host") ||
			!strings.Contains(ee.Detail, "provider-host rule") {
			t.Errorf("%s %s: path %q detail %q", tc.key, tc.hosts, ee.Path, ee.Detail)
		}
		if rc == nil || rc.Result != ResultRefused {
			t.Errorf("%s %s: receipt %+v, want refused", tc.key, tc.hosts, rc)
		}
	}
	st, err := e.store.Status(ctx, 20)
	if err != nil {
		t.Fatal(err)
	}
	for name, s := range st.Stages {
		if s.Active != nil {
			t.Fatalf("stage %s: a refused bundle became active: %+v", name, s.Active)
		}
	}
	for _, r := range st.Receipts {
		if r.Result == ResultApplied {
			t.Fatalf("an applied receipt for a refused bundle: %+v", r)
		}
	}
	// Not provider hosts: they apply.
	for _, hosts := range []string{"github.com, registry.npmjs.org", "\"*.amazonaws.com\", github.com"} {
		if rc, err := apply(gap0572Policy("egress_allow_only", hosts)); err != nil || rc.Result != ResultApplied {
			t.Fatalf("allow-only [%s]: %+v %v", hosts, rc, err)
		}
	}
}
