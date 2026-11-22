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

package render

import "testing"

// GAP-0572: ProviderHost, the check a policy bundle refuses provider hosts
// with, is the one EgressPolicy drops a destination with (provider_host).
func TestGAP0572ProviderHostIsTheRenderDropCheck(t *testing.T) {
	extra := []string{"llm.corp.example.test"}
	for _, h := range []string{"api.anthropic.com", "*.openai.com", "bedrock-runtime.us-east-1.amazonaws.com",
		"*.amazonaws.com", "github.com", "llm.corp.example.test", "x.llm.corp.example.test", "us-central1-aiplatform.googleapis.com",
		"*.googleapis.com", "registry.npmjs.org", "not a host"} {
		s := baseSettings()
		s.AllowHosts, s.ProviderHosts = []string{h}, extra
		res, err := EgressPolicy(Input{Settings: s})
		if err != nil {
			t.Fatal(err)
		}
		dropped := false
		for _, d := range res.Dropped {
			dropped = dropped || (d.Host == h && d.Reason == ReasonProvider)
		}
		_, hit := ProviderHost(extra, h)
		if hit != dropped {
			t.Errorf("%s: ProviderHost %v, render drops it as a provider %v", h, hit, dropped)
		}
	}
}
