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

package unit

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/capability"
)

func TestAgentPolicyGeneratedApprovedFields(t *testing.T) {
	input := `
agent: test-agent
description: "test"
generated: true
approved: false
capabilities: []
restrictions: []
conditions: {}
`
	var pol capability.AgentPolicy
	if err := yaml.Unmarshal([]byte(input), &pol); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !pol.Generated {
		t.Error("expected Generated to be true")
	}
	if pol.Approved {
		t.Error("expected Approved to be false")
	}
}

func TestAgentPolicyOmitEmptyGeneratedApproved(t *testing.T) {
	pol := capability.AgentPolicy{
		Agent:       "plain-agent",
		Description: "no auto-gen fields",
	}
	data, err := yaml.Marshal(&pol)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(data)
	if strings.Contains(s, "generated") {
		t.Error("expected generated to be omitted when false")
	}
	if strings.Contains(s, "approved") {
		t.Error("expected approved to be omitted when false")
	}
}
