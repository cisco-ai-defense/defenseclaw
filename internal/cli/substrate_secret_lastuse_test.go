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

package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
)

// S6b: secrets test says when, by which agent and on which host the secret
// was last used, and says nothing when no use is known.
func TestSubstrateSecretTestLastUseS6b(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	used := now.Add(-2 * time.Minute)
	var b bytes.Buffer
	printSubstrateSecretTest(&b, api.SecretTest{Secret: api.Secret{Name: "gl-work", Status: "set", Hosts: []string{"gitlab.com"},
		Kind: "template", Template: "gitlab", LastUsed: &used, LastUsedHost: "gitlab.com", LastUsedAgent: "claude-7a"}}, now)
	if !strings.Contains(b.String(), "Last used 2 min ago by claude-7a on gitlab.com.") {
		t.Errorf("output:\n%s", b.String())
	}
	b.Reset()
	printSubstrateSecretTest(&b, api.SecretTest{Secret: api.Secret{Name: "gl-work", Status: "set", Hosts: []string{"gitlab.com"}}}, now)
	if strings.Contains(b.String(), "Last used") {
		t.Errorf("a last use with none known:\n%s", b.String())
	}
}
