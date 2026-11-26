// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/workspace"
)

// B1 S7: run writes the registry hosts of the secrets that reach its
// agent (an older gateway lists every secret, so the agent list decides),
// and says so in one line.
func TestB1S7RunRegistryEntries(t *testing.T) {
	secrets := []api.Secret{
		{Name: "npm-corp", Registry: "npm", Hosts: []string{"npm.corp.example", "*.corp.example"}, Agents: []string{"claude-ab12"}},
		{Name: "py", Registry: "pypi", Hosts: []string{"pypi.corp.example"}, Agents: []string{"claude-ab12"}, Placeholder: "DC_SECRET_PY"},
		{Name: "other", Registry: "npm", Hosts: []string{"npm.other.example"}, Agents: []string{"codex-cd34"}},
		{Name: "gl", Hosts: []string{"gitlab.com"}, Agents: []string{"claude-ab12"}},
	}
	got := substrateRegistryEntries(secrets, "claude-ab12")
	want := []workspace.RegistryEntry{{Kind: "npm", Secret: "npm-corp", Host: "npm.corp.example", Placeholder: "placeholder-not-a-secret"},
		{Kind: "pypi", Secret: "py", Host: "pypi.corp.example", Placeholder: "DC_SECRET_PY"}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("entries %+v", got)
	}
	var b bytes.Buffer
	printSubstrateRegistryPlan(&b, workspace.RegistryPlan{Hosts: map[string][]string{"npm": {"npm.corp.example"}}, Notes: []string{"kept"}}, nil)
	if s := b.String(); !strings.Contains(s, "Registries: npm (npm.corp.example) get a placeholder") || !strings.Contains(s, "Note: kept.") {
		t.Errorf("output %q", s)
	}
	b.Reset()
	printSubstrateRegistryPlan(&b, workspace.RegistryPlan{}, errors.New("relay gone"))
	if !strings.HasPrefix(b.String(), "Warning: registry placeholders not written") {
		t.Errorf("error output %q", b.String())
	}
}
