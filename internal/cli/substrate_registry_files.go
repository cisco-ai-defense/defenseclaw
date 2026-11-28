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
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/safetext"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/workspace"
	"github.com/spf13/cobra"
)

// substrateRegistryEntries are the registry hosts of the secrets that
// reach agent (the gateway's ?agent= answer; an older gateway answers
// every secret, so the agent list is checked here too).
func substrateRegistryEntries(secrets []api.Secret, agent string) []workspace.RegistryEntry {
	var in []workspace.RegistryEntry
	for _, sec := range secrets {
		if sec.Registry == "" || !slices.Contains(sec.Agents, agent) {
			continue
		}
		for _, h := range sec.Hosts {
			in = append(in, workspace.RegistryEntry{Kind: sec.Registry, Secret: sec.Name, Host: h, Placeholder: sec.Placeholder})
		}
	}
	return workspace.RegistryEntries(in)
}

// substrateRegistryFiles writes the npm and pip placeholders of the
// registries bound in agent a's policy in its home, after create and
// before the agent starts (B1 2.6, S7), so a binding added or removed
// takes effect on the next run with no template rebuild. Placeholders
// only: Substrate egress adds the real credential on the bound host. A
// failure is a warning; the agent still starts (its registries then answer
// 401 as before).
func substrateRegistryFiles(ctx context.Context, cmd *cobra.Command, s *substrateSession, a api.Actor) {
	w := cmd.ErrOrStderr()
	secrets, err := s.Client.SecretsForAgent(ctx, a.Name)
	if err != nil {
		if e, ok := api.AsError(err); ok && (e.Status == 404 || e.NotImplemented()) {
			return
		}
		fmt.Fprintf(w, "Warning: the registries bound for this agent could not be read (%s); npm and pip get no placeholders.\n", substrateFail(err))
		return
	}
	entries := substrateRegistryEntries(secrets, a.Name)
	if len(entries) == 0 {
		return
	}
	rel, err := substrateOpenRelay(ctx, s, a)
	if err != nil {
		fmt.Fprintf(w, "Warning: registry placeholders not written: %v\n", err)
		return
	}
	defer rel.Close()
	cctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	plan, err := workspace.StartRegistryFiles(cctx, rel.Client, substrateCopyName(a), entries)
	printSubstrateRegistryPlan(w, plan, err)
}

func printSubstrateRegistryPlan(w io.Writer, plan workspace.RegistryPlan, err error) {
	if err != nil {
		fmt.Fprintf(w, "Warning: registry placeholders not written: %s\n", safetext.Line(err.Error()))
		return
	}
	var parts []string
	for _, k := range []string{workspace.RegistryNPM, workspace.RegistryPyPI} {
		if hs := plan.Hosts[k]; len(hs) > 0 {
			name := map[string]string{workspace.RegistryNPM: "npm", workspace.RegistryPyPI: "pip"}[k]
			parts = append(parts, name+" ("+safetext.Line(strings.Join(hs, ", "))+")")
		}
	}
	if len(parts) > 0 {
		fmt.Fprintf(w, "Registries: %s get a placeholder in the agent's home; Substrate adds the real credential on those hosts.\n", strings.Join(parts, " and "))
	}
	for _, n := range plan.Notes {
		fmt.Fprintf(w, "Note: %s.\n", safetext.Line(n))
	}
}

// doctorRegistryFiles is the registry_files row: how the agent the attach
// row checks gets its npm and pip placeholders: written at its start
// (1.0.11 and later), the lines its template image carries from its build
// (kept for launchers older than 1.0.11), both, or none.
func doctorRegistryFiles(ctx context.Context, s *substrateSession, mine []api.Actor, signedIn bool) substrateCheck {
	const id = "registry_files"
	if !signedIn || len(mine) == 0 {
		return substrateCheck{ID: id, Status: doctorSkip, Summary: "can be checked once you have a running agent"}
	}
	a, ok := mine[0], false
	for _, m := range mine {
		if m.State == "running" {
			a, ok = m, true
			break
		}
	}
	if !ok {
		return substrateCheck{ID: id, Status: doctorSkip, Summary: "can be checked once you have a running agent"}
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	rel, err := substrateOpenRelay(cctx, s, a)
	if err != nil {
		return substrateCheck{ID: id, Status: doctorWarn, Summary: "the agent " + a.Name + " could not be read: " + doctorFirstLine(err)}
	}
	defer rel.Close()
	p := workspace.ProbeRegistryFiles(cctx, rel.Client, substrateCopyName(a))
	if p.ReadError != nil {
		return substrateCheck{ID: id, Status: doctorWarn, Summary: "the agent " + a.Name + "'s registry files could not be read: " + doctorFirstLine(p.ReadError)}
	}
	baked := safetext.Line(strings.Join(p.BakedNPM, ", "))
	switch p.Mode() {
	case "start":
		return substrateCheck{ID: id, Status: doctorOK, Summary: "agent " + a.Name + ": registry placeholders were written at its start (mode start)"}
	case "template+start":
		return substrateCheck{ID: id, Status: doctorOK, Summary: "agent " + a.Name + ": registry placeholders were written at its start; its template also names " + baked + " from its build (mode template+start)"}
	case "template":
		return substrateCheck{ID: id, Status: doctorOK, Summary: "agent " + a.Name + ": its template names " + baked + " in its npm configuration from its build; none was written at start (mode template)",
			Fix: "a registry bound since its start reaches the next agent you run"}
	}
	// The doctor reads only the agent's files, not its bindings: none says
	// what it saw (GAP-0975). A kept image file or a refused link shows up
	// here too; run prints a Note for each at start.
	return substrateCheck{ID: id, Status: doctorOK, Summary: "agent " + a.Name + ": no registry placeholders were found in its home or its template (mode none)",
		Fix: "if a registry is bound for this agent, the Notes defenseclaw substrate run printed at its start say which file was kept and why"}
}
