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

package actionfacts

import "net/netip"

// ExactPOSIXDescriptorFeedbackShell proves a closed descriptor-to-shell
// feedback loop after the parser resolves literal descriptor duplications.
func ExactPOSIXDescriptorFeedbackShell(facts Facts) bool {
	if facts.Parse.Dialect != DialectPOSIX || facts.Parse.Status != StatusPartial ||
		len(facts.Commands) != 3 {
		return false
	}
	for _, issue := range facts.Parse.Issues {
		if issue != IssueOpaqueArtifact && issue != IssueUnsupportedConstruct {
			return false
		}
	}
	opener, reader, shell := facts.Commands[0], facts.Commands[1], facts.Commands[2]
	if opener.Program != "exec" || len(opener.Argv) != 1 ||
		reader.Program != "cat" || len(reader.Argv) != 1 ||
		!oneOfPOSIXShell(shell.Program) || len(shell.Argv) != 1 ||
		!opener.ArgvComplete || !reader.ArgvComplete || !shell.ArgvComplete ||
		opener.Effect != EffectExecute || reader.Effect != EffectExecute || shell.Effect != EffectExecute ||
		opener.PipelineID != 0 || opener.Background ||
		reader.PipelineID == 0 || reader.PipelineID != shell.PipelineID ||
		opener.ControlFlowUncertain || reader.ControlFlowUncertain || shell.ControlFlowUncertain {
		return false
	}
	for _, network := range facts.Network {
		if network.CommandID != opener.ID || network.Action != NetworkConnect || network.Scheme != "tcp" {
			continue
		}
		address, err := netip.ParseAddr(network.Host)
		if err != nil || address.IsLoopback() || address.IsUnspecified() ||
			address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() {
			continue
		}
		for _, opened := range opener.Redirects {
			if opened.FD < 3 || opened.Access != PathAccessRead || opened.Target == "" {
				continue
			}
			for _, input := range reader.Redirects {
				if input.FD != 0 || input.Access != PathAccessRead || input.Target != opened.Target {
					continue
				}
				for _, output := range shell.Redirects {
					if output.FD == 1 && output.Access == PathAccessWrite && output.Target == opened.Target {
						for _, flow := range facts.DataFlows {
							if flow.FromCommandID == reader.ID && flow.ToCommandID == shell.ID &&
								flow.From == DataStdout && flow.To == DataStdin {
								return true
							}
						}
					}
				}
			}
		}
	}
	return false
}
