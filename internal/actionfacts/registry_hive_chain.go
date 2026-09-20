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

import "strings"

const sensitiveRegistryHiveWindow = 4

// SensitiveRegistryHiveDumpPair reports a bounded Windows credential-dump
// proof: exact reg save/export operations read both HKLM/SAM and HKLM/SYSTEM
// into distinct output operands within four top-level commands. A single hive,
// generic registry backup, dynamic hive identity, pipelines, wrappers, and
// unrelated registry verbs abstain.
func SensitiveRegistryHiveDumpPair(facts Facts) bool {
	if facts.Parse.Dialect != DialectCMD &&
		facts.Parse.Dialect != DialectPowerShell {
		return false
	}
	for sourceIndex, source := range facts.Commands {
		sourceHive, sourceOutput, ok := exactSensitiveRegistryHiveExport(facts, source)
		if !ok {
			continue
		}
		limit := sourceIndex + sensitiveRegistryHiveWindow
		if limit > len(facts.Commands) {
			limit = len(facts.Commands)
		}
		for destinationIndex := sourceIndex + 1; destinationIndex < limit; destinationIndex++ {
			destinationHive, destinationOutput, ok := exactSensitiveRegistryHiveExport(
				facts,
				facts.Commands[destinationIndex],
			)
			if !ok || strings.EqualFold(sourceOutput, destinationOutput) {
				continue
			}
			if sourceHive == "HKLM/SAM" && destinationHive == "HKLM/SYSTEM" ||
				sourceHive == "HKLM/SYSTEM" && destinationHive == "HKLM/SAM" {
				return true
			}
		}
	}
	return false
}

func exactSensitiveRegistryHiveExport(
	facts Facts,
	command CommandFact,
) (string, string, bool) {
	if command.ParentCommandID != 0 || command.PipelineID != 0 ||
		command.ControlFlowUncertain || len(command.Wrappers) != 0 ||
		len(command.Redirects) != 0 ||
		(command.Program != "reg" && command.Program != "reg.exe") ||
		!hasFactOperation(command, OperationCredentialRead) ||
		len(command.Arguments) < 4 || len(command.Arguments) > 5 {
		return "", "", false
	}
	arguments := command.Arguments
	if arguments[0].Expands || arguments[1].Expands || arguments[2].Expands ||
		(!strings.EqualFold(arguments[1].Value, "save") &&
			!strings.EqualFold(arguments[1].Value, "export")) {
		return "", "", false
	}
	if len(arguments) == 5 &&
		(arguments[4].Expands || !strings.EqualFold(arguments[4].Value, "/y")) {
		return "", "", false
	}
	output := strings.TrimSpace(arguments[3].Value)
	if output == "" || strings.HasPrefix(output, "/") {
		return "", "", false
	}
	hive := ""
	for _, candidate := range facts.Paths {
		if candidate.CommandID != command.ID || candidate.Access != PathAccessRead ||
			candidate.Flavor != PathFlavorRegistry {
			continue
		}
		candidateHive := strings.ToUpper(candidate.Normalized)
		if candidateHive == "HKLM/SAM" || candidateHive == "HKLM/SYSTEM" {
			if hive != "" {
				return "", "", false
			}
			hive = candidateHive
		}
	}
	return hive, output, hive != ""
}
