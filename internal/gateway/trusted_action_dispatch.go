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

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semantic"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semanticpb"
)

const (
	trustedActionDispatchTimeout = 50 * time.Millisecond
	trustedActionDispatchMaxCost = uint64(24_000_000)
)

// trustedActionRequest is private so a remote payload cannot assert that an
// arbitrary body is a trusted or enforcement-capable action. Only adapters
// that have already established a typed server-side boundary construct it.
type trustedActionRequest struct {
	Input              actionfacts.Input
	LegacyText         string
	Connector          string
	EnforcementCapable bool
	record             func(actionfacts.Facts, []RuleFinding)
}

func dispatchTrustedAction(
	parent context.Context,
	request trustedActionRequest,
) (findings []RuleFinding) {
	if ManagedEnterpriseActive() {
		return nil
	}
	var (
		facts    actionfacts.Facts
		analyzed bool
	)
	if request.record != nil {
		defer func() {
			if !analyzed {
				facts = actionfacts.Analyze(request.Input)
			}
			request.record(facts, findings)
		}()
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, trustedActionDispatchTimeout)
	defer cancel()

	generation := snapshotRulePackGeneration(request.Connector)
	options := ruleScanOptions{includeToolCallOnly: true}
	if generation == nil || len(generation.semanticRules) == 0 {
		facts = actionfacts.Analyze(request.Input)
		analyzed = true
		return dispatchTrustedFallback(
			generation,
			request,
			facts,
			options,
		)
	}

	facts = actionfacts.Analyze(request.Input)
	analyzed = true
	if !facts.Authoritative() {
		return dispatchTrustedFallback(
			generation,
			request,
			facts,
			options,
		)
	}
	fullProjection, projectionCode := semantic.Project(facts)
	if projectionCode != semantic.ProjectionOK {
		return dispatchTrustedFallback(
			generation,
			request,
			facts,
			options,
		)
	}

	excluded := make(map[string]struct{})
	semanticFindings := make([]RuleFinding, 0, len(generation.semanticRules))
	var enforcementFacts actionfacts.Facts
	var enforcementProjection *semanticpb.Facts
	enforcementProjected := false
	var consumedCost uint64
	fallbackAllOwners := false

	for _, candidate := range generation.semanticRules {
		if ctx.Err() != nil ||
			consumedCost >= trustedActionDispatchMaxCost {
			break
		}
		if !candidate.owner.eligible(facts) {
			if candidate.owner.suppressFallback != nil &&
				candidate.owner.suppressFallback(facts) {
				excludeSemanticOwner(excluded, candidate.owner, false)
			}
			continue
		}
		result, evalCode := candidate.program.EvalBool(ctx, fullProjection)
		consumedCost += result.Cost
		if consumedCost > trustedActionDispatchMaxCost {
			break
		}
		if evalCode != semantic.EvalOK {
			if ctx.Err() != nil {
				break
			}
			continue
		}
		if !result.Matched {
			excludeSemanticOwner(excluded, candidate.owner, false)
			continue
		}

		if !enforcementProjected {
			enforcementFacts = facts.EnforcementProjection()
			enforcementProjection, projectionCode = semantic.Project(enforcementFacts)
			enforcementProjected = true
		}
		if projectionCode != semantic.ProjectionOK {
			fallbackAllOwners = true
			break
		}
		enforcementResult, enforcementCode := candidate.program.EvalBool(
			ctx,
			enforcementProjection,
		)
		consumedCost += enforcementResult.Cost
		if consumedCost > trustedActionDispatchMaxCost {
			break
		}
		if enforcementCode != semantic.EvalOK {
			if ctx.Err() != nil {
				break
			}
			continue
		}

		excludeSemanticOwner(excluded, candidate.owner, true)
		finding := RuleFinding{
			RuleID:      candidate.rule.ID,
			Title:       candidate.rule.Title,
			Severity:    candidate.rule.Severity,
			Confidence:  candidate.rule.Confidence,
			Tags:        append([]string(nil), candidate.rule.Tags...),
			enforcement: findingEnforcementAllowed,
		}
		if !request.EnforcementCapable ||
			!enforcementFacts.EnforcementEligible() ||
			!enforcementResult.Matched {
			finding.enforcement = findingEnforcementDetectionOnly
		}
		semanticFindings = append(
			semanticFindings,
			adjustConfidence(request.Input.Tool, finding),
		)
	}
	if fallbackAllOwners {
		clear(excluded)
		semanticFindings = semanticFindings[:0]
	}

	options.excludedRuleIDs = excluded
	legacyFindings := scanRuleGeneration(
		generation,
		request.LegacyText,
		request.Input.Tool,
		options,
	)
	legacyFindings = filterExactFallbackFindings(
		legacyFindings,
		request.Input,
		facts,
		request.EnforcementCapable,
	)
	findings = append(semanticFindings, legacyFindings...)
	return applyBoundaryEnforcement(findings, request.EnforcementCapable)
}

func excludeSemanticOwner(
	excluded map[string]struct{},
	owner semanticOwner,
	matched bool,
) {
	for _, ruleID := range owner.claimedIDs(matched) {
		excluded[ruleID] = struct{}{}
	}
	if matched {
		for _, ruleID := range owner.fallbackAliasesOnMatch {
			excluded[ruleID] = struct{}{}
		}
	}
}

type exactFallbackContract struct {
	proves        func(actionfacts.Input, actionfacts.Facts) bool
	detectionOnly bool
}

var exactFallbackContracts = map[string]exactFallbackContract{
	"CMD-ENV-DUMP": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return environmentDumpExternalPrerequisite(facts)
		},
	},
	"C2-DNS-TUNNEL": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return dnsSubstitutionFallbackProof(facts)
		},
	},
	"CMD-PIPE-CURL": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return stdinInterpreterPipelineFallbackProof(
				facts,
				actionfacts.OperationFetch,
				"curl",
				"curl.exe",
			)
		},
	},
	"CMD-PIPE-WGET": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return stdinInterpreterPipelineFallbackProof(
				facts,
				actionfacts.OperationFetch,
				"wget",
				"wget.exe",
			)
		},
	},
	"CMD-PIPE-BASE64": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return stdinInterpreterPipelineFallbackProof(
				facts,
				actionfacts.OperationDecode,
				"base64",
				"base64.exe",
			)
		},
	},
	"CMD-REVSHELL-BASH": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return staticReverseShellPrerequisite(facts) ||
				devTCPFallbackProof(facts, true)
		},
	},
	"CMD-REVSHELL-NC": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return staticReverseShellPrerequisite(facts)
		},
	},
	"CMD-SOCAT-EXEC": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return staticReverseShellPrerequisite(facts)
		},
	},
	"CMD-REVSHELL-DEVTCP": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return devTCPFallbackProof(facts, false)
		},
	},
	"CMD-REVSHELL-PYTHON": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return pythonSocketFallbackProof(facts)
		},
	},
	"exec.reverse_tunnel": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return reverseTunnelFallbackProof(facts)
		},
	},
	"exec.agent_runtime_bypass_flags": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return agentRuntimeBypassPrerequisite(facts)
		},
	},
	"integrity.git_hooks_bypass": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return gitHooksBypassPrerequisite(facts)
		},
	},
	"CMD-SUDO": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return semanticReconImpactOwners["CMD-SUDO"].prerequisite(facts)
		},
	},
	"privilege.host_namespace_entry": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return hostNamespaceEntryFallbackProof(facts)
		},
	},
	"lateral.workload_exec": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return workloadExecFallbackProof(facts)
		},
		detectionOnly: true,
	},
	"impact.fork_bomb": {
		proves:        forkBombFallbackProof,
		detectionOnly: true,
	},
	"impact.cryptomining_launch": {
		proves: cryptominingFallbackProof,
	},
	"impact.mass_process_termination": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return semanticReconImpactOwners["impact.mass_process_termination"].prerequisite(facts)
		},
	},
	"persistence.ssh_authorized_keys_command": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return sshAuthorizedKeysCommandPrerequisite(facts)
		},
	},
}

func stdinInterpreterPipelineFallbackProof(
	facts actionfacts.Facts,
	operation actionfacts.OperationKind,
	sourcePrograms ...string,
) bool {
	for _, source := range facts.Commands {
		if source.Effect != actionfacts.EffectExecute ||
			source.PipelineID == 0 ||
			!oneOfFold(source.Program, sourcePrograms...) ||
			!hasOperation(source, operation) {
			continue
		}
		for _, sink := range facts.Commands {
			if sink.Effect == actionfacts.EffectExecute &&
				sink.PipelineID == source.PipelineID &&
				exactStdinInterpreterSink(sink) &&
				hasCommandDataFlow(
					facts,
					source.ID,
					sink.ID,
					actionfacts.DataStdout,
					actionfacts.DataStdin,
				) {
				return true
			}
		}
	}
	return false
}

func exactStdinInterpreterSink(command actionfacts.CommandFact) bool {
	if !command.ArgvComplete || len(command.Argv) == 0 {
		return false
	}
	program := strings.ToLower(command.Program)
	if oneOfFold(program, "python", "python2", "python3", "perl", "ruby") ||
		versionedPythonProgram(program) {
		return len(command.Argv) == 1 ||
			len(command.Argv) == 2 && command.Argv[1] == "-"
	}
	if !oneOfFold(program, "sh", "bash", "zsh", "dash", "ksh") {
		return false
	}
	for index := 1; index < len(command.Argv); index++ {
		argument := command.Argv[index]
		if argument == "-s" || argument == "--" || argument == "-" {
			continue
		}
		if !strings.HasPrefix(argument, "-") &&
			!strings.HasPrefix(argument, "+") {
			return false
		}
		lower := strings.ToLower(argument)
		if lower == "--command" || strings.HasPrefix(lower, "--command=") ||
			strings.HasPrefix(argument, "-") &&
				!strings.HasPrefix(argument, "--") &&
				strings.Contains(argument[1:], "c") {
			return false
		}
		// Options that take a following value can make that value a local
		// script or command source. Leave those forms on the unsupported lane.
		switch argument {
		case "-O", "+O", "-o", "+o", "--rcfile", "--init-file":
			return false
		}
	}
	return true
}

func versionedPythonProgram(program string) bool {
	if !strings.HasPrefix(program, "python") {
		return false
	}
	suffix := strings.TrimPrefix(program, "python")
	if suffix == "" {
		return true
	}
	for _, char := range suffix {
		if (char < '0' || char > '9') && char != '.' {
			return false
		}
	}
	return true
}

func reverseTunnelFallbackProof(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		if command.Effect != actionfacts.EffectExecute ||
			!command.ArgvComplete ||
			!exactReverseTunnelArgv(command) ||
			!hasExternalNetworkAction(
				facts,
				command.ID,
				actionfacts.NetworkTunnel,
				actionfacts.NetworkConnect,
			) {
			continue
		}
		return true
	}
	return false
}

func exactReverseTunnelArgv(command actionfacts.CommandFact) bool {
	argv := command.Argv
	switch strings.ToLower(command.Program) {
	case "ssh", "ssh.exe", "autossh", "autossh.exe":
		for index := 1; index < len(argv); index++ {
			argument := argv[index]
			if argument == "-R" && index+1 < len(argv) &&
				argv[index+1] != "" {
				return true
			}
			if strings.HasPrefix(argument, "-R") && len(argument) > 2 {
				return true
			}
			if strings.EqualFold(argument, "-o") &&
				index+1 < len(argv) &&
				strings.HasPrefix(
					strings.ToLower(argv[index+1]),
					"remoteforward=",
				) {
				return true
			}
			if strings.HasPrefix(
				strings.ToLower(argument),
				"-oremoteforward=",
			) {
				return true
			}
		}
	case "chisel", "chisel.exe":
		if len(argv) < 4 || argv[1] != "client" {
			return false
		}
		for _, argument := range argv[3:] {
			lower := strings.ToLower(argument)
			if lower == "r:socks" ||
				strings.HasPrefix(lower, "r:") && len(lower) > 2 {
				return true
			}
		}
	case "ligolo-agent", "ligolo-ng-agent":
		for index := 1; index < len(argv); index++ {
			lower := strings.ToLower(argv[index])
			if (lower == "-connect" || lower == "--connect") &&
				index+1 < len(argv) && argv[index+1] != "" {
				return true
			}
			if strings.HasPrefix(lower, "-connect=") ||
				strings.HasPrefix(lower, "--connect=") {
				return !strings.HasSuffix(lower, "=")
			}
		}
	}
	return false
}

func dnsSubstitutionFallbackProof(facts actionfacts.Facts) bool {
	for _, destination := range facts.Commands {
		if destination.Effect == actionfacts.EffectPreview ||
			!oneOfFold(destination.Program, "dig", "host", "nslookup") {
			continue
		}
		for _, source := range facts.Commands {
			if source.ParentCommandID == destination.ID &&
				source.Effect == actionfacts.EffectExecute &&
				dnsSubstitutionSource(source) &&
				hasCommandDataFlow(
					facts,
					source.ID,
					destination.ID,
					actionfacts.DataStdout,
					actionfacts.DataProcess,
				) {
				return true
			}
		}
	}
	return false
}

func dnsSubstitutionSource(command actionfacts.CommandFact) bool {
	if !command.ArgvComplete {
		return false
	}
	switch strings.ToLower(command.Program) {
	case "whoami", "hostname":
		return len(command.Argv) == 1
	case "id":
		return len(command.Argv) == 1 ||
			len(command.Argv) == 2 && command.Argv[1] == "-u"
	case "cat":
		return len(command.Argv) == 2 &&
			oneOfFold(
				command.Argv[1],
				"/etc/hostname",
				"/etc/machine-id",
			)
	default:
		return false
	}
}

func devTCPFallbackProof(
	facts actionfacts.Facts,
	requireShell bool,
) bool {
	for _, network := range facts.Network {
		if network.Action != actionfacts.NetworkConnect ||
			!strings.EqualFold(network.Scheme, "tcp") {
			continue
		}
		command, ok := commandByID(facts, network.CommandID)
		if !ok ||
			command.Effect != actionfacts.EffectExecute ||
			requireShell && !shellProgram(command.Program) {
			continue
		}
		if hasCommandDataFlow(
			facts,
			command.ID,
			0,
			actionfacts.DataProcess,
			actionfacts.DataNetwork,
		) || hasCommandDataFlow(
			facts,
			0,
			command.ID,
			actionfacts.DataNetwork,
			actionfacts.DataProcess,
		) {
			return true
		}
	}
	if requireShell {
		for _, command := range facts.Commands {
			if command.Effect == actionfacts.EffectExecute &&
				shellProgram(command.Program) &&
				containsFold(command.Argv, "-i") &&
				len(command.Redirects) != 0 {
				return true
			}
		}
	}
	return false
}

func containsFold(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(value, target) {
			return true
		}
	}
	return false
}

func pythonSocketFallbackProof(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		if command.Effect != actionfacts.EffectExecute ||
			!command.ArgvComplete ||
			!oneOfFold(
				command.Program,
				"python",
				"python2",
				"python3",
				"python.exe",
				"python2.exe",
				"python3.exe",
			) {
			continue
		}
		for index := 1; index+1 < len(command.Argv); index++ {
			if command.Argv[index] != "-c" {
				continue
			}
			script := strings.ToLower(command.Argv[index+1])
			return strings.Contains(script, "socket") &&
				strings.Contains(script, "connect")
		}
	}
	return false
}

func hasCommandDataFlow(
	facts actionfacts.Facts,
	fromCommandID int64,
	toCommandID int64,
	from actionfacts.DataKind,
	to actionfacts.DataKind,
) bool {
	for _, flow := range facts.DataFlows {
		if flow.FromCommandID == fromCommandID &&
			flow.ToCommandID == toCommandID &&
			flow.From == from &&
			flow.To == to {
			return true
		}
	}
	return false
}

func commandByID(
	facts actionfacts.Facts,
	commandID int64,
) (actionfacts.CommandFact, bool) {
	for _, command := range facts.Commands {
		if command.ID == commandID {
			return command, true
		}
	}
	return actionfacts.CommandFact{}, false
}

func filterExactFallbackFindings(
	findings []RuleFinding,
	input actionfacts.Input,
	facts actionfacts.Facts,
	enforcementCapable bool,
) []RuleFinding {
	suppressAuthorizedKeysPathFallback := false
	for _, finding := range findings {
		if finding.RuleID != "persistence.ssh_authorized_keys_command" {
			continue
		}
		contract := exactFallbackContracts[finding.RuleID]
		if contract.proves != nil && contract.proves(input, facts) {
			suppressAuthorizedKeysPathFallback = true
			break
		}
	}
	filtered := findings[:0]
	preserveUnstructured := noRecoverableCommandFacts(facts)
	for _, finding := range findings {
		if suppressAuthorizedKeysPathFallback &&
			finding.RuleID == "PATH-SSH-DIR" {
			continue
		}
		contract, exact := exactFallbackContracts[finding.RuleID]
		if !exact {
			filtered = append(filtered, finding)
			continue
		}
		if !preserveUnstructured &&
			(contract.proves == nil || !contract.proves(input, facts)) {
			continue
		}
		if contract.detectionOnly || !enforcementCapable {
			finding.enforcement = findingEnforcementDetectionOnly
		} else {
			finding.enforcement = findingEnforcementAllowed
		}
		filtered = append(filtered, finding)
	}
	return filtered
}

func noRecoverableCommandFacts(facts actionfacts.Facts) bool {
	if facts.Parse.Status != actionfacts.StatusInvalid &&
		facts.Parse.Status != actionfacts.StatusNotApplicable {
		return false
	}
	for _, command := range facts.Commands {
		if command.Executable != "" || command.Program != "" ||
			len(command.Argv) != 0 {
			return false
		}
	}
	return true
}

func dispatchTrustedFallback(
	generation *compiledRulePackCategories,
	request trustedActionRequest,
	facts actionfacts.Facts,
	options ruleScanOptions,
) []RuleFinding {
	findings := scanRuleGeneration(
		generation,
		request.LegacyText,
		request.Input.Tool,
		options,
	)
	findings = filterExactFallbackFindings(
		findings,
		request.Input,
		facts,
		request.EnforcementCapable,
	)
	return applyBoundaryEnforcement(findings, request.EnforcementCapable)
}

func applyBoundaryEnforcement(
	findings []RuleFinding,
	enforcementCapable bool,
) []RuleFinding {
	if enforcementCapable {
		return findings
	}
	for index := range findings {
		findings[index].enforcement = findingEnforcementDetectionOnly
	}
	return findings
}

func enforceableRuleFindings(findings []RuleFinding) []RuleFinding {
	enforceable := make([]RuleFinding, 0, len(findings))
	for _, finding := range findings {
		if finding.contributesToEnforcement() {
			enforceable = append(enforceable, finding)
		}
	}
	return enforceable
}

func trustedSameHostHome() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	home = strings.TrimSpace(home)
	if home == "" || !filepath.IsAbs(home) {
		return ""
	}
	return filepath.Clean(home)
}
