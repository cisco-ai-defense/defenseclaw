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
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semantic"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semanticpb"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/pattern"
	"mvdan.cc/sh/v3/syntax"
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
	// DowngradeReadOnlyDataArgs is advisory-only. Bare executable names and
	// PowerShell cmdlets are not runtime-attested, so Action-mode adapters must
	// leave this false even when the argv shape is a static reader.
	DowngradeReadOnlyDataArgs bool
	record                    func(actionfacts.Facts, []RuleFinding)
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
	options := ruleScanOptions{
		includeToolCallOnly: true,
		excludeTrustExploit: true,
	}
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
	restoreTrustedUnresolvedReadFallbacks(
		excluded,
		generation,
		request.Input,
		request.Input.Tool,
		facts,
	)
	restoreTrustedEmbeddedCommandFallbacks(
		excluded,
		generation,
		request.Input.Tool,
		facts,
	)

	options.excludedRuleIDs = excluded
	legacyText := request.LegacyText
	if trustedFixtureSourceInspectionAction(request.Input, facts) {
		legacyText = neutralizeKnownFixtureDataLiterals(legacyText)
	}
	legacyFindings := scanRuleGeneration(
		generation,
		legacyText,
		request.Input.Tool,
		options,
	)
	legacyFindings = appendTrustedEmbeddedCommandFindings(
		legacyFindings,
		generation,
		request.Input.Tool,
		facts,
		options,
	)
	legacyFindings = appendTrustedBashFallbackFindings(
		legacyFindings,
		generation,
		request.Input,
		request.Input.Tool,
		facts,
		options,
		request.EnforcementCapable,
		request.DowngradeReadOnlyDataArgs,
	)
	legacyFindings = filterTrustedLegacyActionContext(
		generation,
		legacyFindings,
		request.Input,
		request.Input.Tool,
		facts,
		request.DowngradeReadOnlyDataArgs,
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
	"tamper.detector_state_write": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			owner := semanticIntegrityPersistenceOwners["tamper.detector_state_write"]
			return owner.prerequisite != nil && owner.prerequisite(facts)
		},
		// Detector-state mutation is an operation claim, not a string claim.
		// If ActionFacts cannot authorize the semantic lane, preserve the
		// regex hit for diagnostics but never let it synchronously deny.
		detectionOnly: true,
	},
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
	"integrity.history_tamper": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return historyTamperPrerequisite(facts)
		},
		detectionOnly: true,
	},
	"CMD-PIPE-CURL": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return curlDownloadExecPrerequisite(facts)
		},
	},
	"CMD-WIN-IWR-IEX": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return powerShellDownloadExecPrerequisite(facts)
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
	"source.git_config_exec": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return gitConfigExecPrerequisite(facts)
		},
	},
	"persistence.git_hook_write": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return semanticIntegrityPersistenceOwners["persistence.git_hook_write"].prerequisite(facts)
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
	"privilege.container_host_escape": {
		proves: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
			return semanticReconImpactOwners["privilege.container_host_escape"].prerequisite(facts)
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

type trustedLegacyProvenCommandDetectionOnlyContract struct {
	category     string
	pattern      string
	title        string
	severity     string
	confidence   float64
	tags         []string
	prerequisite func(actionfacts.Facts) bool
}

const (
	trustedPerlInlinePattern = `(?i)\bperl\s+-e\s+`
	trustedRubyInlinePattern = `(?i)\bruby\s+-e\s+`
)

var (
	trustedPerlInlineRegexp = regexp.MustCompile(trustedPerlInlinePattern)
	trustedRubyInlineRegexp = regexp.MustCompile(trustedRubyInlinePattern)
)

// trustedLegacyProvenCommandDetectionOnly is deliberately code-owned instead
// of rule-pack metadata: policy data must not be able to opt an arbitrary or
// overridden command owner out of enforcement. Each entry binds the shipped
// immutable rule identity as well as its ActionFacts proof. Literal/raw
// fallback and custom rules with a reused ID retain conservative enforcement.
var trustedLegacyProvenCommandDetectionOnly = map[string]trustedLegacyProvenCommandDetectionOnlyContract{
	"CMD-BASH-C": {
		category:     "command",
		pattern:      `(?i)\b(?:ba)?sh\s+-c\s+`,
		title:        "Shell -c execution",
		severity:     "LOW",
		confidence:   0.55,
		tags:         []string{"execution"},
		prerequisite: trustedBashInlineCommandOwnerProven,
	},
	"CMD-PYTHON-C": {
		category:   "command",
		pattern:    `(?i)\bpython[23]?\s+-c\s+`,
		title:      "Python inline execution",
		severity:   "LOW",
		confidence: 0.55,
		tags:       []string{"execution"},
	},
	"CMD-PERL-E": {
		category:     "command",
		pattern:      trustedPerlInlinePattern,
		title:        "Perl inline execution",
		severity:     "LOW",
		confidence:   0.55,
		tags:         []string{"execution"},
		prerequisite: trustedPerlInlineEffectFreeOwnerProven,
	},
	"CMD-RUBY-E": {
		category:     "command",
		pattern:      trustedRubyInlinePattern,
		title:        "Ruby inline execution",
		severity:     "LOW",
		confidence:   0.55,
		tags:         []string{"execution"},
		prerequisite: trustedRubyInlineEffectFreeOwnerProven,
	},
}

func stdinInterpreterPipelineFallbackProof(
	facts actionfacts.Facts,
	operation actionfacts.OperationKind,
	sourcePrograms ...string,
) bool {
	for _, source := range facts.Commands {
		if source.PipelineID == 0 ||
			!oneOfFold(source.Program, sourcePrograms...) ||
			!hasOperation(source, operation) &&
				!(operation == actionfacts.OperationFetch &&
					hasOperation(source, actionfacts.OperationUpload)) ||
			!actionfacts.ProvesPOSIXPipelineInterpreterSource(source) {
			continue
		}
		for _, sink := range facts.Commands {
			if sink.PipelineID == source.PipelineID &&
				actionfacts.ProvesPOSIXStdinInterpreter(sink) &&
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

func exactPipelineSourceStdout(command actionfacts.CommandFact) bool {
	return actionfacts.ProvesPOSIXPipelineInterpreterSource(command)
}

func exactStdinInterpreterSink(command actionfacts.CommandFact) bool {
	return actionfacts.ProvesPOSIXStdinInterpreter(command)
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
			!oneOfFold(destination.Program, "dig", "host", "nslookup", "drill") {
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
		// An interactive shell can bind stdin and stdout directly to a
		// /dev/tcp descriptor without the process-level flow emitted for
		// `exec N<>/dev/tcp/...`. Require both directions on the same typed
		// command so one-way health probes and file transfers do not inherit
		// reverse-shell ownership.
		if actionfacts.ProvesPOSIXInteractiveShell(command) &&
			hasCommandDataFlow(
				facts,
				0,
				command.ID,
				actionfacts.DataNetwork,
				actionfacts.DataStdin,
			) && hasCommandDataFlow(
			facts,
			command.ID,
			0,
			actionfacts.DataStdout,
			actionfacts.DataNetwork,
		) {
			return true
		}
	}
	if requireShell {
		for _, command := range facts.Commands {
			if command.Effect == actionfacts.EffectExecute &&
				shellProgram(command.Program) &&
				(actionfacts.ProvesPOSIXInteractiveShell(command) ||
					legacyUnmodeledInteractiveShellOption(command)) &&
				len(command.Redirects) != 0 {
				return true
			}
		}
	}
	return false
}

func legacyUnmodeledInteractiveShellOption(command actionfacts.CommandFact) bool {
	// Zsh and fish intentionally remain outside ActionFacts' bounded invocation
	// grammar. Preserve only the pre-existing requireShell fallback for those
	// programs; the new bidirectional /dev/tcp owner never calls this lane.
	return oneOfFold(command.Program, "zsh", "fish") &&
		containsFold(command.Argv, "-i")
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
	suppressPowerShellDownloadAlias := false
	for _, finding := range findings {
		switch finding.RuleID {
		case "persistence.ssh_authorized_keys_command":
			contract := exactFallbackContracts[finding.RuleID]
			if contract.proves != nil && contract.proves(input, facts) {
				suppressAuthorizedKeysPathFallback = true
			}
		case "CMD-PIPE-CURL":
			contract := exactFallbackContracts[finding.RuleID]
			if contract.proves != nil && contract.proves(input, facts) &&
				powerShellDownloadExecPrerequisite(facts) {
				suppressPowerShellDownloadAlias = true
			}
		}
	}
	filtered := findings[:0]
	preserveUnstructured := noRecoverableCommandFacts(facts)
	for _, finding := range findings {
		if suppressAuthorizedKeysPathFallback &&
			finding.RuleID == "PATH-SSH-DIR" {
			continue
		}
		if suppressPowerShellDownloadAlias &&
			finding.RuleID == "CMD-WIN-IWR-IEX" {
			continue
		}
		contract, exact := exactFallbackContracts[finding.RuleID]
		if !exact {
			filtered = append(filtered, finding)
			continue
		}
		if hasTag(finding.Tags, trustedParserUncertaintyTag) {
			finding.enforcement = findingEnforcementDetectionOnly
			filtered = append(filtered, finding)
			continue
		}
		proven := contract.proves != nil && contract.proves(input, facts)
		if !proven {
			proven = trustedNestedExactFallbackProof(
				contract,
				input,
				facts,
			)
		}
		if !preserveUnstructured && !proven {
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

func trustedNestedExactFallbackProof(
	contract exactFallbackContract,
	input actionfacts.Input,
	facts actionfacts.Facts,
) bool {
	if contract.proves == nil {
		return false
	}
	for _, nested := range trustedNestedExecutionActions(input, facts) {
		if nested.rawFallback {
			continue
		}
		if contract.proves(nested.input, nested.facts) {
			return true
		}
	}
	return false
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
	legacyText := request.LegacyText
	if trustedFixtureSourceInspectionAction(request.Input, facts) {
		legacyText = neutralizeKnownFixtureDataLiterals(legacyText)
	}
	findings := scanRuleGeneration(
		generation,
		legacyText,
		request.Input.Tool,
		options,
	)
	findings = appendTrustedEmbeddedCommandFindings(
		findings,
		generation,
		request.Input.Tool,
		facts,
		options,
	)
	findings = appendTrustedBashFallbackFindings(
		findings,
		generation,
		request.Input,
		request.Input.Tool,
		facts,
		options,
		request.EnforcementCapable,
		request.DowngradeReadOnlyDataArgs,
	)
	findings = filterTrustedLegacyActionContext(
		generation,
		findings,
		request.Input,
		request.Input.Tool,
		facts,
		request.DowngradeReadOnlyDataArgs,
	)
	findings = filterExactFallbackFindings(
		findings,
		request.Input,
		facts,
		request.EnforcementCapable,
	)
	return applyBoundaryEnforcement(findings, request.EnforcementCapable)
}

// trustedFixtureSourceInspectionAction identifies the one tool-call shape in
// which credential and PII literals are examples rather than submitted data:
// a read-only inspection whose every proven target is an explicit fixture or
// bundled guardrail rule source. Any mixed, unresolved, networked, or mutating
// action keeps the data detectors enabled.
func trustedFixtureSourceInspectionAction(
	input actionfacts.Input,
	facts actionfacts.Facts,
) bool {
	if len(facts.Paths) == 0 || len(facts.Network) != 0 {
		return false
	}
	for _, path := range facts.Paths {
		if path.Access != actionfacts.PathAccessRead &&
			path.Access != actionfacts.PathAccessList {
			return false
		}
		value := firstNonEmpty(path.Resolved, path.Normalized, path.Value)
		if !fixtureOrGuardrailSourcePathLexical(value, input.CWD) {
			return false
		}
	}

	if len(facts.Commands) == 0 {
		return trustedStructuredSourceInspectionTool(input.Tool)
	}
	for _, command := range facts.Commands {
		switch strings.ToLower(strings.TrimSpace(command.Program)) {
		case "rg", "ripgrep", "grep", "sed", "awk", "head", "tail",
			"cat", "find", "fd":
		default:
			return false
		}
	}
	return true
}

func trustedStructuredSourceInspectionTool(tool string) bool {
	name := strings.ToLower(strings.TrimSpace(tool))
	name = strings.NewReplacer(".", "", "-", "", "_", "").Replace(name)
	switch name {
	case "read", "readfile", "fsread", "fileread", "catfile", "openfile",
		"viewfile", "getfile", "search", "searchfiles", "filesearch", "glob",
		"globfiles", "listfiles", "listdirectory":
		return true
	default:
		return false
	}
}

// trustedReadOnlyInspectionAction proves that secret- or PII-shaped bytes in
// a tool call are inert reader/search arguments, not data being written or
// transmitted. The returned tool output is scanned independently at
// PostToolUse, so lowering these argument-only matches does not suppress a
// credential or regulated value that the reader actually returns.
//
// Keep this proof deliberately narrower than "no network facts": every shell
// stage must be a statically projected reader, searcher, or stdin-only output
// limiter with no redirects, wrappers, expansion, or embedded execution. This
// proves argv structure, not the ambient executable/profile identity, which is
// why callers may use it only behind DowngradeReadOnlyDataArgs in Observe.
func trustedReadOnlyInspectionAction(
	input actionfacts.Input,
	facts actionfacts.Facts,
) bool {
	if len(facts.Network) != 0 {
		return false
	}
	for _, path := range facts.Paths {
		if path.Access != actionfacts.PathAccessRead &&
			path.Access != actionfacts.PathAccessList {
			return false
		}
	}
	if facts.Parse.Dialect == actionfacts.DialectArgv &&
		facts.Authoritative() && len(facts.Commands) == 1 &&
		trustedStructuredSourceInspectionTool(input.Tool) {
		return len(facts.Paths) != 0
	}
	if len(facts.Commands) == 0 {
		return len(facts.Paths) != 0 &&
			trustedStructuredSourceInspectionTool(input.Tool)
	}

	commandText := trustedActionInputText(input, "")
	if powerShellFacts, candidate := codexStaticPowerShellReaderFacts(
		commandText, facts, input.CWD, input.Tool,
	); candidate {
		return trustedReadOnlyPowerShellInspection(powerShellFacts)
	}
	if facts.Parse.Dialect != actionfacts.DialectPOSIX ||
		len(facts.Commands) == 0 ||
		!codexStaticReaderParseStatus(facts.Parse) ||
		!codexStaticReaderShellStructureSafe(commandText) {
		return false
	}

	pipelineHasSource := make(map[int64]bool)
	sawSource := false
	for _, command := range facts.Commands {
		if command.Kind != actionfacts.CommandKindProcess ||
			command.Effect != actionfacts.EffectExecute ||
			!command.ArgvComplete || len(command.Argv) == 0 ||
			len(command.Redirects) != 0 || len(command.Wrappers) != 0 {
			return false
		}
		for _, argument := range command.Arguments {
			if argument.Expands || codexArgumentHasBraceExpansion(argument) {
				return false
			}
		}

		inputs, ok := codexStaticReaderCommandInputs(command.Program, command.Argv)
		if !ok && trustedGitStatusInspection(command.Argv) {
			inputs = codexStaticReaderInputs{hasDataTarget: true}
			ok = true
		}
		if !ok || inputs.readsStdin && inputs.hasDataTarget {
			return false
		}
		if inputs.hasDataTarget {
			sawSource = true
			if command.PipelineID != 0 {
				pipelineHasSource[command.PipelineID] = true
			}
			continue
		}
		if !inputs.readsStdin || command.PipelineID == 0 ||
			!pipelineHasSource[command.PipelineID] {
			return false
		}
	}
	return sawSource
}

func trustedReadOnlyPowerShellInspection(facts actionfacts.Facts) bool {
	if !codexStaticPowerShellReaderParseStatus(facts.Parse) ||
		len(facts.Commands) != 1 || len(facts.Network) != 0 ||
		len(facts.DataFlows) != 0 {
		return false
	}
	command := facts.Commands[0]
	if command.Kind != actionfacts.CommandKindProcess ||
		(command.Dialect != actionfacts.DialectPowerShell &&
			command.Dialect != actionfacts.DialectCMD) ||
		command.Effect != actionfacts.EffectExecute || !command.ArgvComplete ||
		len(command.Argv) == 0 || command.PipelineID != 0 ||
		len(command.Redirects) != 0 || len(command.Wrappers) != 0 ||
		len(command.Arguments) != len(command.Argv) {
		return false
	}
	for _, argument := range command.Arguments {
		if argument.Expands || argument.Quote == actionfacts.QuoteMixed {
			return false
		}
	}
	var (
		inputs codexStaticReaderInputs
		ok     bool
	)
	switch strings.ToLower(command.Program) {
	case "get-content", "gc", "type":
		inputs, ok = codexPowerShellGetContentInputs(command)
	case "select-string":
		inputs, ok = codexPowerShellSelectStringInputs(command)
	}
	return ok && inputs.hasDataTarget && !inputs.readsStdin
}

func trustedGitStatusInspection(argv []string) bool {
	if len(argv) < 2 || argv[0] != "git" || argv[1] != "status" {
		return false
	}
	for index := 2; index < len(argv); index++ {
		argument := argv[index]
		switch {
		case argument == "--":
			return index+1 < len(argv)
		case argument == "--short", argument == "-s",
			argument == "--branch", argument == "-b",
			argument == "--porcelain", argument == "--ignored",
			argument == "--show-stash", argument == "--ahead-behind",
			argument == "--no-ahead-behind":
		case strings.HasPrefix(argument, "--porcelain="),
			strings.HasPrefix(argument, "--untracked-files="):
		default:
			return false
		}
	}
	return true
}

// filterTrustedLegacyActionContext prevents a search pattern, patch body, or
// other content payload from being promoted into an action by the regex
// compatibility lane. Paths, commands, cognitive mutations, and C2 destinations
// each require the corresponding typed ActionFact.
func filterTrustedLegacyActionContext(
	generation *compiledRulePackCategories,
	findings []RuleFinding,
	input actionfacts.Input,
	toolName string,
	facts actionfacts.Facts,
	downgradeReadOnlyDataArgs bool,
) []RuleFinding {
	pathMatches, mutationMatches := trustedLegacyPathRuleMatches(
		generation,
		input,
		toolName,
		facts,
	)
	commandMatches := trustedLegacyCommandRuleMatches(
		generation,
		input,
		toolName,
		facts,
	)
	networkMatches := trustedLegacyNetworkRuleMatches(
		generation,
		input,
		toolName,
		facts,
	)
	var (
		readOnlyInspectionKnown bool
		readOnlyInspection      bool
	)
	filtered := findings[:0]
	for _, finding := range findings {
		if hasTag(finding.Tags, trustedParserUncertaintyTag) {
			finding.enforcement = findingEnforcementDetectionOnly
			filtered = append(filtered, finding)
			continue
		}
		if contract, ok := exactFallbackContracts[finding.RuleID]; ok &&
			contract.detectionOnly && noRecoverableCommandFacts(facts) {
			filtered = append(filtered, finding)
			continue
		}
		category := trustedLegacyRuleCategory(generation, finding.RuleID)
		if downgradeReadOnlyDataArgs &&
			trustedReadOnlyArgumentDataFinding(category, finding) {
			if !readOnlyInspectionKnown {
				readOnlyInspection = trustedReadOnlyInspectionAction(input, facts)
				readOnlyInspectionKnown = true
			}
			if readOnlyInspection {
				finding.Severity = "LOW"
				finding.enforcement = findingEnforcementDetectionOnly
				filtered = append(filtered, finding)
				continue
			}
		}
		switch category {
		case "sensitive-path":
			if _, ok := pathMatches[finding.RuleID]; ok {
				filtered = append(filtered, finding)
			}
		case "cognitive-file":
			if _, ok := mutationMatches[finding.RuleID]; ok {
				filtered = append(filtered, finding)
			}
		case "command":
			if _, ok := commandMatches[finding.RuleID]; ok {
				filtered = append(
					filtered,
					trustedLegacyProvenCommandFinding(generation, finding, facts),
				)
			}
		case "c2":
			if _, ok := networkMatches[finding.RuleID]; ok {
				filtered = append(filtered, finding)
			}
		default:
			switch {
			case strings.HasPrefix(finding.RuleID, "PATH-"):
				if _, ok := pathMatches[finding.RuleID]; ok {
					filtered = append(filtered, finding)
				}
			case strings.HasPrefix(finding.RuleID, "COG-"):
				if _, ok := mutationMatches[finding.RuleID]; ok {
					filtered = append(filtered, finding)
				}
			case strings.HasPrefix(finding.RuleID, "CMD-"):
				if _, ok := commandMatches[finding.RuleID]; ok {
					filtered = append(
						filtered,
						trustedLegacyProvenCommandFinding(generation, finding, facts),
					)
				}
			case strings.HasPrefix(finding.RuleID, "C2-"):
				if _, ok := networkMatches[finding.RuleID]; ok {
					filtered = append(filtered, finding)
				}
			default:
				filtered = append(filtered, finding)
			}
		}
	}
	return filtered
}

func trustedLegacyProvenCommandFinding(
	generation *compiledRulePackCategories,
	finding RuleFinding,
	facts actionfacts.Facts,
) RuleFinding {
	// CMD-PYTHON-C and CMD-BASH-C are generic interpreter-shape owners. Once
	// ActionFacts proves the command being executed, retain the LOW match as
	// audit telemetry without letting the generic shape alert or block.
	// Specific semantic owners (for example reverse shells and destructive
	// commands) remain independently enforcement-capable. Unstructured and
	// malformed literal fallback never reaches this proven-owner branch and
	// keeps its existing conservative contract.
	contract, ok := trustedLegacyProvenCommandDetectionOnly[finding.RuleID]
	if !ok || !trustedLegacyDetectionOnlyCommandRule(
		generation,
		finding.RuleID,
		contract,
	) {
		return finding
	}
	if contract.prerequisite != nil && !contract.prerequisite(facts) {
		return finding
	}
	finding.enforcement = findingEnforcementDetectionOnly
	return finding
}

func trustedLegacyDetectionOnlyCommandRule(
	generation *compiledRulePackCategories,
	ruleID string,
	contract trustedLegacyProvenCommandDetectionOnlyContract,
) bool {
	if generation == nil {
		return false
	}
	matched := false
	for _, category := range generation.categories {
		for _, rule := range category.Rules {
			if canonicalTrustedRuleID(rule.ID) != canonicalTrustedRuleID(ruleID) {
				continue
			}
			if matched || rule.ID != ruleID || category.Name != contract.category ||
				rule.Pattern == nil ||
				rule.Pattern.String() != contract.pattern ||
				rule.Expression != "" || rule.ToolCallOnly ||
				rule.Title != contract.title ||
				rule.Severity != contract.severity ||
				rule.Confidence != contract.confidence ||
				!slices.Equal(rule.Tags, contract.tags) {
				return false
			}
			matched = true
		}
	}
	return matched
}

func canonicalTrustedRuleID(ruleID string) string {
	return strings.ToUpper(strings.TrimSpace(ruleID))
}

func trustedBashInlineCommandOwnerProven(facts actionfacts.Facts) bool {
	if !facts.Authoritative() {
		return false
	}
	for _, command := range facts.Commands {
		if command.Effect == actionfacts.EffectExecute &&
			command.ArgvComplete &&
			oneOfFold(command.Program, "bash", "sh") &&
			len(command.Argv) >= 3 && command.Argv[1] == "-c" &&
			strings.TrimSpace(command.Argv[2]) != "" {
			return true
		}
	}
	return false
}

func trustedPerlInlineEffectFreeOwnerProven(facts actionfacts.Facts) bool {
	return trustedInlineEffectFreeOwnerProven(
		facts,
		"perl",
		trustedPerlInlineRegexp,
		actionfacts.RecognizesPOSIXPerlInlineBody,
	)
}

func trustedRubyInlineEffectFreeOwnerProven(facts actionfacts.Facts) bool {
	return trustedInlineEffectFreeOwnerProven(
		facts,
		"ruby",
		trustedRubyInlineRegexp,
		actionfacts.RecognizesPOSIXRubyInlineBody,
	)
}

func trustedInlineEffectFreeOwnerProven(
	facts actionfacts.Facts,
	program string,
	compiledPattern *regexp.Regexp,
	recognizes func(actionfacts.CommandFact) bool,
) bool {
	if !facts.Authoritative() || !facts.EnforcementEligible() ||
		recognizes == nil || compiledPattern == nil {
		return false
	}
	commandIndex, ok := inlineCommandIndex(facts.Commands)
	if !ok {
		return false
	}
	matched := 0
	for _, command := range facts.Commands {
		text := strings.TrimSpace(command.Executable)
		if len(command.Argv) != 0 {
			text = serializeArgvForLegacyScan(command.Argv)
		}
		patternMatches := compiledPattern.MatchString(text) ||
			compiledPattern.MatchString(normalizeShell(text))
		if command.Program != program {
			if patternMatches {
				return false
			}
			continue
		}
		if !patternMatches {
			continue
		}
		if command.ParentCommandID != 0 || command.Dialect != actionfacts.DialectPOSIX ||
			command.Effect != actionfacts.EffectExecute || !command.ArgvComplete ||
			command.PipelineID != 0 || len(command.Redirects) != 0 ||
			len(command.Wrappers) != 0 || !recognizes(command) ||
			actionfacts.ProvesPOSIXInlineInterpreterForkBomb(command) ||
			len(command.Operations) != 1 || command.Operations[0] != actionfacts.OperationExecute {
			return false
		}
		matched++
	}
	if matched == 0 {
		return false
	}
	for _, command := range facts.Commands {
		if command.ParentCommandID != 0 && (command.Program == program ||
			inlineCommandDescendsFromProgram(commandIndex, command, program)) {
			return false
		}
	}
	for _, fact := range facts.Paths {
		if inlineFactOwnedByProgram(commandIndex, fact.CommandID, program) {
			return false
		}
	}
	for _, fact := range facts.Network {
		if inlineFactOwnedByProgram(commandIndex, fact.CommandID, program) {
			return false
		}
	}
	for _, fact := range facts.DataFlows {
		if inlineFactOwnedByProgram(commandIndex, fact.FromCommandID, program) ||
			inlineFactOwnedByProgram(commandIndex, fact.ToCommandID, program) {
			return false
		}
	}
	return true
}

func inlineCommandIndex(
	commands []actionfacts.CommandFact,
) (map[int64]actionfacts.CommandFact, bool) {
	index := make(map[int64]actionfacts.CommandFact, len(commands))
	for _, command := range commands {
		if command.ID == 0 {
			return nil, false
		}
		if _, duplicate := index[command.ID]; duplicate {
			return nil, false
		}
		index[command.ID] = command
	}
	return index, true
}

func inlineCommandDescendsFromProgram(
	commandIndex map[int64]actionfacts.CommandFact,
	command actionfacts.CommandFact,
	program string,
) bool {
	parentID := command.ParentCommandID
	visited := make(map[int64]struct{}, len(commandIndex))
	for steps := 0; parentID != 0; steps++ {
		if steps >= len(commandIndex) {
			return true
		}
		if _, repeated := visited[parentID]; repeated {
			return true
		}
		visited[parentID] = struct{}{}
		parent, found := commandIndex[parentID]
		if !found {
			return true
		}
		if parent.Program == program {
			return true
		}
		parentID = parent.ParentCommandID
	}
	return false
}

func inlineFactOwnedByProgram(
	commandIndex map[int64]actionfacts.CommandFact,
	commandID int64,
	program string,
) bool {
	if commandID == 0 {
		return false
	}
	command, found := commandIndex[commandID]
	if !found {
		return true
	}
	return command.Program == program ||
		inlineCommandDescendsFromProgram(commandIndex, command, program)
}

func trustedReadOnlyArgumentDataFinding(category string, finding RuleFinding) bool {
	// Action families always win over generic data tags. Some built-in path
	// findings (notably the native Windows PATH-WIN-* rules) are not members of
	// the generated category catalog, but carry a "credential" tag to describe
	// the target. Treating that tag as submitted credential data would turn an
	// actual credential-store read into inert LOW telemetry in Observe.
	for _, prefix := range []string{"PATH-", "COG-", "CMD-", "C2-"} {
		if strings.HasPrefix(finding.RuleID, prefix) {
			return false
		}
	}
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "secret", "secrets", "cred", "credential", "credential-leak",
		"enterprise-data", "pii":
		return true
	case "", "general", "unknown":
		// Unclassified/custom rules may still declare a stable data tag or ID.
	default:
		// A declared action category wins over generic tags such as credential.
		// Sensitive-path rules commonly carry that tag but still describe an
		// actual read and must keep their ordinary path enforcement.
		return false
	}
	for _, tag := range finding.Tags {
		switch strings.ToLower(strings.TrimSpace(tag)) {
		case "secret", "credential", "credential-leak", "pii":
			return true
		}
	}
	for _, prefix := range []string{
		"SEC-", "CS-SEC-", "SECRET-", "JSON-SEC-", "CG-CRED-", "CRED-",
		"ENT-", "PII-", "CS-PII-", "LP-PII-", "LP-SECRET-",
	} {
		if strings.HasPrefix(finding.RuleID, prefix) {
			return true
		}
	}
	return false
}

func trustedLegacyRuleCategory(
	generation *compiledRulePackCategories,
	ruleID string,
) string {
	if generation == nil {
		return ""
	}
	for _, category := range generation.categories {
		for _, rule := range category.Rules {
			if rule.ID == ruleID {
				return category.Name
			}
		}
	}
	return ""
}

func trustedLegacyCommandRuleMatches(
	generation *compiledRulePackCategories,
	input actionfacts.Input,
	toolName string,
	facts actionfacts.Facts,
) map[string]struct{} {
	type pipelineProjection struct {
		id               int64
		commands         []string
		stdinInterpreter bool
	}
	matchesByID := make(map[string]struct{})
	pipelines := make(map[int64]pipelineProjection)
	for _, command := range facts.Commands {
		scanCommand := command
		if command.Effect == actionfacts.EffectUncertain {
			staticArgv, ok := trustedStaticCommandArgv(command)
			if !ok {
				continue
			}
			scanCommand.Argv = staticArgv
			scanCommand.ArgvComplete = true
		} else if command.Effect != actionfacts.EffectExecute {
			continue
		}
		text := strings.TrimSpace(scanCommand.Executable)
		if len(scanCommand.Argv) != 0 {
			text = serializeArgvForLegacyScan(scanCommand.Argv)
		} else if text == "" {
			text = strings.TrimSpace(scanCommand.Program)
		}
		if !trustedCommandLiteralCarrier(scanCommand) {
			collectTrustedLegacyCommandMatches(
				generation,
				text,
				toolName,
				matchesByID,
			)
			for _, embedded := range trustedEmbeddedCommandTexts(command) {
				collectTrustedLegacyCommandMatches(
					generation,
					embedded,
					toolName,
					matchesByID,
				)
			}
		}
		if command.Effect == actionfacts.EffectExecute && command.PipelineID != 0 {
			pipeline := pipelines[command.PipelineID]
			pipeline.id = command.PipelineID
			pipeline.commands = append(pipeline.commands, text)
			pipeline.stdinInterpreter = pipeline.stdinInterpreter ||
				(actionfacts.ProvesPOSIXStdinInterpreter(command) &&
					hasDataFlowTo(
						facts,
						command.ID,
						actionfacts.DataStdout,
						actionfacts.DataStdin,
					))
			pipelines[command.PipelineID] = pipeline
		}
	}
	for _, pipeline := range pipelines {
		if len(pipeline.commands) < 2 {
			continue
		}
		pipelineMatches := make(map[string]struct{})
		collectTrustedLegacyCommandMatches(
			generation,
			strings.Join(pipeline.commands, " | "),
			toolName,
			pipelineMatches,
		)
		for ruleID := range pipelineMatches {
			if pipeline.stdinInterpreter ||
				trustedRuleHasActionProof(ruleID, input, facts) ||
				trustedPipelineFallbackProof(ruleID, pipeline.id, facts) {
				matchesByID[ruleID] = struct{}{}
			}
		}
	}
	for ruleID := range exactFallbackContracts {
		if trustedLegacyRuleCategory(generation, ruleID) == "command" &&
			trustedRuleHasActionProof(ruleID, input, facts) {
			matchesByID[ruleID] = struct{}{}
		}
	}
	for ruleID := range semanticOwners {
		if trustedLegacyRuleCategory(generation, ruleID) == "command" &&
			trustedRuleHasActionProof(ruleID, input, facts) {
			matchesByID[ruleID] = struct{}{}
		}
	}
	for _, nested := range trustedNestedExecutionActions(input, facts) {
		if nested.rawFallback {
			continue
		}
		if len(nested.facts.Commands) == 0 {
			continue
		}
		for ruleID := range trustedLegacyCommandRuleMatches(
			generation,
			nested.input,
			toolName,
			nested.facts,
		) {
			matchesByID[ruleID] = struct{}{}
		}
	}
	return matchesByID
}

func trustedStaticCommandArgv(
	command actionfacts.CommandFact,
) ([]string, bool) {
	if strings.TrimSpace(command.Program) == "" || len(command.Arguments) == 0 {
		return nil, false
	}
	argv := make([]string, 0, len(command.Arguments))
	for index, argument := range command.Arguments {
		if argument.Expands {
			if index == 0 {
				return nil, false
			}
			break
		}
		if strings.TrimSpace(argument.Value) == "" {
			if index == 0 {
				return nil, false
			}
			continue
		}
		argv = append(argv, argument.Value)
	}
	if len(argv) == 0 {
		return nil, false
	}
	return argv, true
}

type trustedNestedAction struct {
	input       actionfacts.Input
	facts       actionfacts.Facts
	rawFallback bool
}

const trustedProjectedActionTool = "defenseclaw.trusted-projected-action"

const trustedParserUncertaintyTag = "parser-uncertainty"

var (
	trustedAwkSystemPattern = regexp.MustCompile(
		`(?i)\bsystem\s*\(\s*"([^"]+)"\s*\)`,
	)
	trustedAwkGetlinePattern = regexp.MustCompile(
		`"([^"]+)"\s*\|\s*getline\b`,
	)
	trustedAwkPrintPipePattern = regexp.MustCompile(
		`\|\s*"([^"]+)"`,
	)
)

// trustedBashFallbackActions is a bounded secondary projection for valid Bash
// syntax rejected by the POSIX parser before it can emit any facts. Only a
// valid server-derived command for a recognized Bash-capable execution tool is
// eligible. Walking Bash CallExpr nodes exposes commands nested in process
// substitutions, Bash redirects, here-strings, and arithmetic loops while
// quoted lookalikes remain arguments to their actual carrier command.
func trustedBashFallbackActions(
	input actionfacts.Input,
	facts actionfacts.Facts,
) []trustedNestedAction {
	if input.Tool == trustedProjectedActionTool {
		return nil
	}
	// A generic shell envelope can carry native PowerShell or CMD syntax on
	// Windows. Those dialects already have their own structural projection;
	// reparsing their bytes as Bash can turn valid quoted arguments into a raw
	// parser-uncertainty finding (for example, CMD does not treat a backslash
	// before a closing quote as an escape). Never manufacture Bash telemetry
	// for a structurally proven non-Bash dialect. Partial or invalid Windows
	// parses still retain the bounded uncertainty lane below.
	if facts.Authoritative() &&
		(facts.Parse.Dialect == actionfacts.DialectPowerShell ||
			facts.Parse.Dialect == actionfacts.DialectCMD) {
		return nil
	}
	command, ok := trustedBashCommandInput(input)
	const maxBashFallbackBytes = 64 << 10
	if !ok {
		return nil
	}
	if facts.Parse.Status == actionfacts.StatusLimitExceeded ||
		len(command) > maxBashFallbackBytes {
		return trustedRawShellFallbackAction(input, command)
	}
	file, err := syntax.NewParser(
		syntax.Variant(syntax.LangBash),
	).Parse(strings.NewReader(command), "")
	if err != nil {
		// macOS generic shell boundaries may execute zsh syntax that mvdan's
		// Bash grammar cannot represent. The input is still a valid, trusted
		// execution envelope, so fail closed on action regexes. Normalize only
		// closing syntax delimiters so root-path rules can see an executable
		// operand immediately before `)`/`}`; quoted literals in otherwise
		// parseable commands never enter this lane.
		return trustedRawShellFallbackAction(input, command)
	}
	needsBashProjection := trustedBashTreeNeedsProjection(file)
	if facts.Authoritative() && !needsBashProjection {
		return nil
	}
	wrapperActions := trustedStaticShellWrapperFallbackActions(input, facts)
	definitions := trustedBashFunctionDefinitions(file)
	if len(facts.Commands) != 0 && len(definitions) == 0 &&
		!needsBashProjection {
		return wrapperActions
	}
	projectRoots := []syntax.Node{file}
	invoked := make(map[string]struct{})
	var queue []string
	if len(definitions) != 0 {
		queue = trustedBashStaticCallNames(file)
	}
	functionProjectionUncertain := false
	const maxInvokedFunctions = 64
	for len(queue) != 0 {
		if len(invoked) >= maxInvokedFunctions {
			functionProjectionUncertain = true
			break
		}
		name := queue[0]
		queue = queue[1:]
		definition, exists := definitions[name]
		if !exists {
			continue
		}
		if _, seen := invoked[name]; seen {
			continue
		}
		invoked[name] = struct{}{}
		projectRoots = append(projectRoots, definition.Body)
		queue = append(queue, trustedBashStaticCallNames(definition.Body)...)
	}

	const (
		maxProjectedCalls = 32
		maxRenderedBytes  = 256 << 10
	)
	actions := append([]trustedNestedAction(nil), wrapperActions...)
	projected := 0
	renderedBytes := 0
	fallbackWhole := functionProjectionUncertain
	unresolvedExecution := false
	seenBodies := make(map[string]struct{})
	project := func(root syntax.Node) {
		syntax.Walk(root, func(node syntax.Node) bool {
			if fallbackWhole {
				return false
			}
			if _, definition := node.(*syntax.FuncDecl); definition {
				return false
			}
			var (
				executable       syntax.Node
				call             *syntax.CallExpr
				unresolvedAction bool
			)
			switch node := node.(type) {
			case *syntax.Stmt:
				if _, definition := node.Cmd.(*syntax.FuncDecl); definition {
					return true
				}
				executable = node
				if assignment, ok := node.Cmd.(*syntax.CallExpr); ok &&
					len(assignment.Args) == 0 && len(node.Redirs) != 0 {
					unresolvedAction = true
				}
			case *syntax.CallExpr:
				executable = node
				call = node
			default:
				return true
			}
			var rendered bytes.Buffer
			if err := syntax.NewPrinter().Print(&rendered, executable); err != nil {
				return true
			}
			body := strings.TrimSpace(rendered.String())
			if call != nil {
				// Static field rendering can preserve glob syntax as a literal
				// argv value even though Bash will select the executable at
				// runtime. Keep that useful projection, but also retain the raw
				// detection-only uncertainty lane for the unresolved command
				// identity.
				if trustedBashCallHasDynamicExecutable(call) {
					unresolvedExecution = true
				}
				if fields, ok := trustedBashStaticFields(call); ok {
					body = serializeArgvForLegacyScan(fields)
				} else if trustedBashCallNeedsProjection(call) {
					unresolvedExecution = true
				}
			}
			if body == "" {
				return true
			}
			renderedBytes += len(body)
			if renderedBytes > maxRenderedBytes {
				fallbackWhole = true
				return false
			}
			if _, duplicate := seenBodies[body]; duplicate {
				return true
			}
			seenBodies[body] = struct{}{}
			if projected >= maxProjectedCalls {
				fallbackWhole = true
				return false
			}
			nestedInput := actionfacts.Input{
				Tool:       "bash",
				Command:    body,
				CWD:        input.CWD,
				ActiveHome: input.ActiveHome,
			}
			nestedFacts := actionfacts.Analyze(nestedInput)
			if len(nestedFacts.Commands) == 0 {
				// Assignment-only CallExpr nodes do not execute an external
				// command. In particular, a static Bash array declaration must
				// not create parser-uncertainty telemetry merely because the
				// POSIX projection cannot represent it. Any command substitutions
				// in the assignment are walked and projected independently, while
				// statement-level redirections remain unresolved actions.
				if unresolvedAction || (call != nil && len(call.Args) != 0) {
					unresolvedExecution = true
				}
				return true
			}
			actions = append(actions, trustedNestedAction{
				input: trustedTerminalNestedInput(nestedInput),
				facts: nestedFacts,
			})
			projected++
			return true
		})
	}
	for _, root := range projectRoots {
		project(root)
	}
	if fallbackWhole || unresolvedExecution {
		actions = append(
			actions,
			trustedRawShellFallbackAction(input, command)...,
		)
	}
	return actions
}

func trustedStaticShellWrapperFallbackActions(
	input actionfacts.Input,
	facts actionfacts.Facts,
) []trustedNestedAction {
	seen := make(map[string]struct{})
	var actions []trustedNestedAction
	for _, command := range facts.Commands {
		if command.Effect != actionfacts.EffectExecute &&
			command.Effect != actionfacts.EffectUncertain {
			continue
		}
		program := strings.ToLower(strings.TrimSpace(command.Program))
		switch program {
		case "bash", "zsh", "ksh", "sh", "dash":
		default:
			continue
		}
		for index := 1; index+1 < len(command.Arguments); index++ {
			option := command.Arguments[index]
			if option.Expands || !trustedShellCommandOption(option.Value) {
				continue
			}
			script := command.Arguments[index+1]
			if script.Expands {
				actions = append(
					actions,
					trustedRawShellFallbackAction(
						input,
						serializeArgvForLegacyScan(command.Argv),
					)...,
				)
				break
			}
			if strings.TrimSpace(script.Value) == "" {
				continue
			}
			if _, duplicate := seen[script.Value]; duplicate {
				continue
			}
			seen[script.Value] = struct{}{}
			nestedInput := actionfacts.Input{
				Tool:       program,
				Command:    script.Value,
				CWD:        input.CWD,
				ActiveHome: input.ActiveHome,
			}
			nestedFacts := actionfacts.Analyze(nestedInput)
			actions = append(
				actions,
				trustedBashFallbackActions(nestedInput, nestedFacts)...,
			)
			break
		}
	}
	return actions
}

func trustedBashTreeNeedsProjection(root syntax.Node) bool {
	needsProjection := false
	syntax.Walk(root, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok {
			return true
		}
		if trustedBashCallNeedsProjection(call) {
			needsProjection = true
			return false
		}
		return !needsProjection
	})
	return needsProjection
}

func trustedBashCallNeedsProjection(call *syntax.CallExpr) bool {
	if call == nil {
		return false
	}
	if trustedBashCallHasDynamicExecutable(call) {
		return true
	}
	for _, word := range call.Args {
		if trustedBashWordNeedsProjection(word) {
			return true
		}
	}
	return false
}

// trustedBashCallHasDynamicExecutable identifies a runtime expansion in the
// command word. Expansions in later argv positions do not make the executable
// identity uncertain and therefore must not create generic parser telemetry.
//
// Deliberately do not resolve parameter or array values from earlier shell
// assignments here. Doing that soundly requires control-flow, scope, quoting,
// and mutation semantics that the bounded projection does not currently own;
// the existing raw fallback instead records the uncertainty without allowing
// it to drive enforcement.
func trustedBashCallHasDynamicExecutable(call *syntax.CallExpr) bool {
	if call == nil || len(call.Args) == 0 || call.Args[0] == nil {
		return false
	}
	index := 0
	const maxTransparentWrappers = 4
	for depth := 0; depth <= maxTransparentWrappers; depth++ {
		if index >= len(call.Args) || call.Args[index] == nil {
			return false
		}
		word := call.Args[index]
		if trustedBashWordHasDynamicExecutable(word) {
			return true
		}
		program, ok := trustedBashStaticWordValue(word)
		if !ok {
			return false
		}
		program = path.Base(program)
		next, ok := trustedBashTransparentWrapperExecutable(call.Args, index, program)
		if next == trustedBashUnresolvedWrapperExecutable {
			return true
		}
		if !ok {
			return false
		}
		index = next
	}
	return true
}

func trustedBashWordHasDynamicExecutable(word *syntax.Word) bool {
	if word == nil {
		return false
	}
	var shellPattern strings.Builder
	if trustedBashAppendExecutablePattern(&shellPattern, word.Parts, false) {
		return true
	}
	candidate := shellPattern.String()
	if !pattern.HasMeta(candidate, 0) {
		return false
	}
	// An unmatched bracket is a literal command name under ordinary Bash glob
	// semantics (for example the standard `[` command). Validate the complete
	// quote-aware word because a bracket expression may cross AST parts, as in
	// /bin/r['m']; validating each literal fragment would miss that expansion.
	_, err := pattern.Regexp(candidate, pattern.Filenames|pattern.EntireString)
	return err == nil
}

// trustedBashAppendExecutablePattern reconstructs one shell pattern while
// quoting metacharacters contributed by quoted AST parts. It returns true for
// value-producing expansions whose result can select the executable directly.
func trustedBashAppendExecutablePattern(
	destination *strings.Builder,
	parts []syntax.WordPart,
	quoted bool,
) bool {
	for _, part := range parts {
		switch part := part.(type) {
		case *syntax.ParamExp, *syntax.CmdSubst, *syntax.ArithmExp,
			*syntax.ProcSubst:
			return true
		case *syntax.ExtGlob:
			if !quoted {
				return true
			}
		case *syntax.Lit:
			value := part.Value
			if quoted {
				value = pattern.QuoteMeta(value, 0)
			}
			destination.WriteString(value)
		case *syntax.SglQuoted:
			destination.WriteString(pattern.QuoteMeta(part.Value, 0))
		case *syntax.DblQuoted:
			// Parameter and command expansion still occur inside double
			// quotes, but pathname expansion does not.
			if trustedBashAppendExecutablePattern(destination, part.Parts, true) {
				return true
			}
		}
	}
	return false
}

func trustedBashStaticWordValue(word *syntax.Word) (string, bool) {
	if word == nil || trustedBashWordMayExpandHome(word) {
		return "", false
	}
	fields, err := expand.Fields(&expand.Config{}, word)
	if err != nil || len(fields) != 1 || strings.TrimSpace(fields[0]) != fields[0] {
		return "", false
	}
	return fields[0], fields[0] != ""
}

const trustedBashUnresolvedWrapperExecutable = -1

func trustedBashTransparentWrapperExecutable(
	args []*syntax.Word,
	wrapperIndex int,
	program string,
) (int, bool) {
	switch program {
	case "command":
		for index := wrapperIndex + 1; index < len(args); index++ {
			argument, static := trustedBashStaticWordValue(args[index])
			if !static {
				return index, true
			}
			switch argument {
			case "--":
				return index + 1, index+1 < len(args)
			case "-p":
				continue
			case "-v", "-V":
				return 0, false
			}
			if strings.HasPrefix(argument, "-") {
				return trustedBashUnresolvedWrapperExecutable, false
			}
			return index, true
		}

	case "exec":
		for index := wrapperIndex + 1; index < len(args); index++ {
			argument, static := trustedBashStaticWordValue(args[index])
			if !static {
				return index, true
			}
			switch argument {
			case "--":
				return index + 1, index+1 < len(args)
			case "-c", "-l", "-cl", "-lc":
				continue
			case "-a":
				index++
				if index >= len(args) {
					return 0, false
				}
				continue
			}
			if strings.HasPrefix(argument, "-") {
				return trustedBashUnresolvedWrapperExecutable, false
			}
			return index, true
		}

	case "env":
		for index := wrapperIndex + 1; index < len(args); index++ {
			if trustedBashEnvironmentAssignmentWord(args[index]) {
				continue
			}
			argument, static := trustedBashStaticWordValue(args[index])
			if !static {
				return index, true
			}
			switch argument {
			case "--":
				for index++; index < len(args); index++ {
					if trustedBashEnvironmentAssignmentWord(args[index]) {
						continue
					}
					value, ok := trustedBashStaticWordValue(args[index])
					if !ok || !trustedBashEnvironmentAssignment(value) {
						return index, true
					}
				}
				return 0, false
			case "--help", "--version":
				return 0, false
			case "-S", "--split-string":
				return trustedBashUnresolvedWrapperExecutable, false
			case "-u", "--unset", "-C", "--chdir":
				index++
				if index >= len(args) {
					return 0, false
				}
				continue
			case "-i", "--ignore-environment", "-0", "--null", "-v", "--debug":
				continue
			}
			if strings.HasPrefix(argument, "--unset=") ||
				strings.HasPrefix(argument, "--chdir=") ||
				len(argument) > 2 && strings.HasPrefix(argument, "-C") {
				continue
			}
			if strings.HasPrefix(argument, "--split-string=") ||
				strings.HasPrefix(argument, "-") {
				return trustedBashUnresolvedWrapperExecutable, false
			}
			if trustedBashEnvironmentAssignment(argument) {
				continue
			}
			return index, true
		}

	case "sudo":
		for index := wrapperIndex + 1; index < len(args); index++ {
			if trustedBashEnvironmentAssignmentWord(args[index]) {
				continue
			}
			argument, static := trustedBashStaticWordValue(args[index])
			if !static {
				return index, true
			}
			if argument == "--" {
				for index++; index < len(args); index++ {
					if trustedBashEnvironmentAssignmentWord(args[index]) {
						continue
					}
					value, ok := trustedBashStaticWordValue(args[index])
					if !ok || !trustedBashEnvironmentAssignment(value) {
						return index, true
					}
				}
				return 0, false
			}
			switch argument {
			case "-i", "--login", "-s", "--shell":
				if index+1 < len(args) {
					return trustedBashUnresolvedWrapperExecutable, false
				}
				return 0, false
			case "-l", "-ll", "--list", "-e", "--edit", "-v", "--validate",
				"-V", "--version", "--help":
				return 0, false
			case "-u", "--user", "-g", "--group", "-h", "--host", "-p", "--prompt",
				"-C", "--close-from", "-T", "--command-timeout", "-r", "--role", "-t", "--type",
				"-D", "--chdir", "-R", "--chroot":
				index++
				if index >= len(args) {
					return 0, false
				}
				continue
			case "-n", "--non-interactive", "-E", "--preserve-env", "-H", "--set-home",
				"-S", "--stdin", "-k", "--reset-timestamp", "-K", "--remove-timestamp",
				"-b", "--background":
				continue
			}
			if trustedBashSudoAttachedOption(argument) {
				continue
			}
			if strings.HasPrefix(argument, "-") {
				return trustedBashUnresolvedWrapperExecutable, false
			}
			if trustedBashEnvironmentAssignment(argument) {
				continue
			}
			return index, true
		}
	}
	return 0, false
}

func trustedBashEnvironmentAssignment(argument string) bool {
	name, _, ok := strings.Cut(argument, "=")
	return ok && name != ""
}

func trustedBashEnvironmentAssignmentWord(word *syntax.Word) bool {
	if word == nil || len(word.Parts) == 0 {
		return false
	}
	literal, ok := word.Parts[0].(*syntax.Lit)
	if !ok {
		return false
	}
	name, _, ok := strings.Cut(literal.Value, "=")
	return ok && name != "" && !strings.HasPrefix(name, "-")
}

func trustedBashSudoAttachedOption(argument string) bool {
	for _, prefix := range []string{
		"--user=", "--group=", "--host=", "--prompt=", "--close-from=",
		"--command-timeout=", "--role=", "--type=", "--chdir=", "--chroot=",
	} {
		if strings.HasPrefix(argument, prefix) && len(argument) > len(prefix) {
			return true
		}
	}
	return strings.HasPrefix(argument, "--preserve-env=") &&
		len(argument) > len("--preserve-env=")
}

func trustedBashWordNeedsProjection(word *syntax.Word) bool {
	if word == nil {
		return false
	}
	copyWord := *word
	if syntax.SplitBraces(&copyWord) {
		return true
	}
	needsProjection := false
	syntax.Walk(word, func(node syntax.Node) bool {
		switch quoted := node.(type) {
		case *syntax.SglQuoted:
			needsProjection = needsProjection || quoted.Dollar
		case *syntax.DblQuoted:
			needsProjection = needsProjection || quoted.Dollar
		}
		return !needsProjection
	})
	return needsProjection
}

func trustedBashStaticFields(call *syntax.CallExpr) ([]string, bool) {
	if call == nil || len(call.Args) == 0 {
		return nil, false
	}
	for _, assignment := range call.Assigns {
		if assignment.Name == nil {
			return nil, false
		}
		switch strings.ToUpper(assignment.Name.Value) {
		case "PATH", "BASH_ENV", "ENV", "LD_PRELOAD", "LD_LIBRARY_PATH",
			"DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH":
			return nil, false
		}
	}
	fields := make([]string, 0, len(call.Args))
	for _, word := range call.Args {
		static := true
		syntax.Walk(word, func(node syntax.Node) bool {
			switch node.(type) {
			case *syntax.ParamExp, *syntax.CmdSubst, *syntax.ArithmExp,
				*syntax.ProcSubst:
				static = false
				return false
			}
			return static
		})
		if !static || trustedBashWordMayExpandHome(word) {
			if len(fields) == 0 {
				return nil, false
			}
			break
		}
		expanded, err := expand.Fields(&expand.Config{}, word)
		if err != nil {
			if len(fields) == 0 {
				return nil, false
			}
			break
		}
		fields = append(fields, expanded...)
		if len(fields) > 256 {
			return nil, false
		}
	}
	if len(fields) == 0 {
		return nil, false
	}
	for _, field := range fields {
		if strings.IndexByte(field, 0) >= 0 || len(field) > 8<<10 {
			return nil, false
		}
	}
	return fields, true
}

func trustedBashWordMayExpandHome(word *syntax.Word) bool {
	if word == nil || len(word.Parts) == 0 {
		return false
	}
	literal, ok := word.Parts[0].(*syntax.Lit)
	return ok && strings.HasPrefix(literal.Value, "~")
}

func trustedShellCommandOption(value string) bool {
	if value == "-c" || value == "--command" {
		return true
	}
	return strings.HasPrefix(value, "-") &&
		!strings.HasPrefix(value, "--") &&
		strings.Contains(strings.TrimPrefix(value, "-"), "c")
}

func trustedEmbeddedExecutionActions(
	input actionfacts.Input,
	facts actionfacts.Facts,
) []trustedNestedAction {
	if input.Tool == trustedProjectedActionTool {
		return nil
	}
	seen := make(map[string]struct{})
	var actions []trustedNestedAction
	var uncertaintyText string
	markUncertainty := func(text string) {
		if uncertaintyText == "" {
			uncertaintyText = trustedBoundedText(text, 64<<10)
		}
	}
	const (
		maxDirectNestedCount = 32
		maxDirectNestedBytes = 128 << 10
	)
	directBytes := 0
	var overflowText string
	reserve := func(text string) bool {
		if len(actions) >= maxDirectNestedCount ||
			directBytes+len(text) > maxDirectNestedBytes {
			if overflowText == "" {
				overflowText = trustedBoundedText(
					trustedActionInputText(input, text),
					maxDirectNestedBytes,
				)
			}
			return false
		}
		directBytes += len(text)
		return true
	}
	appendText := func(text string) {
		text = strings.TrimSpace(text)
		if text == "" {
			return
		}
		key := "text\x00" + text
		if _, duplicate := seen[key]; duplicate {
			return
		}
		seen[key] = struct{}{}
		if !reserve(text) {
			return
		}
		nestedInput := actionfacts.Input{
			Tool:       "bash",
			Command:    text,
			CWD:        input.CWD,
			ActiveHome: input.ActiveHome,
		}
		nestedFacts := actionfacts.Analyze(nestedInput)
		if len(nestedFacts.Commands) == 0 {
			actions = append(
				actions,
				trustedBashFallbackActions(nestedInput, nestedFacts)...,
			)
			return
		}
		actions = append(actions, trustedNestedAction{
			input: trustedTerminalNestedInput(nestedInput),
			facts: nestedFacts,
		})
	}
	appendArgv := func(argv []string) {
		if len(argv) == 0 {
			return
		}
		key := "argv\x00" + strings.Join(argv, "\x00")
		if _, duplicate := seen[key]; duplicate {
			return
		}
		seen[key] = struct{}{}
		if !reserve(serializeArgvForLegacyScan(argv)) {
			return
		}
		nestedInput := actionfacts.Input{
			Tool:       "shell",
			Argv:       append([]string(nil), argv...),
			CWD:        input.CWD,
			ActiveHome: input.ActiveHome,
		}
		actions = append(actions, trustedNestedAction{
			input: trustedTerminalNestedInput(nestedInput),
			facts: actionfacts.Analyze(nestedInput),
		})
	}

	commands := make(map[int64]actionfacts.CommandFact, len(facts.Commands))
	for _, command := range facts.Commands {
		commands[command.ID] = command
		if command.Effect != actionfacts.EffectExecute &&
			command.Effect != actionfacts.EffectUncertain {
			continue
		}
		program := strings.ToLower(strings.TrimSpace(command.Program))
		switch program {
		case "find":
			for index := 1; index < len(command.Argv); index++ {
				if !oneOfFold(command.Argv[index], "-exec", "-execdir", "-ok", "-okdir") {
					continue
				}
				end := index + 1
				for end < len(command.Argv) && command.Argv[end] != ";" && command.Argv[end] != "+" {
					end++
				}
				appendArgv(command.Argv[index+1 : end])
				index = end
			}
		case "fd":
			for index := 1; index < len(command.Argv); index++ {
				if oneOfFold(command.Argv[index], "-x", "--exec", "-X", "--exec-batch") {
					appendArgv(command.Argv[index+1:])
					break
				}
				for _, prefix := range []string{"--exec=", "--exec-batch="} {
					if strings.HasPrefix(command.Argv[index], prefix) {
						appendText(strings.TrimPrefix(command.Argv[index], prefix))
					}
				}
			}
		case "rg", "ripgrep":
			for index := 1; index < len(command.Argv); index++ {
				if command.Argv[index] == "--pre" && index+1 < len(command.Argv) {
					appendText(command.Argv[index+1])
					break
				}
				if strings.HasPrefix(command.Argv[index], "--pre=") {
					appendText(strings.TrimPrefix(command.Argv[index], "--pre="))
					break
				}
			}
		case "sed":
			embedded := trustedEmbeddedCommandTexts(command)
			for _, text := range embedded {
				appendText(text)
			}
			if len(embedded) == 0 && sedInvocationExecutes(command.Argv) {
				markUncertainty(serializeArgvForLegacyScan(command.Argv))
			}
		case "awk":
			extracted := 0
			for _, argument := range trustedAwkProgramTexts(command.Argv) {
				argument = trustedStripAwkComments(argument)
				for _, pattern := range []*regexp.Regexp{
					trustedAwkSystemPattern,
					trustedAwkGetlinePattern,
					trustedAwkPrintPipePattern,
				} {
					for _, match := range pattern.FindAllStringSubmatch(argument, -1) {
						if len(match) > 1 {
							appendText(match[1])
							extracted++
						}
					}
				}
			}
			if extracted == 0 && awkInvocationExecutes(command.Argv) {
				markUncertainty(serializeArgvForLegacyScan(command.Argv))
			}
		case "eval":
			var fields []string
			for _, argument := range trustedCommandOperandArguments(command) {
				if argument.Expands {
					markUncertainty(serializeArgvForLegacyScan(command.Argv))
					break
				}
				fields = append(fields, argument.Value)
			}
			appendText(strings.Join(fields, " "))
		}
	}
	for _, flow := range facts.DataFlows {
		if flow.From != actionfacts.DataStdout || flow.To != actionfacts.DataStdin {
			continue
		}
		source, sourceOK := commands[flow.FromCommandID]
		sink, sinkOK := commands[flow.ToCommandID]
		if !sourceOK || !sinkOK || !actionfacts.ProvesPOSIXStdinInterpreter(sink) {
			continue
		}
		if source.Effect != actionfacts.EffectExecute ||
			sink.Effect != actionfacts.EffectExecute {
			continue
		}
		switch strings.ToLower(source.Program) {
		case "echo":
			var fields []string
			for _, argument := range trustedCommandOperandArguments(source) {
				if argument.Expands {
					markUncertainty(serializeArgvForLegacyScan(source.Argv))
					break
				}
				fields = append(fields, argument.Value)
			}
			appendText(strings.Join(fields, " "))
		case "printf":
			static := trustedCommandOperandArguments(source)
			for _, argument := range static {
				if argument.Expands {
					markUncertainty(serializeArgvForLegacyScan(source.Argv))
					break
				}
			}
			if len(static) == 1 && !static[0].Expands {
				appendText(static[0].Value)
				continue
			}
			if len(static) <= 1 {
				continue
			}
			for _, argument := range static[1:] {
				if !argument.Expands {
					appendText(argument.Value)
				}
			}
		}
	}
	if overflowText != "" {
		actions = append(
			actions,
			trustedRawShellFallbackAction(input, overflowText)...,
		)
	}
	if uncertaintyText != "" {
		actions = append(
			actions,
			trustedRawShellFallbackAction(input, uncertaintyText)...,
		)
	}
	return actions
}

func trustedAwkProgramTexts(argv []string) []string {
	var programs []string
	hasSource := false
	for index := 1; index < len(argv); index++ {
		argument := argv[index]
		switch argument {
		case "-f", "--file":
			hasSource = true
			if index+1 < len(argv) {
				index++
			}
		case "-e", "--source":
			hasSource = true
			if index+1 < len(argv) {
				programs = append(programs, argv[index+1])
				index++
			}
		case "-v", "-F", "--field-separator", "--assign":
			if index+1 < len(argv) {
				index++
			}
		case "--":
			if !hasSource && index+1 < len(argv) {
				programs = append(programs, argv[index+1])
			}
			return programs
		default:
			if strings.HasPrefix(argument, "-F") ||
				strings.HasPrefix(argument, "-v") ||
				strings.HasPrefix(argument, "--source=") ||
				strings.HasPrefix(argument, "--file=") {
				if strings.HasPrefix(argument, "--source=") {
					hasSource = true
					programs = append(programs, strings.TrimPrefix(argument, "--source="))
				}
				if strings.HasPrefix(argument, "--file=") {
					hasSource = true
				}
				continue
			}
			if strings.HasPrefix(argument, "-") {
				continue
			}
			if !hasSource {
				programs = append(programs, argument)
			}
			return programs
		}
	}
	return programs
}

func trustedNestedExecutionActions(
	input actionfacts.Input,
	facts actionfacts.Facts,
) []trustedNestedAction {
	if input.Tool == trustedProjectedActionTool {
		return nil
	}
	type queuedAction struct {
		action trustedNestedAction
		depth  int
	}
	direct := func(
		candidate actionfacts.Input,
		candidateFacts actionfacts.Facts,
	) []trustedNestedAction {
		actions := trustedBashFallbackActions(candidate, candidateFacts)
		return append(
			actions,
			trustedEmbeddedExecutionActions(candidate, candidateFacts)...,
		)
	}
	queue := make([]queuedAction, 0, 16)
	for _, action := range direct(input, facts) {
		queue = append(queue, queuedAction{action: action})
	}
	const (
		maxNestedDepth = 4
		maxNestedCount = 64
		maxNestedBytes = 256 << 10
	)
	seen := make(map[string]struct{})
	actions := make([]trustedNestedAction, 0, len(queue))
	processedBytes := 0
	var overflow strings.Builder
	for len(queue) != 0 {
		queued := queue[0]
		queue = queue[1:]
		text := trustedNestedActionText(queued.action)
		key := strings.Join([]string{
			text,
			string(queued.action.facts.Parse.Status),
			string(queued.action.facts.Parse.Dialect),
		}, "\x00")
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		if len(actions) >= maxNestedCount ||
			processedBytes+len(text) > maxNestedBytes {
			overflow.WriteString(trustedBoundedText(
				trustedActionInputText(input, text),
				maxNestedBytes,
			))
			break
		}
		processedBytes += len(text)
		actions = append(actions, queued.action)
		if queued.action.rawFallback {
			continue
		}
		if queued.depth >= maxNestedDepth {
			overflow.WriteString(trustedBoundedText(
				trustedActionInputText(input, text),
				maxNestedBytes,
			))
			break
		}
		exploreInput := queued.action.input
		exploreInput.Tool = queued.action.facts.Tool
		if strings.TrimSpace(exploreInput.Tool) == "" {
			exploreInput.Tool = "bash"
		}
		for _, child := range direct(exploreInput, queued.action.facts) {
			queue = append(queue, queuedAction{
				action: child,
				depth:  queued.depth + 1,
			})
		}
	}
	if overflow.Len() != 0 {
		actions = append(
			actions,
			trustedRawShellFallbackAction(input, overflow.String())...,
		)
	}
	return actions
}

func trustedNestedActionText(action trustedNestedAction) string {
	if strings.TrimSpace(action.input.Command) != "" {
		return action.input.Command
	}
	if len(action.input.Argv) != 0 {
		return serializeArgvForLegacyScan(action.input.Argv)
	}
	return ""
}

func trustedActionInputText(input actionfacts.Input, fallback string) string {
	if strings.TrimSpace(input.Command) != "" {
		return input.Command
	}
	if command, present, valid := trustedTopLevelCommandField(input.Args); valid && present && strings.TrimSpace(command) != "" {
		return command
	}
	if len(input.Argv) != 0 {
		return serializeArgvForLegacyScan(input.Argv)
	}
	return fallback
}

func trustedBoundedText(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	return text[:limit]
}

func trustedBashFunctionDefinitions(
	root syntax.Node,
) map[string]*syntax.FuncDecl {
	definitions := make(map[string]*syntax.FuncDecl)
	syntax.Walk(root, func(node syntax.Node) bool {
		definition, ok := node.(*syntax.FuncDecl)
		if !ok {
			return true
		}
		if definition.Name != nil && definition.Name.Value != "" {
			definitions[definition.Name.Value] = definition
		}
		for _, name := range definition.Names {
			if name != nil && name.Value != "" {
				definitions[name.Value] = definition
			}
		}
		return false
	})
	return definitions
}

func trustedBashStaticCallNames(root syntax.Node) []string {
	const maxStaticCalls = 64
	var names []string
	syntax.Walk(root, func(node syntax.Node) bool {
		if len(names) >= maxStaticCalls {
			return false
		}
		if _, definition := node.(*syntax.FuncDecl); definition {
			return false
		}
		call, ok := node.(*syntax.CallExpr)
		if !ok {
			return true
		}
		fields, ok := trustedBashStaticFields(call)
		if !ok || len(fields) == 0 || strings.TrimSpace(fields[0]) == "" {
			return true
		}
		names = append(names, fields[0])
		return true
	})
	return names
}

func trustedRawShellFallbackAction(
	input actionfacts.Input,
	command string,
) []trustedNestedAction {
	return []trustedNestedAction{{
		input: trustedTerminalNestedInput(actionfacts.Input{
			Tool:       "bash",
			Command:    trustedExecutableShellProjection(command),
			CWD:        input.CWD,
			ActiveHome: input.ActiveHome,
		}),
		rawFallback: true,
	}}
}

func trustedTerminalNestedInput(input actionfacts.Input) actionfacts.Input {
	input.Tool = trustedProjectedActionTool
	input.Args = nil
	return input
}

type trustedShellHeredoc struct {
	delimiter string
	stripTabs bool
}

// trustedExecutableShellProjection is the last-resort lane for a validated
// shell execution envelope whose dialect or size cannot be represented by
// ActionFacts. It preserves unquoted executable syntax, but masks strings,
// comments, and heredoc bodies so source-review examples do not become proof
// of an action merely because the primary parser could not classify them.
func trustedExecutableShellProjection(command string) string {
	var projected strings.Builder
	projected.Grow(len(command))
	var (
		quote    byte
		escaped  bool
		heredocs []trustedShellHeredoc
	)
	for offset := 0; offset < len(command); {
		lineEnd := strings.IndexByte(command[offset:], '\n')
		hasNewline := lineEnd >= 0
		if !hasNewline {
			lineEnd = len(command) - offset
		}
		line := command[offset : offset+lineEnd]
		if len(heredocs) != 0 {
			candidate := strings.TrimSuffix(line, "\r")
			if heredocs[0].stripTabs {
				candidate = strings.TrimLeft(candidate, "\t")
			}
			if candidate == heredocs[0].delimiter {
				heredocs = heredocs[1:]
			}
			projected.WriteString(strings.Repeat(" ", len(line)))
		} else {
			for index := 0; index < len(line); index++ {
				current := line[index]
				if quote != 0 {
					projected.WriteByte(' ')
					if escaped {
						escaped = false
						continue
					}
					if quote == '"' && current == '\\' {
						escaped = true
						continue
					}
					if current == quote {
						quote = 0
					}
					continue
				}
				if escaped {
					projected.WriteByte(' ')
					escaped = false
					continue
				}
				if current == '\\' {
					projected.WriteByte(' ')
					escaped = true
					continue
				}
				if current == '\'' || current == '"' {
					quote = current
					projected.WriteByte(' ')
					continue
				}
				if current == '#' && trustedShellCommentBoundary(line, index) {
					projected.WriteString(strings.Repeat(" ", len(line)-index))
					break
				}
				if current == '<' && index+1 < len(line) &&
					line[index+1] == '<' &&
					(index+2 >= len(line) || line[index+2] != '<') {
					if heredoc, ok := trustedShellHeredocAt(line, index); ok {
						heredocs = append(heredocs, heredoc)
					}
				}
				switch current {
				case ')', '}', ';':
					projected.WriteByte(' ')
				default:
					projected.WriteByte(current)
				}
			}
		}
		if hasNewline {
			projected.WriteByte('\n')
			offset += lineEnd + 1
			continue
		}
		offset += lineEnd
	}
	return projected.String()
}

func trustedShellCommentBoundary(line string, index int) bool {
	if index == 0 {
		return true
	}
	previous := line[index-1]
	return previous == ' ' || previous == '\t' ||
		strings.ContainsRune(";|&(){}<>", rune(previous))
}

func trustedShellHeredocAt(
	line string,
	operator int,
) (trustedShellHeredoc, bool) {
	index := operator + 2
	heredoc := trustedShellHeredoc{}
	if index < len(line) && line[index] == '-' {
		heredoc.stripTabs = true
		index++
	}
	for index < len(line) && (line[index] == ' ' || line[index] == '\t') {
		index++
	}
	if index >= len(line) {
		return trustedShellHeredoc{}, false
	}
	if line[index] == '\'' || line[index] == '"' {
		quote := line[index]
		index++
		start := index
		for index < len(line) && line[index] != quote {
			index++
		}
		if index == len(line) || index == start {
			return trustedShellHeredoc{}, false
		}
		heredoc.delimiter = line[start:index]
		return heredoc, true
	}
	start := index
	for index < len(line) && !strings.ContainsRune(" \t\r;|&()<>", rune(line[index])) {
		index++
	}
	if index == start {
		return trustedShellHeredoc{}, false
	}
	heredoc.delimiter = line[start:index]
	return heredoc, true
}

func trustedBashCommandInput(input actionfacts.Input) (string, bool) {
	if !trustedBashExecutionTool(input.Tool) {
		return "", false
	}
	command := input.Command
	if len(bytes.TrimSpace(input.Args)) != 0 {
		fromArgs, present, valid := trustedTopLevelCommandField(input.Args)
		if !valid || command != "" && present && command != fromArgs {
			return "", false
		}
		if command == "" && present {
			command = fromArgs
		}
	}
	if strings.TrimSpace(command) == "" || strings.IndexByte(command, 0) >= 0 {
		return "", false
	}
	return command, true
}

func trustedBashExecutionTool(tool string) bool {
	switch strings.ToLower(strings.TrimSpace(tool)) {
	case "bash", "zsh", "ksh", "shell", "shell_command", "terminal",
		"run_command", "run_shell", "run_shell_command", "runshellcommand",
		"run_terminal_cmd", "execute", "execute_command", "exec",
		"exec_command", "command", "subprocess", "system.run":
		return true
	default:
		return false
	}
}

func trustedTopLevelCommandField(raw json.RawMessage) (string, bool, bool) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return "", false, false
	}
	seen := make(map[string]struct{})
	var command string
	found := false
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return "", false, false
		}
		lower := strings.ToLower(key)
		if _, duplicate := seen[lower]; duplicate {
			return "", false, false
		}
		seen[lower] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return "", false, false
		}
		if !trustedCommandFieldName(lower) {
			continue
		}
		if found || json.Unmarshal(value, &command) != nil {
			return "", false, false
		}
		found = true
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return "", false, false
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return "", false, false
	}
	return command, found, true
}

func trustedCommandFieldName(name string) bool {
	switch name {
	case "command", "cmd", "script", "rawcommand", "raw_command",
		"raw-command", "shellcommand", "shell_command", "shell-command",
		"commandline", "command_line", "command-line":
		return true
	default:
		return false
	}
}

func appendTrustedBashFallbackFindings(
	findings []RuleFinding,
	generation *compiledRulePackCategories,
	input actionfacts.Input,
	toolName string,
	facts actionfacts.Facts,
	options ruleScanOptions,
	enforcementCapable bool,
	downgradeReadOnlyDataArgs bool,
) []RuleFinding {
	seen := make(map[string]int, len(findings))
	for index, finding := range findings {
		seen[finding.RuleID] = index
	}
	var typedProof map[string]struct{}
	loadTypedProof := func() map[string]struct{} {
		if typedProof == nil {
			typedProof = trustedTypedLegacyActionRuleMatches(
				generation,
				input,
				toolName,
				facts,
			)
		}
		return typedProof
	}
	for _, nested := range trustedNestedExecutionActions(input, facts) {
		if nested.rawFallback {
			matched := false
			for _, finding := range scanRuleGeneration(
				generation,
				nested.input.Command,
				toolName,
				options,
			) {
				matched = true
				finding = markTrustedParserUncertainty(finding)
				if index, exists := seen[finding.RuleID]; exists {
					if _, proven := loadTypedProof()[finding.RuleID]; !proven {
						findings[index] = finding
					}
					continue
				}
				seen[finding.RuleID] = len(findings)
				findings = append(findings, finding)
			}
			if _, exists := seen[trustedParserUncertaintyRuleID]; !exists {
				finding := trustedParserUncertaintyFinding(matched)
				seen[finding.RuleID] = len(findings)
				findings = append(findings, finding)
			}
			continue
		}
		if len(nested.facts.Commands) == 0 {
			continue
		}
		nestedFindings := scanRuleGeneration(
			generation,
			nested.input.Command,
			toolName,
			options,
		)
		nestedFindings = appendTrustedEmbeddedCommandFindings(
			nestedFindings,
			generation,
			toolName,
			nested.facts,
			options,
		)
		nestedFindings = filterTrustedLegacyActionContext(
			generation,
			nestedFindings,
			nested.input,
			toolName,
			nested.facts,
			downgradeReadOnlyDataArgs,
		)
		nestedFindings = filterExactFallbackFindings(
			nestedFindings,
			nested.input,
			nested.facts,
			enforcementCapable,
		)
		for _, finding := range nestedFindings {
			if _, exists := seen[finding.RuleID]; exists {
				continue
			}
			seen[finding.RuleID] = len(findings)
			findings = append(findings, finding)
		}
	}
	return findings
}

func markTrustedParserUncertainty(finding RuleFinding) RuleFinding {
	finding.enforcement = findingEnforcementDetectionOnly
	finding.Severity = "LOW"
	if finding.Confidence > 0.25 {
		finding.Confidence = 0.25
	}
	if !hasTag(finding.Tags, trustedParserUncertaintyTag) {
		finding.Tags = append(finding.Tags, trustedParserUncertaintyTag)
	}
	return finding
}

const trustedParserUncertaintyRuleID = "ACTION-PARSER-UNCERTAINTY"

func trustedParserUncertaintyFinding(catalogMatch bool) RuleFinding {
	title := "Shell action could not be fully projected"
	if catalogMatch {
		title = "Shell action matched only under parser uncertainty"
	}
	return RuleFinding{
		RuleID:      trustedParserUncertaintyRuleID,
		Title:       title,
		Severity:    "LOW",
		Confidence:  0.2,
		Tags:        []string{trustedParserUncertaintyTag},
		enforcement: findingEnforcementDetectionOnly,
	}
}

func trustedTypedLegacyActionRuleMatches(
	generation *compiledRulePackCategories,
	input actionfacts.Input,
	toolName string,
	facts actionfacts.Facts,
) map[string]struct{} {
	matches := make(map[string]struct{})
	merge := func(candidate actionfacts.Input, candidateFacts actionfacts.Facts) {
		for ruleID := range trustedLegacyCommandRuleMatches(
			generation,
			candidate,
			toolName,
			candidateFacts,
		) {
			matches[ruleID] = struct{}{}
		}
		paths, mutations := trustedLegacyPathRuleMatches(
			generation,
			candidate,
			toolName,
			candidateFacts,
		)
		for ruleID := range paths {
			matches[ruleID] = struct{}{}
		}
		for ruleID := range mutations {
			matches[ruleID] = struct{}{}
		}
		for ruleID := range trustedLegacyNetworkRuleMatches(
			generation,
			candidate,
			toolName,
			candidateFacts,
		) {
			matches[ruleID] = struct{}{}
		}
	}
	if facts.Authoritative() {
		merge(input, facts)
	}
	for _, nested := range trustedNestedExecutionActions(input, facts) {
		if !nested.rawFallback {
			merge(nested.input, nested.facts)
		}
	}
	return matches
}

// trustedPipelineFallbackProof authorizes only compatibility rules whose
// literal match is bound to the same typed pipeline that proves the underlying
// action. It intentionally does not turn arbitrary pipeline text into command
// proof.
func trustedPipelineFallbackProof(
	ruleID string,
	pipelineID int64,
	facts actionfacts.Facts,
) bool {
	if ruleID != "exfil.secret_read_and_egress_oneliner" || pipelineID == 0 {
		return false
	}
	for _, source := range facts.Commands {
		if source.PipelineID != pipelineID ||
			!hasAnyOperation(
				source,
				actionfacts.OperationRead,
				actionfacts.OperationCredentialRead,
			) ||
			!hasReadPathFact(facts, source.ID) ||
			!hasDataFlowFrom(
				facts,
				source.ID,
				actionfacts.DataStdout,
				actionfacts.DataStdin,
			) {
			continue
		}
		for _, destination := range facts.Commands {
			if destination.PipelineID == pipelineID &&
				hasOperation(destination, actionfacts.OperationUpload) &&
				hasExternalUpload(facts, destination.ID) &&
				hasDataFlowTo(
					facts,
					destination.ID,
					actionfacts.DataStdout,
					actionfacts.DataStdin,
				) &&
				hasDataFlowFrom(
					facts,
					destination.ID,
					"",
					actionfacts.DataNetwork,
				) {
				return true
			}
		}
	}
	return false
}

func hasReadPathFact(facts actionfacts.Facts, commandID int64) bool {
	for _, candidate := range facts.Paths {
		if candidate.CommandID == commandID &&
			candidate.Access == actionfacts.PathAccessRead {
			return true
		}
	}
	return false
}

func trustedRuleHasActionProof(
	ruleID string,
	input actionfacts.Input,
	facts actionfacts.Facts,
) bool {
	if contract, ok := exactFallbackContracts[ruleID]; ok &&
		contract.proves != nil && contract.proves(input, facts) {
		return true
	}
	owner, ok := semanticOwners[ruleID]
	return ok && owner.prerequisite != nil && owner.prerequisite(facts)
}

func collectTrustedLegacyCommandMatches(
	generation *compiledRulePackCategories,
	text string,
	toolName string,
	matchesByID map[string]struct{},
) {
	for _, match := range scanRuleGeneration(
		generation,
		text,
		toolName,
		ruleScanOptions{
			includeToolCallOnly: true,
			excludeTrustExploit: true,
		},
	) {
		if trustedLegacyRuleCategory(generation, match.RuleID) == "command" ||
			strings.HasPrefix(match.RuleID, "CMD-") {
			matchesByID[match.RuleID] = struct{}{}
		}
	}
}

func trustedCommandLiteralCarrier(command actionfacts.CommandFact) bool {
	program := strings.ToLower(strings.TrimSpace(command.Program))
	switch program {
	case "rg", "ripgrep", "find", "fd", "awk", "sed", "grep", "echo",
		"printf", "logger", "cat", "head", "tail":
		return true
	default:
		return false
	}
}

func trustedEmbeddedCommandTexts(command actionfacts.CommandFact) []string {
	if !strings.EqualFold(strings.TrimSpace(command.Program), "sed") {
		return nil
	}
	var embedded []string
	for _, argument := range trustedSedProgramTexts(command.Argv) {
		for _, statement := range trustedSedStatements(argument) {
			statement = stripSedAddresses(statement)
			switch {
			case strings.HasPrefix(statement, "e "):
				embedded = append(embedded, strings.TrimSpace(statement[1:]))
			case strings.HasPrefix(statement, "e\t"):
				embedded = append(embedded, strings.TrimSpace(statement[1:]))
			default:
				if replacement, ok := sedSubstitutionExecutionText(statement); ok {
					embedded = append(embedded, replacement)
				}
			}
		}
	}
	return embedded
}

func trustedSedProgramTexts(argv []string) []string {
	var (
		programs   []string
		hasProgram bool
	)
	for index := 1; index < len(argv); index++ {
		argument := argv[index]
		switch argument {
		case "-e", "--expression":
			if index+1 < len(argv) {
				programs = append(programs, argv[index+1])
				hasProgram = true
				index++
			}
		case "-f", "--file":
			if index+1 < len(argv) {
				hasProgram = true
				index++
			}
		case "--":
			if !hasProgram && index+1 < len(argv) {
				programs = append(programs, argv[index+1])
			}
			return programs
		default:
			switch {
			case strings.HasPrefix(argument, "--expression="):
				programs = append(
					programs,
					strings.TrimPrefix(argument, "--expression="),
				)
				hasProgram = true
			case strings.HasPrefix(argument, "--file="):
				hasProgram = true
			case strings.HasPrefix(argument, "-e") && len(argument) > 2:
				programs = append(programs, argument[2:])
				hasProgram = true
			case strings.HasPrefix(argument, "-"):
				continue
			case !hasProgram:
				programs = append(programs, argument)
				return programs
			default:
				return programs
			}
		}
	}
	return programs
}

func trustedSedStatements(program string) []string {
	var statements []string
	for offset := 0; offset < len(program); {
		for offset < len(program) &&
			(program[offset] == ';' || program[offset] == '\n' ||
				program[offset] == '\r' || program[offset] == ' ' ||
				program[offset] == '\t') {
			offset++
		}
		if offset >= len(program) {
			break
		}
		start := offset
		commandIndex := trustedSedCommandIndex(program, start)
		if commandIndex < 0 {
			break
		}
		end := commandIndex + 1
		switch program[commandIndex] {
		case 's', 'y':
			if commandIndex+1 >= len(program) {
				end = trustedSedLineEnd(program, end)
				break
			}
			delimiter := program[commandIndex+1]
			first := findUnescapedByte(program, delimiter, commandIndex+2)
			if first < 0 {
				end = trustedSedLineEnd(program, commandIndex+2)
				break
			}
			second := findUnescapedByte(program, delimiter, first+1)
			if second < 0 {
				end = trustedSedLineEnd(program, first+1)
				break
			}
			end = trustedSedSeparator(program, second+1)
		case 'e', 'a', 'i', 'c', '#':
			// These commands consume command/text material through the end of
			// the sed source line. A semicolon inside that material is not
			// evidence of a second sed command.
			end = trustedSedLineEnd(program, end)
		default:
			end = trustedSedSeparator(program, end)
		}
		if statement := strings.TrimSpace(program[start:end]); statement != "" {
			statements = append(statements, statement)
		}
		offset = end
		if offset < len(program) {
			offset++
		}
	}
	return statements
}

func trustedSedCommandIndex(program string, start int) int {
	index := start
	for address := 0; address < 2; address++ {
		for index < len(program) && (program[index] == ' ' || program[index] == '\t') {
			index++
		}
		if index >= len(program) {
			return -1
		}
		switch {
		case program[index] == '/':
			end := findUnescapedByte(program, '/', index+1)
			if end < 0 {
				return -1
			}
			index = end + 1
		case program[index] == '$':
			index++
		case program[index] >= '0' && program[index] <= '9':
			for index < len(program) && program[index] >= '0' && program[index] <= '9' {
				index++
			}
		default:
			if program[index] == '!' {
				index++
				for index < len(program) &&
					(program[index] == ' ' || program[index] == '\t') {
					index++
				}
			}
			if index >= len(program) {
				return -1
			}
			return index
		}
		for index < len(program) && (program[index] == ' ' || program[index] == '\t') {
			index++
		}
		if index >= len(program) || program[index] != ',' {
			break
		}
		index++
	}
	for index < len(program) && (program[index] == ' ' || program[index] == '\t') {
		index++
	}
	if index < len(program) && program[index] == '!' {
		index++
		for index < len(program) && (program[index] == ' ' || program[index] == '\t') {
			index++
		}
	}
	if index >= len(program) {
		return -1
	}
	return index
}

func trustedSedSeparator(program string, start int) int {
	for index := start; index < len(program); index++ {
		if program[index] == ';' || program[index] == '\n' || program[index] == '\r' {
			return index
		}
	}
	return len(program)
}

func trustedSedLineEnd(program string, start int) int {
	for index := start; index < len(program); index++ {
		if program[index] == '\n' || program[index] == '\r' {
			return index
		}
	}
	return len(program)
}

func restoreTrustedEmbeddedCommandFallbacks(
	excluded map[string]struct{},
	generation *compiledRulePackCategories,
	toolName string,
	facts actionfacts.Facts,
) {
	for _, command := range facts.Commands {
		if command.Effect != actionfacts.EffectExecute {
			continue
		}
		for _, embedded := range trustedEmbeddedCommandTexts(command) {
			matches := make(map[string]struct{})
			collectTrustedLegacyCommandMatches(
				generation,
				embedded,
				toolName,
				matches,
			)
			for ruleID := range matches {
				delete(excluded, ruleID)
			}
		}
	}
}

func appendTrustedEmbeddedCommandFindings(
	findings []RuleFinding,
	generation *compiledRulePackCategories,
	toolName string,
	facts actionfacts.Facts,
	options ruleScanOptions,
) []RuleFinding {
	seen := make(map[string]struct{}, len(findings))
	for _, finding := range findings {
		seen[finding.RuleID] = struct{}{}
	}
	for _, command := range facts.Commands {
		if command.Effect != actionfacts.EffectExecute {
			continue
		}
		for _, embedded := range trustedEmbeddedCommandTexts(command) {
			for _, finding := range scanRuleGeneration(
				generation,
				embedded,
				toolName,
				options,
			) {
				if trustedLegacyRuleCategory(generation, finding.RuleID) != "command" &&
					!strings.HasPrefix(finding.RuleID, "CMD-") {
					continue
				}
				if _, exists := seen[finding.RuleID]; exists {
					continue
				}
				seen[finding.RuleID] = struct{}{}
				findings = append(findings, finding)
			}
		}
	}
	return findings
}

func argvHasOption(argv []string, option string) bool {
	for _, argument := range argv[1:] {
		if argument == option || strings.HasPrefix(argument, option+"=") {
			return true
		}
	}
	return false
}

func argvHasAnyOption(argv []string, options ...string) bool {
	for _, option := range options {
		if argvHasOption(argv, option) {
			return true
		}
	}
	return false
}

func awkInvocationExecutes(argv []string) bool {
	for _, argument := range trustedAwkProgramTexts(argv) {
		argument = trustedStripAwkComments(argument)
		lower := strings.ToLower(argument)
		for {
			index := strings.Index(lower, "system")
			if index < 0 {
				break
			}
			after := strings.TrimLeft(lower[index+len("system"):], " \t\r\n")
			if strings.HasPrefix(after, "(") {
				return true
			}
			lower = lower[index+len("system"):]
		}
		for index := 0; index < len(argument); index++ {
			if argument[index] != '|' {
				continue
			}
			previousPipe := index > 0 && argument[index-1] == '|'
			nextPipe := index+1 < len(argument) && argument[index+1] == '|'
			if !previousPipe && !nextPipe {
				// awk uses a single pipe for both command-to-getline and
				// print-to-command forms. Treat regex alternation conservatively
				// as executable rather than hiding a nested command.
				return true
			}
		}
	}
	return false
}

func trustedStripAwkComments(program string) string {
	var projected strings.Builder
	projected.Grow(len(program))
	var (
		quoted        bool
		regexLiteral  bool
		escaped       bool
		expectOperand = true
	)
	for index := 0; index < len(program); index++ {
		current := program[index]
		if regexLiteral {
			projected.WriteByte(' ')
			if escaped {
				escaped = false
				continue
			}
			if current == '\\' {
				escaped = true
				continue
			}
			if current == '/' {
				regexLiteral = false
				expectOperand = false
			}
			continue
		}
		if escaped {
			projected.WriteByte(current)
			escaped = false
			continue
		}
		if current == '\\' {
			projected.WriteByte(current)
			escaped = true
			continue
		}
		if current == '"' {
			quoted = !quoted
			projected.WriteByte(current)
			if !quoted {
				expectOperand = false
			}
			continue
		}
		if current == '#' && !quoted {
			for index < len(program) && program[index] != '\n' {
				projected.WriteByte(' ')
				index++
			}
			if index < len(program) {
				projected.WriteByte('\n')
			}
			expectOperand = true
			continue
		}
		if !quoted && trustedAwkIdentifierStart(current) {
			end := index + 1
			for end < len(program) && trustedAwkIdentifierContinue(program[end]) {
				end++
			}
			token := program[index:end]
			projected.WriteString(token)
			switch strings.ToLower(token) {
			case "return", "print", "printf", "delete", "exit", "nextfile":
				expectOperand = true
			default:
				expectOperand = false
			}
			index = end - 1
			continue
		}
		if !quoted && current >= '0' && current <= '9' {
			projected.WriteByte(current)
			expectOperand = false
			continue
		}
		if !quoted && current == '/' {
			if expectOperand {
				regexLiteral = true
				projected.WriteByte(' ')
			} else {
				projected.WriteByte(current)
				expectOperand = true
			}
			continue
		}
		projected.WriteByte(current)
		if !quoted {
			switch current {
			case '\n', ';', '{', '(', '[', ',', '=', '~', '!', '?', ':',
				'&', '|', '+', '-', '*', '%', '^', '<', '>':
				expectOperand = true
			case ')', ']', '}':
				expectOperand = false
			}
		}
	}
	return projected.String()
}

func trustedAwkIdentifierStart(character byte) bool {
	return character == '_' || character >= 'a' && character <= 'z' ||
		character >= 'A' && character <= 'Z'
}

func trustedAwkIdentifierContinue(character byte) bool {
	return trustedAwkIdentifierStart(character) ||
		character >= '0' && character <= '9'
}

func sedInvocationExecutes(argv []string) bool {
	for _, argument := range trustedSedProgramTexts(argv) {
		for _, statement := range trustedSedStatements(argument) {
			statement = stripSedAddresses(statement)
			if statement == "e" || strings.HasPrefix(statement, "e ") ||
				strings.HasPrefix(statement, "e\t") ||
				sedSubstitutionExecutes(statement) {
				return true
			}
		}
	}
	return false
}

func stripSedAddresses(statement string) string {
	statement = strings.TrimSpace(statement)
	for address := 0; address < 2; address++ {
		statement = strings.TrimSpace(statement)
		if statement == "" {
			return statement
		}
		switch {
		case statement[0] == '/':
			end := findUnescapedByte(statement, '/', 1)
			if end < 0 {
				return statement
			}
			statement = statement[end+1:]
		case statement[0] == '$':
			statement = statement[1:]
		case statement[0] >= '0' && statement[0] <= '9':
			index := 0
			for index < len(statement) &&
				statement[index] >= '0' && statement[index] <= '9' {
				index++
			}
			statement = statement[index:]
		default:
			return strings.TrimSpace(statement)
		}
		statement = strings.TrimSpace(statement)
		if !strings.HasPrefix(statement, ",") {
			return statement
		}
		statement = statement[1:]
	}
	return strings.TrimSpace(statement)
}

func sedSubstitutionExecutes(statement string) bool {
	_, executes := sedSubstitutionExecutionText(statement)
	return executes
}

func sedSubstitutionExecutionText(statement string) (string, bool) {
	statement = strings.TrimSpace(statement)
	if len(statement) < 4 || statement[0] != 's' {
		return "", false
	}
	delimiter := statement[1]
	first := findUnescapedByte(statement, delimiter, 2)
	if first < 0 {
		return "", false
	}
	second := findUnescapedByte(statement, delimiter, first+1)
	if second < 0 {
		return "", false
	}
	flags := strings.Fields(statement[second+1:])
	if len(flags) == 0 || !strings.Contains(flags[0], "e") {
		return "", false
	}
	return strings.TrimSpace(statement[first+1 : second]), true
}

func findUnescapedByte(value string, target byte, start int) int {
	escaped := false
	for index := start; index < len(value); index++ {
		if escaped {
			escaped = false
			continue
		}
		if value[index] == '\\' {
			escaped = true
			continue
		}
		if value[index] == target {
			return index
		}
	}
	return -1
}

func trustedLegacyNetworkRuleMatches(
	generation *compiledRulePackCategories,
	input actionfacts.Input,
	toolName string,
	facts actionfacts.Facts,
) map[string]struct{} {
	matchesByID := make(map[string]struct{})
	commands := make(map[int64]actionfacts.CommandFact, len(facts.Commands))
	for _, command := range facts.Commands {
		commands[command.ID] = command
	}
	for _, network := range facts.Network {
		values := []string{network.Host, network.NormalizedHost}
		if network.Scheme != "" && network.Host != "" {
			values = append(values, network.Scheme+"://"+network.Host)
		}
		if command, ok := commands[network.CommandID]; ok &&
			command.Effect == actionfacts.EffectExecute &&
			!trustedCommandLiteralCarrier(command) {
			values = append(values, serializeArgvForLegacyScan(command.Argv))
		}
		seenValues := make(map[string]struct{}, len(values))
		for _, value := range values {
			if strings.TrimSpace(value) == "" {
				continue
			}
			if _, seen := seenValues[value]; seen {
				continue
			}
			seenValues[value] = struct{}{}
			for _, match := range scanRuleGeneration(
				generation,
				value,
				toolName,
				ruleScanOptions{
					includeToolCallOnly: true,
					excludeTrustExploit: true,
				},
			) {
				if trustedLegacyRuleCategory(generation, match.RuleID) == "c2" ||
					strings.HasPrefix(match.RuleID, "C2-") {
					matchesByID[match.RuleID] = struct{}{}
				}
			}
		}
	}
	for ruleID, contract := range exactFallbackContracts {
		if strings.HasPrefix(ruleID, "C2-") &&
			contract.proves != nil && contract.proves(input, facts) {
			matchesByID[ruleID] = struct{}{}
		}
	}
	for _, nested := range trustedNestedExecutionActions(input, facts) {
		if nested.rawFallback {
			continue
		}
		for ruleID := range trustedLegacyNetworkRuleMatches(
			generation,
			nested.input,
			toolName,
			nested.facts,
		) {
			matchesByID[ruleID] = struct{}{}
		}
	}
	return matchesByID
}

func trustedLegacyPathRuleMatches(
	generation *compiledRulePackCategories,
	input actionfacts.Input,
	toolName string,
	facts actionfacts.Facts,
) (map[string]struct{}, map[string]struct{}) {
	pathMatches := make(map[string]struct{})
	mutationMatches := make(map[string]struct{})
	for _, path := range facts.Paths {
		mutation := path.Access == actionfacts.PathAccessWrite ||
			path.Access == actionfacts.PathAccessAppend ||
			path.Access == actionfacts.PathAccessDelete
		seenValues := make(map[string]struct{}, 3)
		for _, value := range []string{path.Value, path.Normalized, path.Resolved} {
			if strings.TrimSpace(value) == "" {
				continue
			}
			if _, seen := seenValues[value]; seen {
				continue
			}
			seenValues[value] = struct{}{}
			for _, match := range windowsSensitivePathFindingsWithOptions(
				value,
				toolName,
				true,
				ruleScanOptions{includeToolCallOnly: true},
			) {
				pathMatches[match.RuleID] = struct{}{}
			}
			matches := scanRuleGeneration(
				generation,
				value,
				toolName,
				ruleScanOptions{
					includeToolCallOnly: true,
					excludeTrustExploit: true,
				},
			)
			for _, match := range matches {
				if match.RuleID == "persistence.shell_profile_write" &&
					path.Flavor == actionfacts.PathFlavorWindows &&
					looksLikeSystemShellProfilePath(value) {
					// A leading slash in CMD is rooted on the current Windows
					// drive, not the POSIX system profile. Keep the legacy
					// regex fallback from discarding the typed path flavor.
					continue
				}
				category := trustedLegacyRuleCategory(generation, match.RuleID)
				if category == "sensitive-path" ||
					strings.HasPrefix(match.RuleID, "PATH-") {
					pathMatches[match.RuleID] = struct{}{}
				}
				if mutation && (category == "cognitive-file" ||
					strings.HasPrefix(match.RuleID, "COG-")) {
					mutationMatches[match.RuleID] = struct{}{}
				}
			}
		}
	}
	// Well-known PowerShell environment roots remain statically meaningful even
	// though ActionFacts conservatively marks the expanded path uncertain and
	// therefore emits no PathFact. Require both a typed, path-reading Windows
	// command and a matching structured ArgumentFact; arbitrary/search text can
	// never enter this compatibility exception.
	for _, command := range facts.Commands {
		if !windowsCommandCanReadSensitivePath(command.Program) ||
			(command.Effect != actionfacts.EffectExecute &&
				command.Effect != actionfacts.EffectUncertain) {
			continue
		}
		for _, argument := range trustedCommandOperandArguments(command) {
			for _, match := range windowsSensitivePathFindingsWithOptions(
				argument.Value,
				toolName,
				true,
				ruleScanOptions{includeToolCallOnly: true},
			) {
				pathMatches[match.RuleID] = struct{}{}
			}
		}
	}
	// Tilde and similar shell-expanded operands can be deliberately omitted from
	// PathFacts while remaining a statically captured argument to a concrete
	// file-reading command. Preserve those narrow fallback paths without letting
	// echo/search arguments claim a read action.
	for _, command := range facts.Commands {
		if !trustedPathReadingCommand(command.Program) ||
			(command.Effect != actionfacts.EffectExecute &&
				command.Effect != actionfacts.EffectUncertain) {
			continue
		}
		for _, argument := range trustedCommandOperandArguments(command) {
			for _, match := range scanRuleGeneration(
				generation,
				argument.Value,
				toolName,
				ruleScanOptions{
					includeToolCallOnly: true,
					excludeTrustExploit: true,
				},
			) {
				if trustedLegacyRuleCategory(generation, match.RuleID) == "sensitive-path" {
					pathMatches[match.RuleID] = struct{}{}
				}
			}
		}
	}
	for ruleID := range trustedUnresolvedReadRuleMatches(
		generation,
		input,
		toolName,
		facts,
	) {
		pathMatches[ruleID] = struct{}{}
	}
	for _, nested := range trustedNestedExecutionActions(input, facts) {
		if nested.rawFallback {
			continue
		}
		nestedPaths, nestedMutations := trustedLegacyPathRuleMatches(
			generation,
			nested.input,
			toolName,
			nested.facts,
		)
		for ruleID := range nestedPaths {
			pathMatches[ruleID] = struct{}{}
		}
		for ruleID := range nestedMutations {
			mutationMatches[ruleID] = struct{}{}
		}
	}
	return pathMatches, mutationMatches
}

// restoreTrustedUnresolvedReadFallbacks keeps the legacy detector eligible for
// a concrete read of a shell-home path that ActionFacts deliberately cannot
// resolve. The exception is limited to typed file readers and a leading home
// expansion, so echo/search/patch literals cannot reopen the fallback lane.
func restoreTrustedUnresolvedReadFallbacks(
	excluded map[string]struct{},
	generation *compiledRulePackCategories,
	input actionfacts.Input,
	toolName string,
	facts actionfacts.Facts,
) {
	for ruleID := range trustedUnresolvedReadRuleMatches(
		generation,
		input,
		toolName,
		facts,
	) {
		delete(excluded, ruleID)
	}
}

func trustedUnresolvedReadRuleMatches(
	generation *compiledRulePackCategories,
	input actionfacts.Input,
	toolName string,
	facts actionfacts.Facts,
) map[string]struct{} {
	matchesByID := make(map[string]struct{})
	collect := func(value string) {
		if !trustedUnresolvedHomePath(value) {
			return
		}
		for _, match := range scanRuleGeneration(
			generation,
			value,
			toolName,
			ruleScanOptions{
				includeToolCallOnly: true,
				excludeTrustExploit: true,
			},
		) {
			if trustedLegacyRuleCategory(generation, match.RuleID) == "sensitive-path" {
				matchesByID[match.RuleID] = struct{}{}
			}
		}
	}
	for _, command := range facts.Commands {
		if !trustedPathReadingCommand(command.Program) ||
			(command.Effect != actionfacts.EffectExecute &&
				command.Effect != actionfacts.EffectUncertain) {
			continue
		}
		for _, argument := range trustedCommandOperandArguments(command) {
			collect(argument.Value)
		}
		if command.ArgvComplete || !commandHasUnresolvedExpansion(command) {
			continue
		}
		for _, field := range strings.Fields(input.Command) {
			collect(strings.Trim(field, `"'`))
		}
	}
	return matchesByID
}

func commandHasUnresolvedExpansion(command actionfacts.CommandFact) bool {
	for _, argument := range trustedCommandOperandArguments(command) {
		if argument.Expands && strings.TrimSpace(argument.Value) == "" {
			return true
		}
	}
	return false
}

func trustedCommandOperandArguments(command actionfacts.CommandFact) []actionfacts.ArgumentFact {
	if len(command.Arguments) <= 1 {
		return nil
	}
	return command.Arguments[1:]
}

func trustedUnresolvedHomePath(value string) bool {
	value = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), `\`, "/"))
	return strings.HasPrefix(value, "~/") ||
		strings.HasPrefix(value, "$home/") ||
		strings.HasPrefix(value, "${home}/")
}

func trustedPathReadingCommand(program string) bool {
	switch strings.ToLower(strings.TrimSpace(program)) {
	case "cat", "type", "get-content", "gc", "more":
		return true
	default:
		return false
	}
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
