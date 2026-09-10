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

import (
	"net"
	"net/url"
	"path"
	"strings"
)

// ProvesRemotePayloadExecuteCleanup reports whether one unconditional,
// top-level POSIX command subgraph proves all of these ordered stages for the
// same literal artifact:
//
//   - wget fetches it from a literal IPv4 HTTP(S) URL;
//   - chmod makes that artifact executable;
//   - sh/bash or direct relative execution launches it; and
//   - rm -rf uses one static glob that covers it.
//
// The surrounding action may be partial because unrelated directory fallback
// (`cd a || cd b`) and the final glob cannot be represented as complete argv.
// Conditional/pipelined/background commands, wrappers, redirects, dynamic
// words, option-bearing wget forms, and cross-artifact joins are rejected.
func ProvesRemotePayloadExecuteCleanup(facts Facts) bool {
	if facts.Parse.Dialect != DialectPOSIX || len(facts.Commands) < 4 {
		return false
	}
	for index, download := range facts.Commands {
		artifact, ok := exactWgetArtifact(download, facts.Network)
		if !ok {
			continue
		}
		chmodIndex := findArtifactChmod(facts.Commands, facts.Network, index+1, artifact)
		if chmodIndex < 0 {
			continue
		}
		execIndex := findArtifactExecution(facts.Commands, chmodIndex+1, artifact)
		if execIndex < 0 {
			continue
		}
		if findArtifactCleanup(facts.Commands, execIndex+1, artifact) >= 0 {
			return true
		}
	}
	return false
}

// StaticRemoteIPDownloadExecuteSameArtifact reports a bounded, static intent
// to download one file from a literal public IP and later execute that exact
// absolute path in the same POSIX action. The result is deliberately a
// detection proof, not an enforcement proof: &&, ||, and other shell control
// flow can make execution conditional, and the pre-execution hook cannot know
// the command outcome yet.
//
// The closed grammar rejects hostnames (ordinary installers commonly use
// those), multiple network sources, multiple downloaded files, pipelines,
// wrappers, dynamic argv, cross-artifact execution, and any intervening write,
// append, or delete of the downloaded path. Harmless /dev/null redirects on
// the interpreter are permitted.
func StaticRemoteIPDownloadExecuteSameArtifact(facts Facts) bool {
	if facts.Parse.Dialect != DialectPOSIX || len(facts.Commands) < 2 {
		return false
	}
	for sourceIndex, source := range facts.Commands {
		artifact, ok := staticRemoteIPDownloadPath(facts, source)
		if !ok {
			continue
		}
		limit := sourceIndex + 1 + staticRemoteArtifactMaxCommands
		if limit > len(facts.Commands) {
			limit = len(facts.Commands)
		}
		for destinationIndex := sourceIndex + 1; destinationIndex < limit; destinationIndex++ {
			destination := facts.Commands[destinationIndex]
			if commandMutatesResolvedPath(facts, destination.ID, artifact.Resolved) {
				break
			}
			if staticCommandExecutesPath(facts, destination, artifact.Resolved) {
				return true
			}
		}
	}
	return false
}

// staticRemoteArtifactMaxCommands keeps this same-action proof aligned with
// the public bounded-chain horizon without importing the guardrail package
// (which would create a dependency cycle).
const staticRemoteArtifactMaxCommands = 8

func staticRemoteIPDownloadPath(facts Facts, command CommandFact) (PathFact, bool) {
	if !staticTopLevelProcess(command) || !onlyNullOutputRedirects(command.Redirects) ||
		(command.Program != "curl" && command.Program != "wget") ||
		!hasFactOperation(command, OperationFetch) {
		return PathFact{}, false
	}
	networkCount := 0
	for _, candidate := range facts.Network {
		if candidate.CommandID != command.ID || candidate.Action != NetworkDownload {
			continue
		}
		if candidate.Scope != NetworkScopePublic ||
			candidate.TargetKind != NetworkTargetSingleHost ||
			net.ParseIP(strings.Trim(candidate.NormalizedHost, "[]")) == nil {
			return PathFact{}, false
		}
		networkCount++
	}
	if networkCount != 1 {
		return PathFact{}, false
	}
	var artifact PathFact
	pathCount := 0
	for _, candidate := range facts.Paths {
		if candidate.CommandID != command.ID || candidate.Access != PathAccessWrite ||
			candidate.Flavor == PathFlavorDevice {
			continue
		}
		if !candidate.Absolute || candidate.Resolved == "" {
			return PathFact{}, false
		}
		artifact = candidate
		pathCount++
	}
	return artifact, pathCount == 1
}

func staticCommandExecutesPath(facts Facts, command CommandFact, resolved string) bool {
	if !staticTopLevelProcessShape(command) ||
		!onlyNullOutputRedirects(command.Redirects) ||
		!hasFactOperation(command, OperationExecute) {
		return false
	}
	interpreter := command.Effect == EffectExecute &&
		(command.Program == "sh" || command.Program == "bash")
	direct := (command.Effect == EffectExecute || command.Effect == EffectUncertain) &&
		command.Executable == resolved
	if !interpreter && !direct {
		return false
	}
	count := 0
	for _, candidate := range facts.Paths {
		if candidate.CommandID != command.ID || candidate.Access != PathAccessExecute {
			continue
		}
		if !candidate.Absolute || candidate.Resolved != resolved {
			return false
		}
		count++
	}
	return count == 1
}

func staticTopLevelProcess(command CommandFact) bool {
	return staticTopLevelProcessShape(command) && command.Effect == EffectExecute
}

func staticTopLevelProcessShape(command CommandFact) bool {
	return command.ParentCommandID == 0 && command.PipelineID == 0 &&
		command.Kind == CommandKindProcess && command.ArgvComplete &&
		len(command.Wrappers) == 0
}

func onlyNullOutputRedirects(redirects []RedirectFact) bool {
	for _, redirect := range redirects {
		if redirect.Expands || redirect.Target != "/dev/null" ||
			(redirect.Access != PathAccessWrite && redirect.Access != PathAccessAppend) {
			return false
		}
	}
	return true
}

func commandMutatesResolvedPath(facts Facts, commandID int64, resolved string) bool {
	for _, candidate := range facts.Paths {
		if candidate.CommandID != commandID || candidate.Resolved != resolved {
			continue
		}
		switch candidate.Access {
		case PathAccessWrite, PathAccessAppend, PathAccessDelete:
			return true
		}
	}
	return false
}

// ExactRemoteArtifactDownload returns the single exact local file written by
// one complete, unconditional download from a literal public IP. Requiring a
// literal address keeps this universal chain proof out of ordinary package and
// installer traffic that uses named repositories.
func ExactRemoteArtifactDownload(facts Facts) (PathFact, bool) {
	command, ok := exactSingleArtifactCommand(facts, OperationFetch)
	if !ok {
		return PathFact{}, false
	}
	networkCount := 0
	for _, candidate := range facts.Network {
		if candidate.CommandID != command.ID || candidate.Action != NetworkDownload {
			continue
		}
		if candidate.Scope != NetworkScopePublic ||
			candidate.TargetKind != NetworkTargetSingleHost ||
			net.ParseIP(strings.Trim(candidate.NormalizedHost, "[]")) == nil {
			return PathFact{}, false
		}
		networkCount++
	}
	if networkCount != 1 {
		return PathFact{}, false
	}
	return exactSingleCommandPath(facts, command.ID, PathAccessWrite)
}

// ExactRemoteArtifactDownloadIntent returns one exact literal-public-IP
// download from an unconditional top-level command inside a larger action.
// Unlike ExactRemoteArtifactDownload, this detection-only helper permits
// unrelated sibling commands. It rejects multiple candidate downloads and
// any sibling write, append, move, or delete of the downloaded path because
// those operations break artifact identity before a later chain join.
func ExactRemoteArtifactDownloadIntent(facts Facts) (PathFact, bool) {
	return remoteArtifactDownloadIntent(facts, false)
}

// BoundedRemoteArtifactDownloadIntent returns the exact artifact path named by
// one literal-public-IP curl/wget candidate even when shell short-circuiting
// makes reachability uncertain. It is detection-only evidence: callers must
// join it to a later exact use of the same path and must never authorize a
// synchronous deny from this fact alone.
func BoundedRemoteArtifactDownloadIntent(facts Facts) (PathFact, bool) {
	return remoteArtifactDownloadIntent(facts, true)
}

func remoteArtifactDownloadIntent(facts Facts, allowUncertainControlFlow bool) (PathFact, bool) {
	if facts.Parse.Dialect != DialectPOSIX {
		return PathFact{}, false
	}
	var selected PathFact
	selectedCommandID := int64(0)
	count := 0
	for _, command := range facts.Commands {
		if command.ControlFlowUncertain && !allowUncertainControlFlow {
			continue
		}
		artifact, ok := staticRemoteIPDownloadPath(facts, command)
		if !ok {
			continue
		}
		selected = artifact
		selectedCommandID = command.ID
		count++
	}
	if count != 1 {
		return PathFact{}, false
	}
	for _, command := range facts.Commands {
		if command.ID == selectedCommandID {
			continue
		}
		if commandMutatesResolvedPath(facts, command.ID, selected.Resolved) {
			return PathFact{}, false
		}
	}
	return selected, true
}

// ExactArtifactDecodeTransition returns the exact input and output of one
// complete byte-to-byte decoder. It deliberately does not infer archive member
// names from tar, zip, package, or destination-directory arguments.
func ExactArtifactDecodeTransition(facts Facts) (PathFact, PathFact, bool) {
	command, ok := exactSingleArtifactCommand(facts, OperationDecode)
	if !ok {
		return PathFact{}, PathFact{}, false
	}
	input, inputOK := exactSingleCommandPath(facts, command.ID, PathAccessRead)
	output, outputOK := exactSingleCommandPath(facts, command.ID, PathAccessWrite)
	if !inputOK || !outputOK || input.Resolved == output.Resolved ||
		!hasExactFileProcessFileFlow(facts, command.ID) {
		return PathFact{}, PathFact{}, false
	}
	return input, output, true
}

// ExactArtifactExecution returns the exact local artifact consumed by one
// complete, unconditional execution action. Generic shell script execution is
// intentionally partial because the script bytes are opaque; a connector must
// provide a stable execute-file tool schema for enforcement authority.
func ExactArtifactExecution(facts Facts) (PathFact, bool) {
	command, ok := exactSingleArtifactCommand(facts, OperationExecute)
	if !ok {
		return PathFact{}, false
	}
	return exactSingleCommandPath(facts, command.ID, PathAccessExecute)
}

// ExactArtifactExecutionIntent returns the single exact local artifact named
// by one unconditional execution action. Unlike ExactArtifactExecution, this
// detection-only helper may accept an otherwise unsupported POSIX executable:
// the parser can still prove the command shape and normalized path even when
// it cannot assign enforcement authority to the program itself.
//
// Dynamic argv, wrappers, pipelines, redirects, shell control flow, multiple
// executable candidates, and same-action replacement of the artifact are
// rejected. Unrelated sibling commands are permitted. The caller must not use
// this intent proof to authorize enforcement.
func ExactArtifactExecutionIntent(facts Facts) (PathFact, bool) {
	if exact, ok := ExactArtifactExecution(facts); ok {
		return exact, true
	}
	if facts.Parse.Dialect != DialectPOSIX {
		return PathFact{}, false
	}
	var selected PathFact
	selectedCommandID := int64(0)
	count := 0
	for _, command := range facts.Commands {
		if command.ControlFlowUncertain || !staticTopLevelProcessShape(command) ||
			len(command.Redirects) != 0 || !hasFactOperation(command, OperationExecute) {
			continue
		}
		executed, ok := exactSingleResolvedCommandPath(facts, command.ID, PathAccessExecute)
		if !ok {
			continue
		}
		interpreter := command.Effect == EffectExecute &&
			(command.Program == "sh" || command.Program == "bash") &&
			len(command.Argv) == 2 && command.Argv[1] == executed.Value
		direct := (command.Effect == EffectExecute || command.Effect == EffectUncertain) &&
			command.Executable == executed.Value && len(command.Argv) >= 1
		if !interpreter && !direct {
			continue
		}
		selected = executed
		selectedCommandID = command.ID
		count++
	}
	if count != 1 {
		return PathFact{}, false
	}
	for _, command := range facts.Commands {
		if command.ID == selectedCommandID {
			continue
		}
		if commandMutatesResolvedPath(facts, command.ID, selected.Resolved) {
			return PathFact{}, false
		}
	}
	return selected, true
}

// BoundedArtifactExecutionIntent returns one exact artifact consumed by a
// shell/interpreter action even when short-circuit or branch reachability is
// unresolved. POSIX source/dot commands are included because they execute the
// referenced bytes in the current shell. This is detection-only evidence and
// remains subject to an exact path join and the cross-event mutation barrier.
func BoundedArtifactExecutionIntent(facts Facts) (PathFact, bool) {
	if exact, ok := ExactArtifactExecutionIntent(facts); ok {
		return exact, true
	}
	if facts.Parse.Dialect != DialectPOSIX {
		return PathFact{}, false
	}
	var selected PathFact
	selectedCommandID := int64(0)
	count := 0
	for _, command := range facts.Commands {
		if !staticTopLevelProcessShape(command) ||
			!onlyNullOutputRedirects(command.Redirects) {
			continue
		}
		var executed PathFact
		var ok bool
		program := command.Program
		if program == "" {
			program = command.Executable
		}
		switch program {
		case "sh", "bash":
			if command.Effect != EffectExecute || len(command.Argv) != 2 ||
				!hasFactOperation(command, OperationExecute) {
				continue
			}
			executed, ok = exactSingleResolvedCommandPath(
				facts, command.ID, PathAccessExecute,
			)
		case "source", ".":
			if (command.Effect != EffectExecute && command.Effect != EffectUncertain) ||
				len(command.Argv) != 2 || !hasFactOperation(command, OperationExecute) {
				continue
			}
			executed, ok = exactLiteralArgumentPath(facts, command, 1)
		default:
			if command.Effect != EffectExecute && command.Effect != EffectUncertain ||
				command.Executable == "" || len(command.Argv) < 1 ||
				!hasFactOperation(command, OperationExecute) {
				continue
			}
			executed, ok = exactSingleResolvedCommandPath(
				facts, command.ID, PathAccessExecute,
			)
		}
		if !ok || program != "source" && program != "." &&
			program != "sh" && program != "bash" &&
			command.Executable != executed.Value &&
			command.Executable != executed.Resolved {
			continue
		}
		selected = executed
		selectedCommandID = command.ID
		count++
	}
	if count != 1 {
		return PathFact{}, false
	}
	for _, command := range facts.Commands {
		if command.ID != selectedCommandID &&
			commandMutatesResolvedPath(facts, command.ID, selected.Resolved) {
			return PathFact{}, false
		}
	}
	return selected, true
}

func exactLiteralArgumentPath(facts Facts, command CommandFact, index int) (PathFact, bool) {
	if index < 0 || index >= len(command.Arguments) {
		return PathFact{}, false
	}
	argument := command.Arguments[index]
	if argument.Value == "" || argument.Expands || argument.StaticGlob != "" {
		return PathFact{}, false
	}
	candidates := []PathFact{{
		CommandID: command.ID,
		Access:    PathAccessExecute,
		Flavor:    pathFlavor(argument.Value),
		Value:     argument.Value,
	}}
	normalizePathFactsForCommands(
		candidates,
		facts.CWD,
		facts.ActiveHome,
		[]CommandFact{command},
	)
	candidate := candidates[0]
	if candidate.Flavor != PathFlavorPOSIX || candidate.Resolved == "" ||
		!strings.HasPrefix(candidate.Resolved, "/") {
		return PathFact{}, false
	}
	return candidate, true
}

func exactSingleArtifactCommand(facts Facts, operation OperationKind) (CommandFact, bool) {
	if !facts.Authoritative() || !facts.EnforcementEligible() || len(facts.Commands) != 1 {
		return CommandFact{}, false
	}
	command := facts.Commands[0]
	if !exactUnconditionalTopLevelCommand(command) || !command.ArgvComplete ||
		!hasFactOperation(command, operation) {
		return CommandFact{}, false
	}
	return command, true
}

func exactSingleCommandPath(facts Facts, commandID int64, access PathAccess) (PathFact, bool) {
	var selected PathFact
	count := 0
	for _, candidate := range facts.Paths {
		if candidate.CommandID != commandID || candidate.Access != access {
			continue
		}
		if !candidate.Absolute || candidate.Resolved == "" {
			return PathFact{}, false
		}
		selected = candidate
		count++
	}
	return selected, count == 1
}

func exactSingleResolvedCommandPath(facts Facts, commandID int64, access PathAccess) (PathFact, bool) {
	var selected PathFact
	count := 0
	for _, candidate := range facts.Paths {
		if candidate.CommandID != commandID || candidate.Access != access {
			continue
		}
		if candidate.Resolved == "" || candidate.Flavor != PathFlavorPOSIX ||
			!strings.HasPrefix(candidate.Resolved, "/") {
			return PathFact{}, false
		}
		selected = candidate
		count++
	}
	return selected, count == 1
}

func hasExactFileProcessFileFlow(facts Facts, commandID int64) bool {
	readFlow := false
	writeFlow := false
	for _, flow := range facts.DataFlows {
		readFlow = readFlow || flow.ToCommandID == commandID &&
			flow.From == DataFile && flow.To == DataProcess
		writeFlow = writeFlow || flow.FromCommandID == commandID &&
			flow.From == DataProcess && flow.To == DataFile
	}
	return readFlow && writeFlow
}

func exactWgetArtifact(command CommandFact, network []NetworkFact) (string, bool) {
	if !exactUnconditionalTopLevelCommand(command) ||
		command.Program != "wget" || len(command.Argv) != 2 ||
		!command.ArgvComplete || !hasFactOperation(command, OperationFetch) {
		return "", false
	}
	artifact, host, ok := literalIPv4RemoteArtifact(command.Argv[1])
	if !ok {
		return "", false
	}
	return artifact, commandHasDownloadNetwork(command.ID, host, network)
}

func safeRemoteArtifactName(value string) bool {
	if value == "" || value == "." || value == ".." || strings.HasPrefix(value, ".") ||
		len(value) > 255 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func findArtifactChmod(
	commands []CommandFact,
	network []NetworkFact,
	start int,
	artifact string,
) int {
	for index := start; index < len(commands); index++ {
		command := commands[index]
		if exactArtifactChmod(command, artifact) {
			return index
		}
		// Do not search across arbitrary commands: they could replace the
		// downloaded file and break the artifact-lineage proof. Honeypot chains
		// commonly retry the same literal download through curl or BusyBox, so
		// accept only those two closed grammars for the exact same artifact.
		if exactRedundantArtifactDownload(command, network, artifact) {
			continue
		}
		return -1
	}
	return -1
}

func exactArtifactChmod(command CommandFact, artifact string) bool {
	return exactUnconditionalTopLevelCommand(command) && command.Program == "chmod" &&
		command.ArgvComplete && len(command.Argv) == 3 &&
		command.Argv[2] == artifact && executableChmodMode(command.Argv[1]) &&
		hasFactOperation(command, OperationPermissionChange)
}

func exactRedundantArtifactDownload(
	command CommandFact,
	network []NetworkFact,
	artifact string,
) bool {
	if command.ControlFlowUncertain || command.ParentCommandID != 0 ||
		command.PipelineID != 0 || command.Kind != CommandKindProcess ||
		command.Effect != EffectExecute || !command.ArgvComplete ||
		len(command.Redirects) != 0 {
		return false
	}
	var rawURL string
	switch {
	case command.Program == "curl" && len(command.Wrappers) == 0 &&
		len(command.Argv) == 3 && command.Argv[1] == "-O":
		rawURL = command.Argv[2]
	case command.Program == "busybox" && len(command.Wrappers) == 0 &&
		len(command.Argv) == 3 && command.Argv[1] == "wget":
		rawURL = command.Argv[2]
	default:
		return false
	}
	parsedArtifact, host, ok := literalIPv4RemoteArtifact(rawURL)
	if !ok || parsedArtifact != artifact {
		return false
	}
	if command.Program == "busybox" {
		// BusyBox applet projection is intentionally not inferred globally;
		// this exact argv is owned only by this bounded retry grammar.
		return true
	}
	return commandHasDownloadNetwork(command.ID, host, network) &&
		hasFactOperation(command, OperationFetch)
}

func executableChmodMode(mode string) bool {
	if mode == "+x" {
		return true
	}
	if len(mode) < 3 || len(mode) > 4 {
		return false
	}
	for _, character := range mode {
		if character < '0' || character > '7' {
			return false
		}
	}
	return strings.ContainsAny(mode[len(mode)-3:], "1357")
}

func findArtifactExecution(commands []CommandFact, start int, artifact string) int {
	if start >= len(commands) {
		return -1
	}
	command := commands[start]
	if !exactTopLevelCommandStructure(command) || !command.ArgvComplete ||
		len(command.Argv) == 0 {
		return -1
	}
	matches := (command.Program == "sh" || command.Program == "bash") &&
		command.Effect == EffectExecute && len(command.Argv) >= 2 &&
		command.Argv[1] == artifact
	matches = matches || (command.Effect == EffectExecute ||
		command.Effect == EffectUncertain) && command.Argv[0] == "./"+artifact
	if matches && hasFactOperation(command, OperationExecute) {
		return start
	}
	return -1
}

func literalIPv4RemoteArtifact(rawURL string) (string, string, bool) {
	target, err := url.Parse(rawURL)
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") ||
		target.Hostname() == "" || net.ParseIP(target.Hostname()) == nil ||
		target.RawQuery != "" || target.Fragment != "" || target.User != nil {
		return "", "", false
	}
	artifact, err := url.PathUnescape(path.Base(target.EscapedPath()))
	if err != nil || !safeRemoteArtifactName(artifact) {
		return "", "", false
	}
	return artifact, target.Hostname(), true
}

func commandHasDownloadNetwork(commandID int64, host string, network []NetworkFact) bool {
	for _, fact := range network {
		if fact.CommandID == commandID && fact.Action == NetworkDownload && fact.Host == host {
			return true
		}
	}
	return false
}

func findArtifactCleanup(commands []CommandFact, start int, artifact string) int {
	for index := start; index < len(commands); index++ {
		command := commands[index]
		if command.ControlFlowUncertain || command.ParentCommandID != 0 ||
			command.PipelineID != 0 || command.Kind != CommandKindProcess ||
			command.Program != "rm" || len(command.Arguments) != 3 ||
			command.Arguments[0].Value != "rm" ||
			!recursiveForceFlags(command.Arguments[1].Value) ||
			command.Arguments[2].StaticGlob == "" ||
			!hasFactOperation(command, OperationDelete) {
			continue
		}
		matched, err := path.Match(command.Arguments[2].StaticGlob, artifact)
		if err == nil && matched {
			return index
		}
	}
	return -1
}

func recursiveForceFlags(value string) bool {
	if len(value) < 3 || value[0] != '-' || value[1] == '-' {
		return false
	}
	seenR := false
	seenF := false
	for _, flag := range value[1:] {
		switch flag {
		case 'r', 'R':
			seenR = true
		case 'f':
			seenF = true
		default:
			return false
		}
	}
	return seenR && seenF
}

func exactUnconditionalTopLevelCommand(command CommandFact) bool {
	return exactTopLevelCommandStructure(command) && command.Effect == EffectExecute
}

func exactTopLevelCommandStructure(command CommandFact) bool {
	return !command.ControlFlowUncertain && command.ParentCommandID == 0 &&
		command.PipelineID == 0 && command.Kind == CommandKindProcess &&
		len(command.Wrappers) == 0 && len(command.Redirects) == 0
}

func hasFactOperation(command CommandFact, operation OperationKind) bool {
	for _, candidate := range command.Operations {
		if candidate == operation {
			return true
		}
	}
	return false
}
