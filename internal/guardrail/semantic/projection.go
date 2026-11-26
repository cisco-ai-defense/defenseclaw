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

package semantic

import (
	"path"
	"strings"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semanticpb"
)

// Project constructs the sole CEL-visible activation from bounded ActionFacts.
// It never truncates or repairs the sections rules read; any failure there
// returns no partial message. The fact-only sections (sql_facts, kube) never
// fail the projection: a call whose SQL or Kubernetes facts are past a bound
// keeps every other semantic rule (DET111 T20 review P1-1). Their entries
// past a bound are cut (FactOnlyCuts), and the gateway judges the cut call
// TRUNCATED.
func Project(facts actionfacts.Facts) (*semanticpb.Facts, ProjectionCode) {
	if len(facts.Commands) > maxCommands ||
		len(facts.Paths) > maxPaths ||
		len(facts.Network) > maxNetwork ||
		len(facts.DataFlows) > maxDataFlows ||
		len(facts.Artifacts) > maxArtifacts ||
		len(facts.Parse.Issues) > maxIssues {
		return nil, ProjectionCountLimit
	}
	if !validScalar(facts.Tool) ||
		!validScalar(facts.CWD) ||
		!validScalar(facts.ActiveHome) {
		return nil, ProjectionScalarLimit
	}

	status, ok := projectParseStatus(facts.Parse.Status)
	if !ok {
		return nil, ProjectionInvalidEnum
	}
	dialect, ok := projectDialect(facts.Parse.Dialect)
	if !ok {
		return nil, ProjectionInvalidEnum
	}
	projected := &semanticpb.Facts{
		Tool:       facts.Tool,
		Cwd:        facts.CWD,
		ActiveHome: facts.ActiveHome,
		Parse: &semanticpb.ParseResult{
			Status:  status,
			Dialect: dialect,
			Issues:  make([]semanticpb.IssueCode, len(facts.Parse.Issues)),
		},
		Commands:        make([]*semanticpb.CommandFact, 0, len(facts.Commands)),
		SqlFacts:        make([]*semanticpb.SQLFact, 0, len(facts.SQLFacts)),
		Paths:           make([]*semanticpb.PathFact, 0, len(facts.Paths)),
		Network:         make([]*semanticpb.NetworkFact, 0, len(facts.Network)),
		DataFlows:       make([]*semanticpb.DataFlowFact, 0, len(facts.DataFlows)),
		Artifacts:       make([]*semanticpb.ArtifactFact, 0, len(facts.Artifacts)),
		ArchiveLineages: make([]*semanticpb.ArchiveArtifactLineage, 0),
	}
	sqlFacts, _ := factOnlySQL(facts.SQLFacts)
	projected.SqlFacts = sqlFacts

	for index, issue := range facts.Parse.Issues {
		mapped, valid := projectIssue(issue)
		if !valid {
			return nil, ProjectionInvalidEnum
		}
		projected.Parse.Issues[index] = mapped
	}

	commandIDs := make(map[int64]struct{}, len(facts.Commands))
	parents := make(map[int64]int64, len(facts.Commands))
	var previousID int64
	for _, command := range facts.Commands {
		if command.ID <= previousID {
			return nil, ProjectionInvalidCommand
		}
		previousID = command.ID
		if _, duplicate := commandIDs[command.ID]; duplicate {
			return nil, ProjectionInvalidCommand
		}
		commandIDs[command.ID] = struct{}{}
		parents[command.ID] = command.ParentCommandID

		mapped, code := projectCommand(command, facts.Parse.Status)
		if code != ProjectionOK {
			return nil, code
		}
		projected.Commands = append(projected.Commands, mapped)
	}
	if code := validateCommandReferences(parents, commandIDs); code != ProjectionOK {
		return nil, code
	}

	for _, fact := range facts.Paths {
		if !knownCommandReference(fact.CommandID, commandIDs) {
			return nil, ProjectionInvalidReference
		}
		access, valid := projectPathAccess(fact.Access)
		if !valid {
			return nil, ProjectionInvalidEnum
		}
		flavor, valid := projectPathFlavor(fact.Flavor)
		if !valid {
			return nil, ProjectionInvalidEnum
		}
		if !validScalar(fact.Value) ||
			!validScalar(fact.Normalized) ||
			!validScalar(fact.Resolved) {
			return nil, ProjectionScalarLimit
		}
		if !validResolvedPath(fact.Flavor, fact.Resolved) {
			return nil, ProjectionInvalidReference
		}
		projected.Paths = append(projected.Paths, &semanticpb.PathFact{
			CommandId:  fact.CommandID,
			Access:     access,
			Flavor:     flavor,
			Value:      fact.Value,
			Normalized: fact.Normalized,
			Absolute:   fact.Absolute,
			Resolved:   fact.Resolved,
		})
	}

	for _, fact := range facts.Network {
		if !knownCommandReference(fact.CommandID, commandIDs) {
			return nil, ProjectionInvalidReference
		}
		action, valid := projectNetworkAction(fact.Action)
		if !valid {
			return nil, ProjectionInvalidEnum
		}
		scope, valid := projectNetworkScope(fact.Scope)
		if !valid {
			return nil, ProjectionInvalidEnum
		}
		target, valid := projectNetworkTarget(fact.TargetKind)
		if !valid {
			return nil, ProjectionInvalidEnum
		}
		if !validScalar(fact.Scheme) ||
			!validScalar(fact.Host) ||
			!validScalar(fact.NormalizedHost) {
			return nil, ProjectionScalarLimit
		}
		if fact.Port < 0 || fact.Port > 65535 ||
			fact.PrefixLength < 0 || fact.PrefixLength > 128 {
			return nil, ProjectionInvalidNetwork
		}
		projected.Network = append(projected.Network, &semanticpb.NetworkFact{
			CommandId:      fact.CommandID,
			Action:         action,
			Scheme:         fact.Scheme,
			Host:           fact.Host,
			Port:           fact.Port,
			NormalizedHost: fact.NormalizedHost,
			Scope:          scope,
			TargetKind:     target,
			PrefixLength:   fact.PrefixLength,
		})
	}

	for _, fact := range facts.KubeRequests {
		if !knownCommandReference(fact.CommandID, commandIDs) {
			return nil, ProjectionInvalidReference
		}
		if len(projected.Kube) == maxKube || !validKubeFact(fact) {
			continue // a fact-only cut (FactOnlyCuts), never a failure
		}
		source := string(fact.Source)
		projected.Kube = append(projected.Kube, &semanticpb.KubeFact{
			CommandId:      fact.CommandID,
			Source:         source,
			Verb:           fact.Verb,
			Group:          fact.Group,
			Version:        fact.Version,
			Resource:       fact.Resource,
			Subresource:    fact.Subresource,
			Namespace:      fact.Namespace,
			Name:           fact.Name,
			AllNamespaces:  fact.AllNamespaces,
			Stdin:          fact.Stdin,
			Tty:            fact.TTY,
			Command:        fact.Command,
			LabelSelector:  fact.LabelSelector,
			RevealsContent: fact.RevealsContent,
			Unknown:        fact.Unknown,
		})
	}

	for _, fact := range facts.DataFlows {
		if fact.FromCommandID == 0 && fact.ToCommandID == 0 {
			return nil, ProjectionInvalidDataFlow
		}
		if !knownCommandReference(fact.FromCommandID, commandIDs) ||
			!knownCommandReference(fact.ToCommandID, commandIDs) {
			return nil, ProjectionInvalidReference
		}
		from, valid := projectDataKind(fact.From)
		if !valid {
			return nil, ProjectionInvalidEnum
		}
		to, valid := projectDataKind(fact.To)
		if !valid {
			return nil, ProjectionInvalidEnum
		}
		projected.DataFlows = append(projected.DataFlows, &semanticpb.DataFlowFact{
			FromCommandId: fact.FromCommandID,
			ToCommandId:   fact.ToCommandID,
			From:          from,
			To:            to,
		})
	}

	for _, fact := range facts.Artifacts {
		if !knownCommandReference(fact.CommandID, commandIDs) {
			return nil, ProjectionInvalidReference
		}
		role, valid := projectArtifactRole(fact.Role)
		if !valid {
			return nil, ProjectionInvalidEnum
		}
		kind, valid := projectArtifactKind(fact.Kind)
		if !valid {
			return nil, ProjectionInvalidEnum
		}
		if !validScalar(fact.Value) ||
			!validScalar(fact.Normalized) ||
			!validScalar(fact.Resolved) ||
			!validScalar(fact.Identity) {
			return nil, ProjectionScalarLimit
		}
		projected.Artifacts = append(projected.Artifacts, &semanticpb.ArtifactFact{
			CommandId:  fact.CommandID,
			Role:       role,
			Kind:       kind,
			Value:      fact.Value,
			Normalized: fact.Normalized,
			Absolute:   fact.Absolute,
			Resolved:   fact.Resolved,
			Identity:   fact.Identity,
		})
	}

	lineages := actionfacts.StaticArchiveArtifactLineage(facts)
	if len(lineages) > maxArchiveLineages {
		return nil, ProjectionCountLimit
	}
	for _, lineage := range lineages {
		if !knownCommandReference(lineage.ProducedBy, commandIDs) ||
			!knownCommandReference(lineage.ConsumedBy, commandIDs) {
			return nil, ProjectionInvalidReference
		}
		if !validScalar(lineage.Identity) || !validScalar(lineage.Normalized) {
			return nil, ProjectionScalarLimit
		}
		projected.ArchiveLineages = append(
			projected.ArchiveLineages,
			&semanticpb.ArchiveArtifactLineage{
				Identity:      lineage.Identity,
				ProducedBy:    lineage.ProducedBy,
				ConsumedBy:    lineage.ConsumedBy,
				Normalized:    lineage.Normalized,
				Authoritative: lineage.Authoritative,
			},
		)
	}
	return projected, ProjectionOK
}

func projectCommand(
	command actionfacts.CommandFact,
	parseStatus actionfacts.ParseStatus,
) (*semanticpb.CommandFact, ProjectionCode) {
	if command.ID <= 0 || command.ParentCommandID < 0 ||
		command.PipelineID < 0 || command.ParentCommandID == command.ID {
		return nil, ProjectionInvalidCommand
	}
	if len(command.Argv) > maxArgvItems ||
		len(command.Arguments) > maxArgumentsPerCommand ||
		len(command.Operations) > maxOperationsPerCommand ||
		len(command.Redirects) > maxRedirectsPerCommand ||
		len(command.Wrappers) > maxWrappersPerCommand {
		return nil, ProjectionCountLimit
	}
	if !validScalar(command.Executable) || !validScalar(command.Program) {
		return nil, ProjectionScalarLimit
	}
	kind, ok := projectCommandKind(command.Kind)
	if !ok {
		return nil, ProjectionInvalidEnum
	}
	dialect, ok := projectDialect(command.Dialect)
	if !ok || command.Dialect == actionfacts.DialectNone {
		return nil, ProjectionInvalidEnum
	}
	effect, ok := projectCommandEffect(command.Effect)
	if !ok {
		return nil, ProjectionInvalidEnum
	}
	if command.Kind == actionfacts.CommandKindProcess {
		if command.ArgvComplete &&
			(command.Executable == "" ||
				len(command.Argv) != len(command.Arguments)) {
			return nil, ProjectionInvalidCommand
		}
		if parseStatus == actionfacts.StatusComplete && command.Program == "" {
			return nil, ProjectionInvalidCommand
		}
	} else if command.Executable != "" ||
		command.Program != "" ||
		len(command.Argv) != 0 ||
		len(command.Arguments) != 0 ||
		len(command.Wrappers) != 0 ||
		!command.ArgvComplete ||
		command.Effect != actionfacts.EffectExecute ||
		!hasStaticRedirect(command.Redirects) {
		return nil, ProjectionInvalidCommand
	}

	projected := &semanticpb.CommandFact{
		Id:              command.ID,
		ParentCommandId: command.ParentCommandID,
		PipelineId:      command.PipelineID,
		Kind:            kind,
		Dialect:         dialect,
		Effect:          effect,
		Executable:      command.Executable,
		Program:         command.Program,
		Argv:            make([]string, len(command.Argv)),
		Arguments:       make([]*semanticpb.ArgumentFact, len(command.Arguments)),
		ArgvComplete:    command.ArgvComplete,
		Operations:      make([]semanticpb.OperationKind, len(command.Operations)),
		Redirects:       make([]*semanticpb.RedirectFact, len(command.Redirects)),
		Wrappers:        make([]*semanticpb.WrapperFact, len(command.Wrappers)),
	}
	argvBytes := 0
	for index, argument := range command.Argv {
		if !validScalar(argument) {
			return nil, ProjectionScalarLimit
		}
		argvBytes += len(argument)
		if argvBytes > maxArgvBytes {
			return nil, ProjectionScalarLimit
		}
		projected.Argv[index] = argument
	}
	for index, argument := range command.Arguments {
		if !validScalar(argument.Value) {
			return nil, ProjectionScalarLimit
		}
		quote, valid := projectQuote(argument.Quote)
		if !valid {
			return nil, ProjectionInvalidEnum
		}
		projected.Arguments[index] = &semanticpb.ArgumentFact{
			Value:   argument.Value,
			Quote:   quote,
			Expands: argument.Expands,
		}
	}
	seenOperations := make(map[actionfacts.OperationKind]struct{}, len(command.Operations))
	for index, operation := range command.Operations {
		if _, duplicate := seenOperations[operation]; duplicate {
			return nil, ProjectionInvalidCommand
		}
		seenOperations[operation] = struct{}{}
		mapped, valid := projectOperation(operation)
		if !valid {
			return nil, ProjectionInvalidEnum
		}
		projected.Operations[index] = mapped
	}
	for index, redirect := range command.Redirects {
		access, valid := projectPathAccess(redirect.Access)
		if !valid {
			return nil, ProjectionInvalidEnum
		}
		if !validScalar(redirect.Target) {
			return nil, ProjectionScalarLimit
		}
		projected.Redirects[index] = &semanticpb.RedirectFact{
			Fd:      redirect.FD,
			Access:  access,
			Target:  redirect.Target,
			Expands: redirect.Expands,
		}
	}
	for index, wrapper := range command.Wrappers {
		if wrapper.Executable == "" || !validScalar(wrapper.Executable) ||
			len(wrapper.Argv) > maxArgvItems {
			return nil, ProjectionInvalidCommand
		}
		mapped := &semanticpb.WrapperFact{
			Executable: wrapper.Executable,
			Argv:       make([]string, len(wrapper.Argv)),
		}
		wrapperBytes := 0
		for argvIndex, argument := range wrapper.Argv {
			if !validScalar(argument) {
				return nil, ProjectionScalarLimit
			}
			wrapperBytes += len(argument)
			if wrapperBytes > maxArgvBytes {
				return nil, ProjectionScalarLimit
			}
			mapped.Argv[argvIndex] = argument
		}
		projected.Wrappers[index] = mapped
	}
	return projected, ProjectionOK
}

func validateCommandReferences(
	parents map[int64]int64,
	commandIDs map[int64]struct{},
) ProjectionCode {
	for id, parent := range parents {
		if parent == 0 {
			continue
		}
		if parent == id {
			return ProjectionInvalidCommand
		}
		if _, exists := commandIDs[parent]; !exists {
			return ProjectionInvalidReference
		}
	}
	for id := range commandIDs {
		seen := make(map[int64]struct{}, len(commandIDs))
		for current := id; current != 0; current = parents[current] {
			if _, duplicate := seen[current]; duplicate {
				return ProjectionInvalidCommand
			}
			seen[current] = struct{}{}
		}
	}
	return ProjectionOK
}

func knownCommandReference(id int64, commandIDs map[int64]struct{}) bool {
	if id == 0 {
		return true
	}
	_, ok := commandIDs[id]
	return ok
}

func hasStaticRedirect(redirects []actionfacts.RedirectFact) bool {
	for _, redirect := range redirects {
		if !redirect.Expands && redirect.Target != "" {
			return true
		}
	}
	return false
}

// FactOnlyCuts reports the bounds the projection cut the fact-only sections
// at (sql_facts, kube): more entries than the section holds (bounded.Items),
// or a value past the scalar bound (bounded.Bytes). A cut is never a clean
// read: the gateway judges the call TRUNCATED (DET111 T20 review P1-1).
func FactOnlyCuts(facts actionfacts.Facts) bounded.CapSet {
	var trunc bounded.Truncated
	_, cut := factOnlySQL(facts.SQLFacts)
	trunc.Merge(cut)
	trunc.Within(bounded.Items, len(facts.KubeRequests), maxKube)
	for _, fact := range facts.KubeRequests {
		if !validKubeFact(fact) {
			trunc.Hit(bounded.Bytes)
		}
	}
	return trunc.Set()
}

// factOnlySQL projects the SQL facts, cutting what is past a bound: facts
// past maxSQLFacts, values past maxSQLFactValues per list, a value that is
// not a valid scalar (dropped, or "" for the database) and a statement count
// outside 0..maxSQLFactStatements. It never fails.
func factOnlySQL(facts []actionfacts.SQLFact) ([]*semanticpb.SQLFact, bounded.CapSet) {
	var trunc bounded.Truncated
	if !trunc.Within(bounded.Items, len(facts), maxSQLFacts) {
		facts = facts[:maxSQLFacts]
	}
	values := func(in []string) []string {
		out := make([]string, 0, min(len(in), maxSQLFactValues))
		for _, value := range in {
			if !validScalar(value) {
				trunc.Hit(bounded.Bytes)
				continue
			}
			if !trunc.Within(bounded.Items, len(out)+1, maxSQLFactValues) {
				break
			}
			out = append(out, value)
		}
		return out
	}
	out := make([]*semanticpb.SQLFact, 0, len(facts))
	for _, fact := range facts {
		database := fact.Database
		if !validScalar(database) {
			trunc.Hit(bounded.Bytes)
			database = ""
		}
		count := fact.StatementCount
		if count < 0 || count > maxSQLFactStatements {
			trunc.Hit(bounded.Items)
			count = max(0, min(count, maxSQLFactStatements))
		}
		out = append(out, &semanticpb.SQLFact{
			Verbs:          values(fact.Verbs),
			Tables:         values(fact.Tables),
			Functions:      values(fact.Functions),
			Database:       database,
			StatementCount: int64(count),
		})
	}
	return out, trunc.Set()
}

// validKubeFact reports a Kubernetes request whose every value is a valid
// scalar; any other is cut from f.kube whole, never projected with a blank
// field (a blank resource would read as a request of an unknown kind).
func validKubeFact(fact actionfacts.KubeRequestFact) bool {
	for _, value := range []string{string(fact.Source), fact.Verb, fact.Group, fact.Version,
		fact.Resource, fact.Subresource, fact.Namespace, fact.Name} {
		if !validScalar(value) {
			return false
		}
	}
	return true
}

func validScalar(value string) bool {
	return len(value) <= maxScalarBytes &&
		utf8.ValidString(value) &&
		!strings.ContainsRune(value, '\x00')
}

func validResolvedPath(flavor actionfacts.PathFlavor, value string) bool {
	if value == "" {
		return true
	}
	switch flavor {
	case actionfacts.PathFlavorPOSIX:
		// A Git Bash parse on Windows resolves ~ and $HOME to the drive
		// home in slash form (C:/Users/x), an absolute POSIX path for
		// that shell (GAP-2304, GAP-2122 Windows leg). A drive root keeps
		// its slash: path.Clean spells C:/ as C:, the drive's current
		// folder, so a call on the drive root (find C:/ -delete) failed
		// the projection and no semantic rule judged it
		// (rel-1-0-10:GAP-0945).
		if len(value) == 3 && actionfacts.DriveSlashPath(value) {
			return true
		}
		return (strings.HasPrefix(value, "/") || actionfacts.DriveSlashPath(value)) && path.Clean(value) == value
	case actionfacts.PathFlavorWindows:
		return validWindowsResolvedPath(value)
	case actionfacts.PathFlavorDevice:
		if strings.HasPrefix(value, "//./") {
			tail := strings.TrimPrefix(value, "//./")
			return !strings.Contains(tail, `\`) &&
				validSlashSegments(tail, false)
		}
		return strings.HasPrefix(value, "/") && path.Clean(value) == value
	case actionfacts.PathFlavorRegistry:
		return validRegistryResolvedPath(value)
	default:
		return false
	}
}

func validWindowsResolvedPath(value string) bool {
	if strings.Contains(value, `\`) {
		return false
	}
	switch {
	case len(value) >= 3 &&
		value[0] >= 'A' && value[0] <= 'Z' &&
		value[1] == ':' && value[2] == '/':
		return validSlashSegments(value[3:], true)
	case strings.HasPrefix(value, "//"):
		parts := strings.Split(strings.TrimPrefix(value, "//"), "/")
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			return false
		}
		return validSlashSegments(strings.Join(parts, "/"), false)
	default:
		return false
	}
}

func validRegistryResolvedPath(value string) bool {
	if strings.Contains(value, `\`) {
		return false
	}
	for _, root := range []string{"HKLM", "HKCU", "HKCR", "HKU", "HKCC"} {
		if value == root {
			return true
		}
		if strings.HasPrefix(value, root+"/") {
			return validSlashSegments(strings.TrimPrefix(value, root+"/"), false)
		}
	}
	return false
}

func validSlashSegments(value string, allowEmpty bool) bool {
	if value == "" {
		return allowEmpty
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}
