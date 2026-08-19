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

// EnforcementProjection returns an independent view containing only commands
// and effects that are statically proven to execute.
//
// The full Facts value remains the input for detection. Callers may evaluate
// the same semantic expression against this projection to determine whether a
// match is supported entirely by executing commands. Filtering never makes
// non-authoritative input authoritative. Redirect reclassification may
// downgrade the projection when its bounded fact budgets are exhausted.
// Shell redirections remain executing effects even when the invoked program
// is in a preview mode.
func (f Facts) EnforcementProjection() Facts {
	projected := Facts{
		Tool:                                     f.Tool,
		CWD:                                      f.CWD,
		ActiveHome:                               f.ActiveHome,
		ActiveAgentFiles:                         cloneSlice(f.ActiveAgentFiles),
		ActiveAgentFilesCaseInsensitive:          cloneSlice(f.ActiveAgentFilesCaseInsensitive),
		ActiveAgentFilesCaseInsensitiveUncertain: f.ActiveAgentFilesCaseInsensitiveUncertain,
		ActiveAgentFilesUncertain:                f.ActiveAgentFilesUncertain,
		Parse: ParseResult{
			Status:  f.Parse.Status,
			Dialect: f.Parse.Dialect,
			Issues:  cloneSlice(f.Parse.Issues),
		},
	}

	executing := make(map[int64]struct{}, len(f.Commands))
	redirecting := make(map[int64]struct{}, len(f.Commands))
	// Redirect-only commands may remain structural parents, but only executing
	// commands own the source's semantic facts below.
	retainedHierarchy := make(map[int64]struct{}, len(f.Commands))
	parents := make(map[int64]int64, len(f.Commands))
	for _, command := range f.Commands {
		parents[command.ID] = command.ParentCommandID
		if command.Effect == EffectExecute {
			executing[command.ID] = struct{}{}
			retainedHierarchy[command.ID] = struct{}{}
		} else if command.Effect == EffectPreview &&
			hasStaticRedirect(command.Redirects) {
			redirecting[command.ID] = struct{}{}
			retainedHierarchy[command.ID] = struct{}{}
		}
	}

	for _, command := range f.Commands {
		if _, ok := executing[command.ID]; ok {
			copied := cloneCommands([]CommandFact{command})[0]
			copied.ParentCommandID = retainedParent(
				command.ID,
				command.ParentCommandID,
				parents,
				retainedHierarchy,
			)
			projected.Commands = append(projected.Commands, copied)
			continue
		}
		if _, ok := redirecting[command.ID]; !ok {
			continue
		}
		redirectCommand, paths, network, flows, parse := projectRedirectExecution(
			command,
			f.CWD,
			f.ActiveHome,
		)
		mergeProjectionParseResult(
			&projected.Parse,
			parse,
			len(paths) > 0 || len(network) > 0 || len(flows) > 0,
		)
		redirectCommand.ParentCommandID = retainedParent(
			command.ID,
			command.ParentCommandID,
			parents,
			retainedHierarchy,
		)
		projected.Commands = append(projected.Commands, redirectCommand)
		appendProjectionPaths(&projected, paths)
		appendProjectionNetwork(&projected, network)
		appendProjectionDataFlows(&projected, flows)
	}

	for _, fact := range f.Paths {
		if ownsCommand(fact.CommandID, executing) {
			appendProjectionPaths(&projected, []PathFact{fact})
		}
	}
	for _, fact := range f.Network {
		if ownsCommand(fact.CommandID, executing) {
			appendProjectionNetwork(&projected, []NetworkFact{fact})
		}
	}
	for _, fact := range f.DataFlows {
		if retainedFlow(fact, executing) {
			appendProjectionDataFlows(&projected, []DataFlowFact{fact})
		}
	}

	return projected
}

func projectRedirectExecution(
	command CommandFact,
	cwd string,
	activeHome string,
) (CommandFact, []PathFact, []NetworkFact, []DataFlowFact, ParseResult) {
	redirects := make([]RedirectFact, 0, len(command.Redirects))
	for _, redirect := range command.Redirects {
		if isStaticRedirect(redirect) {
			redirects = append(redirects, redirect)
		}
	}
	projected := CommandFact{
		ID:              command.ID,
		ParentCommandID: command.ParentCommandID,
		Kind:            CommandKindShellRedirect,
		Dialect:         command.Dialect,
		Effect:          EffectExecute,
		ArgvComplete:    true,
		Redirects:       redirects,
	}
	addOperation(&projected, OperationExecute)

	out := newParseOutput(command.Dialect, 1)
	classifyRedirects(&out, &projected)
	deduplicateFacts(&out)
	facts := out.factsWithContext("", cwd, activeHome)
	commands := []CommandFact{projected}
	reconcileNormalizedDeviceWrites(commands, facts.Paths)
	return commands[0], facts.Paths, facts.Network, facts.DataFlows, facts.Parse
}

func mergeProjectionParseResult(
	target *ParseResult,
	source ParseResult,
	haveFacts bool,
) {
	// Projection is monotonic: reclassification can downgrade a complete
	// source, but it must never make an already non-authoritative source
	// authoritative.
	if source.Status != StatusComplete &&
		source.Status != StatusNotApplicable &&
		source.Status != "" {
		target.Status = mergeParseStatus(target.Status, source.Status, haveFacts)
	}
	for _, issue := range source.Issues {
		if containsIssue(target.Issues, issue) || len(target.Issues) >= maxIssues {
			continue
		}
		target.Issues = append(target.Issues, issue)
	}
}

func appendProjectionPaths(projected *Facts, facts []PathFact) {
	for _, fact := range facts {
		if len(projected.Paths) >= maxPathFacts {
			markProjectionFactLimit(projected)
			return
		}
		projected.Paths = append(projected.Paths, fact)
	}
}

func appendProjectionNetwork(projected *Facts, facts []NetworkFact) {
	for _, fact := range facts {
		if len(projected.Network) >= maxNetworkFacts {
			markProjectionFactLimit(projected)
			return
		}
		projected.Network = append(projected.Network, fact)
	}
}

func appendProjectionDataFlows(projected *Facts, facts []DataFlowFact) {
	for _, fact := range facts {
		if len(projected.DataFlows) >= maxDataFlowFacts {
			markProjectionFactLimit(projected)
			return
		}
		projected.DataFlows = append(projected.DataFlows, fact)
	}
}

func markProjectionFactLimit(projected *Facts) {
	mergeProjectionParseResult(
		&projected.Parse,
		ParseResult{
			Status: StatusLimitExceeded,
			Issues: []IssueCode{IssueFactLimit},
		},
		len(projected.Commands) > 0 ||
			len(projected.Paths) > 0 ||
			len(projected.Network) > 0 ||
			len(projected.DataFlows) > 0,
	)
}

func hasStaticRedirect(redirects []RedirectFact) bool {
	for _, redirect := range redirects {
		if isStaticRedirect(redirect) {
			return true
		}
	}
	return false
}

func isStaticRedirect(redirect RedirectFact) bool {
	return !redirect.Expands && redirect.Target != ""
}

func ownsCommand(commandID int64, retained map[int64]struct{}) bool {
	if commandID == 0 {
		return false
	}
	_, ok := retained[commandID]
	return ok
}

func retainedFlow(fact DataFlowFact, retained map[int64]struct{}) bool {
	if fact.FromCommandID == 0 && fact.ToCommandID == 0 {
		return false
	}
	if fact.FromCommandID != 0 {
		if _, ok := retained[fact.FromCommandID]; !ok {
			return false
		}
	}
	if fact.ToCommandID != 0 {
		if _, ok := retained[fact.ToCommandID]; !ok {
			return false
		}
	}
	return true
}

func retainedParent(
	commandID int64,
	parentID int64,
	parents map[int64]int64,
	retained map[int64]struct{},
) int64 {
	seen := map[int64]struct{}{commandID: {}}
	for parentID != 0 {
		if _, loop := seen[parentID]; loop {
			return 0
		}
		seen[parentID] = struct{}{}
		if _, ok := retained[parentID]; ok {
			return parentID
		}
		next, ok := parents[parentID]
		if !ok {
			return 0
		}
		parentID = next
	}
	return 0
}
