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

type parseOutput struct {
	status    ParseStatus
	dialect   Dialect
	issues    []IssueCode
	commands  []CommandFact
	paths     []PathFact
	network   []NetworkFact
	dataFlows []DataFlowFact
	nextID    int64
}

func newParseOutput(dialect Dialect, startID int64) parseOutput {
	if startID < 1 {
		startID = 1
	}
	return parseOutput{
		status:  StatusComplete,
		dialect: dialect,
		nextID:  startID,
	}
}

func (o *parseOutput) nextCommandID() int64 {
	id := o.nextID
	o.nextID++
	return id
}

func (o *parseOutput) addIssue(code IssueCode) {
	if code == "" {
		return
	}
	for _, existing := range o.issues {
		if existing == code {
			return
		}
	}
	if len(o.issues) < maxIssues {
		o.issues = append(o.issues, code)
	}
}

func (o *parseOutput) markPartial(code IssueCode) {
	if o.status == StatusComplete || o.status == StatusNotApplicable ||
		o.status == StatusUnsupported {
		o.status = StatusPartial
	}
	o.addIssue(code)
}

func (o *parseOutput) markUnsupported(code IssueCode) {
	if o.status == StatusComplete || o.status == StatusNotApplicable {
		if o.hasFacts() {
			o.status = StatusPartial
		} else {
			o.status = StatusUnsupported
		}
	}
	o.addIssue(code)
}

func (o *parseOutput) markInvalid(code IssueCode) {
	if o.status != StatusLimitExceeded && o.status != StatusAmbiguous {
		o.status = StatusInvalid
	}
	o.addIssue(code)
}

func (o *parseOutput) markLimit(code IssueCode) {
	o.status = StatusLimitExceeded
	o.addIssue(code)
}

func (o *parseOutput) markAmbiguous(code IssueCode) {
	if o.status != StatusLimitExceeded {
		o.status = StatusAmbiguous
	}
	o.addIssue(code)
}

func (o *parseOutput) hasFacts() bool {
	return len(o.commands) > 0 ||
		len(o.paths) > 0 ||
		len(o.network) > 0 ||
		len(o.dataFlows) > 0
}

func (o *parseOutput) appendCommand(command CommandFact) bool {
	if len(o.commands) >= maxCommands {
		o.markLimit(IssueFactLimit)
		return false
	}
	o.commands = append(o.commands, command)
	return true
}

func (o *parseOutput) appendRedirects(
	command *CommandFact,
	redirects ...RedirectFact,
) bool {
	remaining := maxRedirectsPerCommand - len(command.Redirects)
	if remaining < 0 || len(redirects) > remaining {
		o.markLimit(IssueFactLimit)
		return false
	}
	command.Redirects = append(command.Redirects, redirects...)
	return true
}

func (o *parseOutput) appendPath(fact PathFact) bool {
	if len(o.paths) >= maxPathFacts {
		o.markLimit(IssueFactLimit)
		return false
	}
	o.paths = append(o.paths, fact)
	return true
}

func (o *parseOutput) appendNetwork(fact NetworkFact) bool {
	if len(o.network) >= maxNetworkFacts {
		o.markLimit(IssueFactLimit)
		return false
	}
	o.network = append(o.network, fact)
	return true
}

func (o *parseOutput) appendDataFlow(fact DataFlowFact) bool {
	if len(o.dataFlows) >= maxDataFlowFacts {
		o.markLimit(IssueFactLimit)
		return false
	}
	o.dataFlows = append(o.dataFlows, fact)
	return true
}

func (o *parseOutput) merge(other parseOutput) {
	if len(o.commands) > 0 && len(other.commands) > 0 {
		existingCommandIDs := make(map[int64]struct{}, len(o.commands))
		for _, command := range o.commands {
			existingCommandIDs[command.ID] = struct{}{}
		}
		for _, command := range other.commands {
			if _, collision := existingCommandIDs[command.ID]; collision {
				o.markAmbiguous(IssueConflictingSources)
				return
			}
		}
	}
	if o.dialect == DialectNone {
		o.dialect = other.dialect
	} else if other.dialect != DialectNone && o.dialect != other.dialect {
		o.dialect = DialectMixed
		o.markAmbiguous(IssueConflictingSources)
	}
	for _, issue := range other.issues {
		o.addIssue(issue)
	}
	for _, command := range other.commands {
		if !o.appendCommand(command) {
			break
		}
	}
	validCommandIDs := make(map[int64]struct{}, len(o.commands))
	for _, command := range o.commands {
		validCommandIDs[command.ID] = struct{}{}
	}
	for _, fact := range other.paths {
		if fact.CommandID != 0 {
			if _, ok := validCommandIDs[fact.CommandID]; !ok {
				continue
			}
		}
		if !o.appendPath(fact) {
			break
		}
	}
	for _, fact := range other.network {
		if fact.CommandID != 0 {
			if _, ok := validCommandIDs[fact.CommandID]; !ok {
				continue
			}
		}
		if !o.appendNetwork(fact) {
			break
		}
	}
	for _, fact := range other.dataFlows {
		if fact.FromCommandID != 0 {
			if _, ok := validCommandIDs[fact.FromCommandID]; !ok {
				continue
			}
		}
		if fact.ToCommandID != 0 {
			if _, ok := validCommandIDs[fact.ToCommandID]; !ok {
				continue
			}
		}
		if !o.appendDataFlow(fact) {
			break
		}
	}
	if other.nextID > o.nextID {
		o.nextID = other.nextID
	}
	o.status = mergeParseStatus(o.status, other.status, o.hasFacts())
}

// mergeNested combines an exactly located nested grammar without treating the
// expected dialect transition as a source conflict.
func (o *parseOutput) mergeNested(other parseOutput) {
	if o.dialect != DialectNone && other.dialect != DialectNone &&
		o.dialect != other.dialect {
		o.dialect = DialectMixed
		other.dialect = DialectMixed
	}
	o.merge(other)
}

func mergeParseStatus(left, right ParseStatus, haveFacts bool) ParseStatus {
	if left == StatusLimitExceeded || right == StatusLimitExceeded {
		return StatusLimitExceeded
	}
	if left == StatusAmbiguous || right == StatusAmbiguous {
		return StatusAmbiguous
	}
	if left == StatusInvalid || right == StatusInvalid {
		return StatusInvalid
	}
	if left == StatusPartial || right == StatusPartial {
		return StatusPartial
	}
	if left == StatusUnsupported || right == StatusUnsupported {
		if haveFacts {
			return StatusPartial
		}
		return StatusUnsupported
	}
	if left == StatusNotApplicable {
		return right
	}
	if right == StatusNotApplicable {
		return left
	}
	return StatusComplete
}

func (o parseOutput) facts(tool, cwd string) Facts {
	return o.factsWithContext(tool, cwd, "")
}

func (o parseOutput) factsWithContext(tool, cwd, activeHome string) Facts {
	status := o.status
	if status == "" {
		status = StatusNotApplicable
	}
	dialect := o.dialect
	if dialect == "" {
		dialect = DialectNone
	}
	commands := cloneCommands(o.commands)
	paths := cloneSlice(o.paths)
	normalizePathFactsForCommands(paths, cwd, activeHome, commands)
	reconcileNormalizedDeviceWrites(commands, paths)
	network := cloneSlice(o.network)
	normalizeNetworkFacts(network)
	return Facts{
		Tool:       tool,
		CWD:        cwd,
		ActiveHome: activeHome,
		Parse:      ParseResult{Status: status, Dialect: dialect, Issues: cloneSlice(o.issues)},
		Commands:   commands,
		Paths:      paths,
		Network:    network,
		DataFlows:  cloneSlice(o.dataFlows),
	}
}

func cloneSlice[T any](in []T) []T {
	if len(in) == 0 {
		return nil
	}
	return append([]T(nil), in...)
}

func cloneCommands(in []CommandFact) []CommandFact {
	if len(in) == 0 {
		return nil
	}
	out := make([]CommandFact, len(in))
	for i, command := range in {
		out[i] = command
		if out[i].Kind == "" {
			out[i].Kind = CommandKindProcess
		}
		out[i].Argv = cloneSlice(command.Argv)
		out[i].Arguments = cloneSlice(command.Arguments)
		out[i].Operations = cloneSlice(command.Operations)
		out[i].Redirects = cloneSlice(command.Redirects)
		if len(command.Wrappers) > 0 {
			out[i].Wrappers = make([]WrapperFact, len(command.Wrappers))
			for j, wrapper := range command.Wrappers {
				out[i].Wrappers[j] = wrapper
				out[i].Wrappers[j].Argv = cloneSlice(wrapper.Argv)
			}
		}
	}
	return out
}
