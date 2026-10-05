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
	"reflect"
	"sort"
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// dynamicRedirectPlaceholderPrefix starts the static stand-in path for each
// runtime-expanded redirect target in the twin analysis. It is an absolute
// path with no meaning to the shell or to any path classification.
const dynamicRedirectPlaceholderPrefix = "/defenseclaw-runtime-redirect-target-"

// redirectTargetCapture records, for the top-level POSIX parse of a raw
// command, where the redirect targets the shell expands at run time are, so
// DynamicRedirectTargetReduction can analyze a static-target twin of the
// command.
type redirectTargetCapture struct {
	// source is the text the parser read.
	source string
	spans  []redirectTargetSpan
	// unsafe is set when a runtime-expanded target might not name a regular
	// file, or its position in source is unknown.
	unsafe bool
}

// redirectTargetSpan is the byte range of one redirect target word.
type redirectTargetSpan struct {
	start, end int
}

// record adds the target word of a runtime-expanded redirect.
func (c *redirectTargetCapture) record(word *syntax.Word) {
	if word == nil || !word.Pos().IsValid() || !word.End().IsValid() ||
		!posixFileAnchoredRedirectTarget(word) {
		c.unsafe = true
		return
	}
	start, end := int(word.Pos().Offset()), int(word.End().Offset())
	if start < 0 || end <= start {
		c.unsafe = true
		return
	}
	c.spans = append(c.spans, redirectTargetSpan{start: start, end: end})
}

// twin returns the source with every recorded target replaced by its own
// placeholder path, and the set of placeholders. It declines a source that
// already contains the placeholder prefix.
func (c redirectTargetCapture) twin() (string, map[string]bool, bool) {
	if c.unsafe || c.source == "" || len(c.spans) == 0 ||
		strings.Contains(c.source, dynamicRedirectPlaceholderPrefix) {
		return "", nil, false
	}
	spans := append([]redirectTargetSpan(nil), c.spans...)
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	var out strings.Builder
	placeholders := make(map[string]bool, len(spans))
	last := 0
	for index, span := range spans {
		if span.start < last || span.end > len(c.source) {
			return "", nil, false
		}
		placeholder := dynamicRedirectPlaceholderPrefix + strconv.Itoa(index+1)
		placeholders[placeholder] = true
		out.WriteString(c.source[last:span.start])
		out.WriteString(placeholder)
		last = span.end
	}
	out.WriteString(c.source[last:])
	return out.String(), placeholders, true
}

// posixFileAnchoredRedirectTarget reports whether a runtime-expanded
// redirect target can only name a file path: it starts with an unquoted ~
// (a home directory), or with $HOME or ${HOME} (optionally inside double
// quotes) followed by "/", or with a static absolute directory other than
// /dev ("/tmp/out-$USER.txt"), or it expands only as a filename pattern. Any
// other parameter could name anything, including the /dev/tcp and /dev/udp
// paths bash turns into network connections, and a command, process or
// arithmetic substitution runs or computes something.
func posixFileAnchoredRedirectTarget(word *syntax.Word) bool {
	if word == nil || len(word.Parts) == 0 {
		return false
	}
	substitution, parameters := false, 0
	syntax.Walk(word, func(node syntax.Node) bool {
		switch node.(type) {
		case *syntax.CmdSubst, *syntax.ProcSubst, *syntax.ArithmExp,
			*syntax.ExtGlob, *syntax.BraceExp:
			substitution = true
		case *syntax.ParamExp:
			parameters++
		}
		return !substitution
	})
	if substitution {
		return false
	}
	if literal, ok := word.Parts[0].(*syntax.Lit); ok && strings.HasPrefix(literal.Value, "~") {
		return true
	}
	if parameters == 0 {
		return true // only a filename pattern expands
	}
	// $HOME/..., ${HOME}/... or "$HOME/...": the parameter comes first and a
	// literal starting with "/" follows it.
	parts := word.Parts
	if quoted, ok := parts[0].(*syntax.DblQuoted); ok {
		if len(quoted.Parts) > 1 {
			parts = quoted.Parts
		} else if len(quoted.Parts) == 1 {
			parts = append([]syntax.WordPart{quoted.Parts[0]}, word.Parts[1:]...)
		}
	}
	// /tmp/out-$USER.txt: a static absolute directory comes first, so the
	// expanded word can only name a file under it.
	if staticAbsoluteDirectoryPrefix(parts[0]) {
		return true
	}
	if len(parts) < 2 || !plainHomeParameter(parts[0]) {
		return false
	}
	switch next := parts[1].(type) {
	case *syntax.Lit:
		return strings.HasPrefix(next.Value, "/")
	case *syntax.DblQuoted:
		if len(next.Parts) == 0 {
			return false
		}
		literal, ok := next.Parts[0].(*syntax.Lit)
		return ok && strings.HasPrefix(literal.Value, "/")
	case *syntax.SglQuoted:
		return strings.HasPrefix(next.Value, "/")
	}
	return false
}

// staticAbsoluteDirectoryPrefix reports whether part is a literal that starts
// with "/<dir>/", where <dir> is a plain name other than dev. Bash compares
// the expanded target text with its special /dev/... names, so a word with
// that prefix cannot become one, whatever its parameters expand to. A glob
// or escape character in <dir> could still spell dev and is refused.
func staticAbsoluteDirectoryPrefix(part syntax.WordPart) bool {
	var value string
	switch literal := part.(type) {
	case *syntax.Lit:
		value = literal.Value
	case *syntax.SglQuoted:
		value = literal.Value
	default:
		return false
	}
	if !strings.HasPrefix(value, "/") {
		return false
	}
	end := strings.IndexByte(value[1:], '/')
	if end <= 0 {
		return false
	}
	dir := value[1 : 1+end]
	return dir != "dev" && dir != "." && dir != ".." &&
		!strings.ContainsAny(dir, `*?[]\`)
}

// plainHomeParameter reports whether part is $HOME or ${HOME} with no
// operator.
func plainHomeParameter(part syntax.WordPart) bool {
	parameter, ok := part.(*syntax.ParamExp)
	return ok && parameter.Param != nil && parameter.Param.Value == "HOME" &&
		parameter.Flags == nil && !parameter.Excl && !parameter.Length &&
		!parameter.Width && !parameter.IsSet && parameter.NestedParam == nil &&
		parameter.Index == nil && len(parameter.Modifiers) == 0 &&
		parameter.Slice == nil && parameter.Repl == nil &&
		parameter.Names == 0 && parameter.Exp == nil
}

// analyzeWithRedirectTargets is Analyze that also returns the runtime-
// expanded redirect targets of the raw command's top-level POSIX parse.
// twinCommand, when set, is parsed in place of the raw command.
func analyzeWithRedirectTargets(input Input, twinCommand string) (Facts, redirectTargetCapture) {
	var capture redirectTargetCapture
	facts := analyze(input, twinCommand, &capture)
	return facts, capture
}

// DynamicRedirectTargetReduction returns a complete view of a partial POSIX
// action whose only uncertainty is a redirect target the shell expands at
// run time ("> ~/out.txt", "> $HOME/out.txt", "> out-*.txt"), with those
// redirects left out, and twin, the complete analysis the view was cut from.
// && and || lists in the action are read as sequences, as
// ShortCircuitListReduction reads them. facts must be Analyze(input).
//
// twin is the analysis of a twin of the command in which every such target
// is a static placeholder path; the view is twin without the placeholders'
// redirect and path facts. The view carries everything a complete analysis
// derives, including the child commands of wrappers such as sudo, env and
// sh -c and the write operations and data flows of each redirect. It differs
// from the action in the dropped redirect and path facts (the action has
// more), and in facts that only the target's real path could produce. A
// caller may count a semantic match on it only for an expression whose match
// more redirects and paths cannot undo (semantic.Program.RedirectReductionSafe),
// and a non-match on it proves nothing about the action. A Go check written
// for complete facts may read redirects and paths in any way, so a caller
// counts it only when it holds on both the view and twin.
//
// The view is unavailable unless every runtime-expanded target is a file
// path (it starts with ~, $HOME/ or a static directory such as /tmp/, or it
// expands only as a filename pattern), the twin analysis is complete (so the action's other parse
// issues came from those targets alone), every command in it is a plain
// POSIX process with a static argv and certain control flow, and no other
// fact of the twin carries a placeholder.
func DynamicRedirectTargetReduction(input Input, facts Facts) (view, twin Facts, ok bool) {
	defer func() {
		if recover() != nil {
			view, twin, ok = Facts{}, Facts{}, false
		}
	}()
	if facts.Parse.Status != StatusPartial || len(facts.Commands) == 0 ||
		!containsIssue(facts.Parse.Issues, IssueDynamicWord) {
		return Facts{}, Facts{}, false
	}
	original, capture := analyzeWithRedirectTargets(input, "")
	if original.Parse.Status != StatusPartial {
		return Facts{}, Facts{}, false
	}
	if sequence, ok := shortCircuitListSequence(capture.source); ok {
		_, capture = analyzeWithRedirectTargets(input, sequence)
	}
	twinSource, placeholders, ok := capture.twin()
	if !ok {
		return Facts{}, Facts{}, false
	}
	twin, twinCapture := analyzeWithRedirectTargets(input, twinSource)
	if !twin.Authoritative() || len(twin.Parse.Issues) != 0 ||
		twin.Parse.Dialect != facts.Parse.Dialect || len(twin.Commands) == 0 ||
		len(twinCapture.spans) != 0 || twinCapture.unsafe {
		return Facts{}, Facts{}, false
	}
	seen := make(map[string]bool, len(placeholders))
	commands := cloneCommands(twin.Commands)
	for index := range commands {
		command := &commands[index]
		if !plainPOSIXProcess(*command) {
			return Facts{}, Facts{}, false
		}
		kept := make([]RedirectFact, 0, len(command.Redirects))
		for _, redirect := range command.Redirects {
			if placeholders[redirect.Target] {
				seen[redirect.Target] = true
				continue
			}
			kept = append(kept, redirect)
		}
		command.Redirects = kept
	}
	if len(seen) != len(placeholders) {
		return Facts{}, Facts{}, false
	}
	paths := make([]PathFact, 0, len(twin.Paths))
	for _, path := range twin.Paths {
		if !placeholders[path.Value] {
			paths = append(paths, path)
		}
	}
	view = twin
	view.Commands = commands
	view.Paths = paths
	if mentionsString(reflect.ValueOf(view), dynamicRedirectPlaceholderPrefix, 0) {
		return Facts{}, Facts{}, false
	}
	return view, twin, true
}

// plainPOSIXProcess reports whether command is a POSIX process with a static
// argv and program that is certain to execute.
func plainPOSIXProcess(command CommandFact) bool {
	return command.Dialect == DialectPOSIX &&
		command.Kind == CommandKindProcess &&
		command.Effect == EffectExecute &&
		!command.ControlFlowUncertain && command.ArgvComplete &&
		len(command.Argv) != 0 && command.Argv[0] != "" &&
		command.Executable != "" && command.Program != "" &&
		len(command.Arguments) == len(command.Argv)
}

// mentionsString reports whether any string reachable from value contains
// needle.
func mentionsString(value reflect.Value, needle string, depth int) bool {
	if depth > 32 || !value.IsValid() {
		return false
	}
	switch value.Kind() {
	case reflect.String:
		return strings.Contains(value.String(), needle)
	case reflect.Pointer, reflect.Interface:
		return !value.IsNil() && mentionsString(value.Elem(), needle, depth+1)
	case reflect.Struct:
		for index := 0; index < value.NumField(); index++ {
			if mentionsString(value.Field(index), needle, depth+1) {
				return true
			}
		}
	case reflect.Slice, reflect.Array:
		for index := 0; index < value.Len(); index++ {
			if mentionsString(value.Index(index), needle, depth+1) {
				return true
			}
		}
	case reflect.Map:
		iterator := value.MapRange()
		for iterator.Next() {
			if mentionsString(iterator.Key(), needle, depth+1) ||
				mentionsString(iterator.Value(), needle, depth+1) {
				return true
			}
		}
	}
	return false
}
