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
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/psparse"
)

// A PowerShell download cradle runs content it fetched: Invoke-Expression (or
// a script block built from the text) whose input is a web request's output,
// a WebClient download, or a variable that holds one. The pipe form
// (iwr ... | iex) is one spelling of it; this file recognizes the chain itself
// on the psparse tree, so every spelling of the chain is the same fact:
//
//	iex (New-Object Net.WebClient).DownloadString(...)
//	iex (iwr ...)         Invoke-Expression ((irm ...).Content)
//	$c = [Net.WebClient]::new(); iex $c.DownloadString(...)
//	$s = irm ...; iex $s
//	[scriptblock]::Create((iwr ...)).Invoke()    & ([scriptblock]::Create(...))
//
// Only unconditional top-level statements of the script count, after the static
// launchers around it are unwrapped (host_unwrap.go). A fetch whose output goes
// to a file (-OutFile, -o) does not produce content to run.

// PowerShellFetchedContentExecution reports whether the shell call of input
// runs content it fetches from the network (a PowerShell download cradle).
func PowerShellFetchedContentExecution(input Input) bool {
	source := shellCommandText(input)
	if source == "" || len(source) > maxCommandBytes {
		return false
	}
	dialect := input.DialectHint
	if dialect == "" || dialect == DialectNone {
		dialect, _ = chooseRawCommandDialect(input.Tool, input.DialectHint, source)
	}
	return PowerShellFetchedContentExecuted(source, dialect)
}

// PowerShellStatementList reports a shell call whose text is a list of
// several top-level PowerShell statements (a prefix, a trailer, a ; or newline
// separated script), as psparse reads it. A tokenizer that does not read a
// statement list calls such a call partial for that reason alone.
func PowerShellStatementList(input Input) (list bool) {
	defer func() {
		if recover() != nil {
			list = false
		}
	}()
	source := shellCommandText(input)
	if source == "" || len(source) > maxCommandBytes {
		return false
	}
	script, _ := psparse.Parse(source, psparse.Options{Dialect: psparse.DialectUnknown})
	return script != nil && len(script.Diagnostics) == 0 && len(script.Statements) > 1
}

// PowerShellFetchedContentExecuted is PowerShellFetchedContentExecution for a
// command text read in the grammar dialect (PowerShell, cmd.exe, or a POSIX
// shell running a launcher).
func PowerShellFetchedContentExecuted(source string, dialect Dialect) (found bool) {
	defer func() {
		if recover() != nil {
			found = false
		}
	}()
	if len(source) > maxCommandBytes || !mayHoldCradle(source) {
		return false
	}
	if dialect == DialectPOSIX || dialect == DialectNone || dialect == DialectMixed {
		body, bodyDialect, ok := posixSoleHostCallSource(source)
		if !ok {
			return false
		}
		source, dialect = body, bodyDialect
	}
	if dialect != DialectPowerShell && dialect != DialectCMD {
		return false
	}
	if unwrapped, ok := unwrapHostSource(source, dialect, 0); ok {
		if unwrapped.limit {
			return false
		}
		source, dialect = unwrapped.source, unwrapped.dialect
	}
	if dialect != DialectPowerShell {
		return false
	}
	script, _ := psparse.Parse(source, psparse.Options{Dialect: psparse.DialectUnknown})
	if script == nil {
		return false
	}
	analysis := &cradleAnalysis{
		fetched: map[string]bool{},
		clients: map[string]bool{},
	}
	for _, statement := range script.Statements {
		if analysis.statementRuns(statement) {
			return true
		}
	}
	return false
}

// mayHoldCradle is the cheap screen: a cradle runs fetched text through
// Invoke-Expression (or its alias) or a script block built from it. It never
// rejects a text that holds one: an encoded launcher body is decoded after this
// screen, so the encoding switch passes it on.
func mayHoldCradle(source string) bool {
	lower := strings.ToLower(source)
	for _, word := range []string{"iex", "invoke-expression", "scriptblock", "-e", "/c"} {
		if strings.Contains(lower, word) {
			return true
		}
	}
	return false
}

type cradleAnalysis struct {
	// fetched and clients are the variables (lower case) that hold fetched
	// content and a web client object.
	fetched map[string]bool
	clients map[string]bool
}

// statementRuns reports a top-level statement that runs fetched content, and
// records the variables it binds.
func (a *cradleAnalysis) statementRuns(statement psparse.Statement) bool {
	switch typed := statement.(type) {
	case *psparse.Assignment:
		runs := a.statementContainsSink(typed.RHS)
		if name, ok := cradleVariableName(typed.LHS); ok {
			a.fetched[name] = typed.Op == "=" && a.statementFetched(typed.RHS) ||
				typed.Op != "=" && a.fetched[name]
			a.clients[name] = typed.Op == "=" && a.statementIsClient(typed.RHS)
		}
		return runs
	case *psparse.Pipeline:
		return a.pipelineRuns(typed)
	case *psparse.ExprStatement:
		return a.expressionRuns(typed.Expr)
	}
	return false
}

func (a *cradleAnalysis) pipelineRuns(pipeline *psparse.Pipeline) bool {
	for current := pipeline; current != nil; current = current.ChainRHS {
		flow := false
		for _, element := range current.Elements {
			switch typed := element.(type) {
			case *psparse.Command:
				if a.commandRuns(typed, flow) {
					return true
				}
				flow = flow || a.commandFetched(typed)
			case *psparse.ExprStatement:
				if a.expressionRuns(typed.Expr) {
					return true
				}
				flow = flow || a.expressionFetched(typed.Expr)
			}
		}
	}
	return false
}

// statementContainsSink is statementRuns for a statement nested in an
// assignment or parentheses.
func (a *cradleAnalysis) statementContainsSink(statement psparse.Statement) bool {
	switch typed := statement.(type) {
	case *psparse.Pipeline:
		return a.pipelineRuns(typed)
	case *psparse.ExprStatement:
		return a.expressionRuns(typed.Expr)
	case *psparse.Command:
		return a.commandRuns(typed, false)
	}
	return false
}

// commandRuns reports an Invoke-Expression or call-operator command whose
// script comes from fetched content. flow is true when an earlier stage of the
// same pipeline carries fetched content into this command's input.
func (a *cradleAnalysis) commandRuns(command *psparse.Command, flow bool) bool {
	name, named := cradleCommandName(command)
	if named && (name == "iex" || name == "invoke-expression") {
		if flow {
			return true
		}
		for _, element := range command.Elements {
			switch typed := element.(type) {
			case *psparse.Arg:
				if a.expressionFetched(typed.Value) {
					return true
				}
			case *psparse.Parameter:
				if typed.Colon != nil && a.expressionFetched(typed.Colon) {
					return true
				}
			case psparse.Expr:
				if a.expressionFetched(typed) {
					return true
				}
			}
		}
		return false
	}
	if command.InvokeOp == "&" || command.InvokeOp == "." {
		// & ([scriptblock]::Create(<fetched>)) runs the built script block.
		return command.Name != nil && a.scriptBlockOfFetched(command.Name)
	}
	return false
}

// expressionRuns reports [scriptblock]::Create(<fetched>).Invoke() and the
// Invoke-Expression-free forms of the same chain.
func (a *cradleAnalysis) expressionRuns(expression psparse.Expr) bool {
	if invoke, ok := expression.(*psparse.Invoke); ok && strings.EqualFold(invoke.Name, "Invoke") {
		return a.scriptBlockOfFetched(invoke.Target)
	}
	return false
}

// scriptBlockOfFetched reports a script block built from fetched content:
// [scriptblock]::Create(<fetched>), possibly in parentheses.
func (a *cradleAnalysis) scriptBlockOfFetched(expression psparse.Expr) bool {
	switch typed := expression.(type) {
	case *psparse.Paren:
		if pipeline, ok := typed.Inner.(*psparse.Pipeline); ok && len(pipeline.Elements) == 1 {
			if statement, ok := pipeline.Elements[0].(*psparse.ExprStatement); ok {
				return a.scriptBlockOfFetched(statement.Expr)
			}
		}
		if statement, ok := typed.Inner.(*psparse.ExprStatement); ok {
			return a.scriptBlockOfFetched(statement.Expr)
		}
	case *psparse.Invoke:
		if !strings.EqualFold(typed.Name, "Create") {
			return false
		}
		target, ok := typed.Target.(*psparse.TypeExpr)
		if !ok || !strings.HasSuffix(strings.ToLower(target.Name), "scriptblock") {
			return false
		}
		for _, argument := range typed.Args {
			if a.expressionFetched(argument) {
				return true
			}
		}
	}
	return false
}

func (a *cradleAnalysis) statementFetched(statement psparse.Statement) bool {
	switch typed := statement.(type) {
	case *psparse.Pipeline:
		for _, element := range typed.Elements {
			switch stage := element.(type) {
			case *psparse.Command:
				if a.commandFetched(stage) {
					return true
				}
			case *psparse.ExprStatement:
				if a.expressionFetched(stage.Expr) {
					return true
				}
			}
		}
	case *psparse.ExprStatement:
		return a.expressionFetched(typed.Expr)
	case *psparse.Command:
		return a.commandFetched(typed)
	}
	return false
}

// commandFetched reports a command whose output is fetched content: a web
// request that does not write to a file, or any command that takes fetched
// content as an argument.
func (a *cradleAnalysis) commandFetched(command *psparse.Command) bool {
	if name, ok := cradleCommandName(command); ok && cradleFetchCommand(name) {
		return !cradleWritesFile(command)
	}
	if command.Name != nil && a.expressionFetched(command.Name) {
		return true
	}
	for _, element := range command.Elements {
		switch typed := element.(type) {
		case *psparse.Arg:
			if a.expressionFetched(typed.Value) {
				return true
			}
		case *psparse.Parameter:
			if typed.Colon != nil && a.expressionFetched(typed.Colon) {
				return true
			}
		case psparse.Expr:
			if a.expressionFetched(typed) {
				return true
			}
		}
	}
	return false
}

// expressionFetched reports an expression that holds fetched content: it
// contains a download method of a web client, a fetched variable, or a fetching
// command, and derives its value from it.
func (a *cradleAnalysis) expressionFetched(expression psparse.Expr) bool {
	switch typed := expression.(type) {
	case nil:
		return false
	case *psparse.Variable:
		return a.fetched[strings.ToLower(typed.Name)]
	case *psparse.Invoke:
		if cradleDownloadMethod(typed.Name) && a.expressionIsClient(typed.Target) {
			return true
		}
		if a.expressionFetched(typed.Target) {
			return true
		}
		for _, argument := range typed.Args {
			if a.expressionFetched(argument) {
				return true
			}
		}
	case *psparse.Member:
		return a.expressionFetched(typed.Target)
	case *psparse.Paren:
		return a.statementFetched(typed.Inner)
	case *psparse.SubExpr:
		return a.statementsFetched(typed.Statements)
	case *psparse.ArrayExpr:
		return a.statementsFetched(typed.Statements)
	case *psparse.Index:
		return a.expressionFetched(typed.Target) || a.expressionFetched(typed.Index)
	case *psparse.Binary:
		return a.expressionFetched(typed.LHS) || a.expressionFetched(typed.RHS)
	case *psparse.Unary:
		return a.expressionFetched(typed.Operand)
	case *psparse.Convert:
		return a.expressionFetched(typed.Operand)
	case *psparse.ArrayLit:
		for _, element := range typed.Elements {
			if a.expressionFetched(element) {
				return true
			}
		}
	case *psparse.StringLit:
		for _, part := range typed.Parts {
			if part.Expr != nil && a.expressionFetched(part.Expr) {
				return true
			}
		}
	}
	return false
}

func (a *cradleAnalysis) statementsFetched(statements []psparse.Statement) bool {
	for _, statement := range statements {
		if a.statementFetched(statement) {
			return true
		}
	}
	return false
}

func (a *cradleAnalysis) statementIsClient(statement psparse.Statement) bool {
	switch typed := statement.(type) {
	case *psparse.Pipeline:
		return len(typed.Elements) == 1 && a.elementIsClient(typed.Elements[0])
	case *psparse.ExprStatement:
		return a.expressionIsClient(typed.Expr)
	case *psparse.Command:
		return cradleNewWebClient(typed)
	}
	return false
}

func (a *cradleAnalysis) elementIsClient(element psparse.PipelineElement) bool {
	switch typed := element.(type) {
	case *psparse.Command:
		return cradleNewWebClient(typed)
	case *psparse.ExprStatement:
		return a.expressionIsClient(typed.Expr)
	}
	return false
}

// expressionIsClient reports a web client object: (New-Object Net.WebClient),
// [Net.WebClient]::new(), or a variable bound to one.
func (a *cradleAnalysis) expressionIsClient(expression psparse.Expr) bool {
	switch typed := expression.(type) {
	case *psparse.Variable:
		return a.clients[strings.ToLower(typed.Name)]
	case *psparse.Paren:
		return a.statementIsClient(typed.Inner)
	case *psparse.Convert:
		return a.expressionIsClient(typed.Operand)
	case *psparse.Invoke:
		if !strings.EqualFold(typed.Name, "new") {
			return false
		}
		target, ok := typed.Target.(*psparse.TypeExpr)
		return ok && cradleClientType(target.Name)
	}
	return false
}

func cradleVariableName(expression psparse.Expr) (string, bool) {
	variable, ok := expression.(*psparse.Variable)
	if !ok || variable.Splat {
		return "", false
	}
	return strings.ToLower(variable.Name), true
}

// cradleCommandName is the lower-case name of a command without a module
// prefix.
func cradleCommandName(command *psparse.Command) (string, bool) {
	if command.Name == nil {
		return "", false
	}
	name, ok := psparse.LiteralString(command.Name)
	if !ok {
		return "", false
	}
	name = strings.ToLower(name)
	if index := strings.LastIndexAny(name, `\/`); index >= 0 {
		name = name[index+1:]
	}
	return name, true
}

func cradleFetchCommand(name string) bool {
	switch name {
	case "invoke-webrequest", "iwr", "invoke-restmethod", "irm",
		"curl", "curl.exe", "wget", "wget.exe":
		return true
	}
	return false
}

// cradleWritesFile reports a fetch whose body goes to a file, not to the
// output (-OutFile, curl -o/--output).
func cradleWritesFile(command *psparse.Command) bool {
	for _, element := range command.Elements {
		parameter, ok := element.(*psparse.Parameter)
		if !ok {
			continue
		}
		name := strings.ToLower(parameter.Name)
		if name == "o" || name == "output" || (len(name) >= 4 && strings.HasPrefix("outfile", name)) {
			return true
		}
	}
	return false
}

func cradleDownloadMethod(name string) bool {
	switch strings.ToLower(name) {
	case "downloadstring", "downloaddata", "openread",
		"downloadstringtaskasync", "downloaddatataskasync",
		"getstringasync", "getbytearrayasync", "getstreamasync":
		return true
	}
	return false
}

func cradleClientType(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, "webclient") || strings.HasSuffix(lower, "httpclient")
}

// cradleNewWebClient reports New-Object with a web client type name.
func cradleNewWebClient(command *psparse.Command) bool {
	name, ok := cradleCommandName(command)
	if !ok || name != "new-object" {
		return false
	}
	for _, element := range command.Elements {
		switch typed := element.(type) {
		case *psparse.Arg:
			if text, ok := psparse.LiteralString(typed.Value); ok && cradleClientType(text) {
				return true
			}
			if te, ok := typed.Value.(*psparse.TypeExpr); ok && cradleClientType(te.Name) {
				return true
			}
		case *psparse.Parameter:
			if typed.Colon != nil {
				if text, ok := psparse.LiteralString(typed.Colon); ok && cradleClientType(text) {
					return true
				}
			}
		case psparse.Expr:
			if text, ok := psparse.LiteralString(typed); ok && cradleClientType(text) {
				return true
			}
		}
	}
	return false
}
