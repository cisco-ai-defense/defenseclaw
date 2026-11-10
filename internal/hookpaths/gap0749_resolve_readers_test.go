// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// gap0749ResolveReaders reads command the way Resolve reads the command of a
// Bash tool call, without Resolve's file system evidence: every reader that
// takes the command text (and so reads its argv by position), in the dialect
// the hook client selects (hookShellDialect), whatever the host. A bounded
// sweep (race build, native Windows) reads the forms it does not run through
// Resolve here, so a panic in a Resolve-only reader (the cp and mv
// destination readers, the concrete protected-write reading, the link walk)
// is found on every form, not on a sample (GAP-0749, review round 2).
func gap0749ResolveReaders(command, cwd, home string) {
	dialect := hookShellDialect("", "Bash")
	_ = actionfacts.CommandTextOverLimit(command)
	shellparse.TooDeep(command)
	BoundCommandOperands(command, cwd, home)
	ActionCommandAuditReasonWithDialect(command, cwd, home, dialect)
	MayNameState(command)
	StateNamingReading(command, home, false)
	if twin, _, ok := actionfacts.ActiveUserTildeTwin(command, home, clientLogin()); ok {
		command = twin
	}
	var concrete actionConcreteOperands
	actionConcreteProtectedWriteOnWithOperands(command, cwd, home, false, nil, &concrete)
	actionClientProvedSafeVariableTargetsForHook(command, cwd, home)
	actionClientVariableWriteCandidate(command, home)
	ActionCommandDecision(command, cwd, home)
	actionClientProvedOverwrittenRedirect(command, cwd, home)
	actionClientLoopCopyDestinationProtected(command, cwd, home)
	if NoDereferenceTouchShape(command, cwd, home) {
		noDereferenceTouchStatus(command, cwd, home)
	}
	fallback := actionfacts.Input{Tool: "Bash", Command: command, CWD: cwd, ActiveHome: home}
	fallbackFacts := actionfacts.Analyze(fallback)
	if twin, ok := actionfacts.OverLimitCommandBoundedTwin(fallback, fallbackFacts); ok {
		fallback, fallbackFacts = twin, actionfacts.Analyze(twin)
	}
	simples := actionfacts.SimpleCommands(fallback, fallbackFacts)
	plainMoveDestinationsWithStatements(fallback, fallbackFacts, simples)
	straightLineReadings(fallback, command)
	callPastArgvBound(command)
	ShellWriteOperands(command, cwd, home)
	shellWriteOperands(command, cwd, home, KnownUser{})
	knownStateOperands(command, cwd, home)
	LiteralWriteOperands(command, cwd, home)
	AdjacentAssignedWriteOperands(command, cwd, home)
	DeclaredRedirectWriteOperands(command, cwd, home)
	BoundedShellWriteOperands(command, cwd, home)
	QuotedDynamicCopyDestinations(command, cwd, home)
	BoundedLoopCopyDestinations(command, cwd, home)
	CopySourceGlobDestinations(command, cwd, home, nil)
	BoundedGlobLoopCopyDestinations(command, cwd, home, nil)
	stateTreeNameFacts(fallbackFacts, home)
	if strings.Contains(command, "%") {
		StateRootSiblingsForFinds(home, fallbackFacts)
	}
	sourceFacts := map[string]string{}
	ShellDirectoryWriteOperands(command, cwd, home, sourceFacts, true, false)
	readings := []string{command}
	if wrapped, ok := actionfacts.WrapperUnwrapTwin(command); ok && wrapped != command {
		readings = append(readings, wrapped)
		twin := fallback
		twin.Command = wrapped
		actionfacts.Analyze(twin)
		ShellWriteOperands(wrapped, cwd, home)
		LiteralWriteOperands(wrapped, cwd, home)
		ShellDirectoryWriteOperands(wrapped, cwd, home, sourceFacts, true, false)
	}
	for _, reading := range readings {
		for _, twin := range actionfacts.DynamicOperandTwins(reading, home) {
			if twin == reading {
				continue
			}
			readingInput := fallback
			readingInput.Command = twin
			actionfacts.Analyze(readingInput)
			ShellWriteOperands(twin, cwd, home)
			LiteralWriteOperands(twin, cwd, home)
			ShellDirectoryWriteOperands(twin, cwd, home, sourceFacts, true, false)
			commandLinksWithFacts(twin, cwd, home, sourceFacts, true)
		}
	}
	commandLinksWithFacts(command, cwd, home, sourceFacts, true)
	for _, simple := range simples {
		if simple.EvaluationFailure == "" && simple.Text != command {
			commandLinksWithFacts(simple.Text, simple.CWD, home, sourceFacts, true)
		}
	}
	SafeShellRedirectOccurrencesWithFacts(command, cwd, home, sourceFacts)
	actionGlobFacts(command, cwd, home)
	LinkWalkFacts(command, cwd, home)
}

// gap0749ResolveReaderCalls is every function resolveConnector calls with the
// command text, and the readers of gap0749ResolveReaders that run it.
// TestGAP0749ResolveReadersCoverResolve fails when the two differ.
var gap0749ResolveReaderCalls = []string{
	"ActionCommandAuditReasonWithDialect", "ActionCommandDecision", "AdjacentAssignedWriteOperands",
	"BoundCommandOperands", "BoundedGlobLoopCopyDestinations", "BoundedLoopCopyDestinations", "BoundedShellWriteOperands",
	"CopySourceGlobDestinations", "DeclaredRedirectWriteOperands", "LinkWalkFacts", "LiteralWriteOperands",
	"MayNameState", "NoDereferenceTouchShape", "QuotedDynamicCopyDestinations",
	"SafeShellRedirectOccurrencesWithFacts", "ShellDirectoryWriteOperands", "ShellWriteOperands",
	"StateNamingReading", "actionClientLoopCopyDestinationProtected", "actionClientProvedOverwrittenRedirect",
	"actionClientProvedSafeVariableTargetsForHook", "actionClientVariableWriteCandidate",
	"actionConcreteProtectedWriteOnWithOperands", "actionGlobFacts", "actionfacts.ActiveUserTildeTwin",
	"actionfacts.Analyze", "actionfacts.CommandTextOverLimit", "actionfacts.DynamicOperandTwins", "actionfacts.OverLimitCommandBoundedTwin",
	"actionfacts.SimpleCommands", "actionfacts.WrapperUnwrapTwin",
	"callPastArgvBound", "clientStatementBudgetExceeded", "commandLinksWithFacts", "knownStateOperands", "noDereferenceTouchStatus",
	"plainMoveDestinationsWithStatements", "shellWriteOperands", "shellparse.TooDeep", "straightLineReadings",
}

// TestGAP0749ResolveReadersCoverResolve: the argv readers a bounded sweep
// runs on the forms it does not send through Resolve are the readers
// resolveConnector runs. A reader added to resolveConnector must be added to
// gap0749ResolveReaders (and the list above) before this passes, so a bounded
// sweep cannot fall behind Resolve. clientStatementBudgetExceeded only
// counts statements of the facts and is not an argv reader.
func TestGAP0749ResolveReadersCoverResolve(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "hookpaths.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	commandNames := []string{"command", "wrapped", "reading", "fallback", "twinInput", "readingInput"}
	called := map[string]bool{}
	found := false
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "resolveConnector" {
			continue
		}
		found = true
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			takes := false
			for _, arg := range call.Args {
				if id, ok := arg.(*ast.Ident); ok && slices.Contains(commandNames, id.Name) {
					takes = true
				}
			}
			if !takes {
				return true
			}
			switch fun := call.Fun.(type) {
			case *ast.Ident:
				if fun.Name != "append" {
					called[fun.Name] = true
				}
			case *ast.SelectorExpr:
				if pkg, ok := fun.X.(*ast.Ident); ok && pkg.Name != "strings" {
					called[pkg.Name+"."+fun.Sel.Name] = true
				}
			}
			return true
		})
	}
	if !found {
		t.Fatal("resolveConnector is not in hookpaths.go")
	}
	for name := range called {
		if !slices.Contains(gap0749ResolveReaderCalls, name) {
			t.Errorf("resolveConnector reads the command with %s; add it to gap0749ResolveReaders and gap0749ResolveReaderCalls", name)
		}
	}
	for _, name := range gap0749ResolveReaderCalls {
		if !called[name] {
			t.Errorf("gap0749ResolveReaders runs %s, which resolveConnector no longer calls with the command: drop it", name)
		}
	}
}
