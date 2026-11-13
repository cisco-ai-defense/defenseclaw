// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// A credential literal in a tool call is one of two things. It is data the
// action only looks at (a grep, a read, a pattern in a search) or it is data
// the action hands on: written into a file, stored in a memory entity or a
// database row, set in a command's environment. The first is audit
// telemetry. The second is a live credential leaving the model's context for
// a place that keeps it, so it is an alert. It is never a block here: that
// needs proof of where the credential goes, which the risk-pair check
// (trustedActionContentFindingHasRiskPair) already grades as enforceable.

// trustedActionCredentialLiteralRule reports a finding that is a credential
// value written out in the call, as opposed to a rule about intent or a
// path.
func trustedActionCredentialLiteralRule(finding RuleFinding) bool {
	return strings.HasPrefix(finding.RuleID, "SEC-") &&
		hasTag(finding.Tags, "credential") &&
		!hasTag(finding.Tags, "intent")
}

// trustedActionPersistsCredentialLiteral reports whether the action hands the
// literals in its arguments to a file, a store or a process, and does not
// merely look at them.
func trustedActionPersistsCredentialLiteral(facts actionfacts.Facts) bool {
	tool := strings.ToLower(strings.TrimSpace(facts.Tool))
	switch {
	case isWriteToolName(tool):
		// A write whose every target is a test, fixture or example file keeps
		// sample credentials by design.
		wrote := false
		for _, candidate := range facts.Paths {
			if candidate.Access != actionfacts.PathAccessWrite &&
				candidate.Access != actionfacts.PathAccessAppend {
				continue
			}
			wrote = true
			if !trustedActionFixtureTarget(semanticPathValue(candidate)) {
				return true
			}
		}
		return !wrote
	case strings.HasPrefix(tool, "mcp__") || strings.HasPrefix(tool, "mcp."):
		return trustedActionMutatingToolName(tool) && !trustedActionCredentialStoreTool(tool)
	case trustedActionSendToolName(tool):
		// A send tool hands its message to someone else.
		return !trustedActionCredentialStoreTool(tool)
	}
	return trustedActionShellPersistsLiteral(facts)
}

// trustedActionMutatingToolName reports an MCP tool whose name says it
// writes, stores or runs something. A tool whose name carries no such verb
// (read_query, list_directory, search_nodes, get_secret) is read-only here.
func trustedActionMutatingToolName(tool string) bool {
	leaf := tool
	if i := strings.LastIndex(leaf, "__"); i >= 0 {
		leaf = leaf[i+2:]
	} else if i := strings.LastIndexByte(leaf, '.'); i >= 0 {
		leaf = leaf[i+1:]
	}
	for _, word := range strings.FieldsFunc(leaf, func(r rune) bool {
		return r == '_' || r == '-' || r == '.' || r == ' '
	}) {
		switch word {
		case "write", "create", "add", "insert", "update", "set", "put", "store", "save", "append",
			"upsert", "post", "send", "publish", "execute", "exec", "run", "push", "commit", "upload",
			"patch", "edit", "replace", "remember", "memorize", "record", "note":
			return true
		case "read", "get", "list", "search", "find", "fetch", "view", "describe", "show", "query",
			"select", "open", "stat", "check", "lookup", "browse":
			return false
		}
	}
	return false
}

// trustedActionShellPrinters are programs that print their operands or their
// input unchanged.
var trustedActionShellPrinters = map[string]bool{
	"echo": true, "printf": true, "cat": true, "print": true, "write-output": true, "write-host": true,
	"out-string": true, "type": true, "tee": true,
}

// trustedActionShellFileWriters are programs whose job is to put their input
// or an operand into a file.
var trustedActionShellFileWriters = map[string]bool{
	"tee": true, "set-content": true, "add-content": true, "out-file": true, "sc": true, "ac": true,
}

// trustedActionShellPersistsLiteral reports an authoritative shell action that
// writes into a file: a standard-output redirect, or a program that writes
// its operand (tee, Set-Content). Using a credential (an Authorization
// header, a connection string, an environment variable for a build) is not
// persisting it; where it goes then is the egress proof's call
// (trustedActionContentFindingHasRiskPair). The target must not be a test,
// fixture or example file, or a discard device.
func trustedActionShellPersistsLiteral(facts actionfacts.Facts) bool {
	if !facts.Authoritative() {
		return false
	}
	switch facts.Parse.Dialect {
	case actionfacts.DialectPOSIX, actionfacts.DialectPowerShell,
		actionfacts.DialectCMD, actionfacts.DialectMixed:
	default:
		// A structured tool (Read, Grep, Glob, a fetch) is not shell text.
		return false
	}
	writable := func(target string) bool {
		return target != "" && !trustedActionDiscardTarget(target) && !trustedActionFixtureTarget(target)
	}
	for _, command := range facts.Commands {
		if !trustedActionExecutingCommand(facts, command.ID) {
			continue
		}
		program := strings.ToLower(path.Base(strings.ReplaceAll(command.Program, `\`, "/")))
		// A redirect files what the program prints. That is the literal only
		// for a program that prints its operands or its input: curl > out
		// files the response, not the key in its URL.
		printsLiteral := trustedActionShellPrinters[program] || command.LiteralStdin != ""
		for _, redirect := range command.Redirects {
			// Only standard output carries what a program prints; 2> gets none
			// of it.
			if printsLiteral && redirect.FD == 1 &&
				(redirect.Access == actionfacts.PathAccessWrite ||
					redirect.Access == actionfacts.PathAccessAppend) && writable(redirect.Target) {
				return true
			}
		}
		if !trustedActionShellFileWriters[program] {
			continue
		}
		for _, argument := range command.Arguments {
			if !strings.HasPrefix(argument.Value, "-") && writable(argument.Value) {
				return true
			}
		}
	}
	return false
}

func trustedActionDiscardTarget(target string) bool {
	switch strings.ToLower(strings.TrimSpace(target)) {
	case "/dev/null", "/dev/stdout", "/dev/stderr", "nul", "&1", "&2":
		return true
	}
	return false
}

// trustedActionFixtureTarget reports a path that holds test, fixture, example
// or template content, where a credential-shaped value is sample data.
func trustedActionFixtureTarget(p string) bool {
	p = strings.ToLower(strings.ReplaceAll(p, `\`, "/"))
	for _, dir := range []string{
		"/test/", "/tests/", "/__tests__/", "/spec/", "/specs/", "/fixtures/", "/fixture/",
		"/testdata/", "/mocks/", "/__mocks__/", "/examples/", "/example/", "/samples/", "/sample/",
		"/testing/", "/e2e/", "/cypress/",
	} {
		if strings.Contains(p, dir) || strings.HasPrefix(p, dir[1:]) {
			return true
		}
	}
	base := path.Base(p)
	for _, marker := range []string{
		"_test.", ".test.", ".spec.", "test_", "conftest", ".example", ".sample", "template",
		".dist", "example.", "sample.", "fixture",
		".j2", ".jinja", ".tmpl", ".tpl", ".erb", ".mustache", ".hbs",
	} {
		if strings.Contains(base, marker) {
			return true
		}
	}
	return false
}

// trustedActionCredentialStoreTool reports a tool whose job is to keep a
// credential: save_password, store_credential, vault.write, keychain set.
// Handing it a credential is the use it is for.
func trustedActionCredentialStoreTool(tool string) bool {
	leaf := tool
	if i := strings.LastIndex(leaf, "__"); i >= 0 {
		leaf = leaf[i+2:]
	} else if i := strings.LastIndexByte(leaf, '.'); i >= 0 {
		leaf = leaf[i+1:]
	}
	server := strings.TrimPrefix(tool, "mcp__")
	if i := strings.Index(server, "__"); i >= 0 {
		server = server[:i]
	}
	for _, name := range []string{leaf, server} {
		for _, word := range strings.FieldsFunc(name, func(r rune) bool {
			return r == '_' || r == '-' || r == '.' || r == ' '
		}) {
			switch word {
			case "password", "passwords", "credential", "credentials", "vault", "keychain", "keyring",
				"secretsmanager", "1password", "bitwarden", "lastpass", "keepass":
				return true
			}
		}
	}
	return false
}
