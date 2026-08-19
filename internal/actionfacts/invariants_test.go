// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

func assertFactsInvariants(t testing.TB, facts Facts) {
	t.Helper()
	normalizedHome, homeOK := normalizeActiveHome(facts.ActiveHome)
	if !homeOK || normalizedHome != facts.ActiveHome {
		t.Fatalf("invalid active home context: %q", facts.ActiveHome)
	}
	normalizedAgentFiles, issue := normalizeActiveAgentFiles(facts.ActiveAgentFiles)
	if issue != "" || !slices.Equal(normalizedAgentFiles, facts.ActiveAgentFiles) {
		t.Fatalf("invalid active agent file context: %q", facts.ActiveAgentFiles)
	}
	normalizedCaseInsensitive, issue := normalizeCaseInsensitiveActiveAgentFiles(
		facts.ActiveAgentFilesCaseInsensitive,
		facts.ActiveAgentFiles,
	)
	if issue != "" || !slices.Equal(
		normalizedCaseInsensitive,
		facts.ActiveAgentFilesCaseInsensitive,
	) {
		t.Fatalf(
			"invalid active agent case metadata: %q",
			facts.ActiveAgentFilesCaseInsensitive,
		)
	}
	commandIDs := make(map[int64]struct{}, len(facts.Commands))
	for _, command := range facts.Commands {
		if command.ID <= 0 {
			t.Fatalf("non-positive command ID: %#v", command)
		}
		if _, exists := commandIDs[command.ID]; exists {
			t.Fatalf("duplicate command ID %d", command.ID)
		}
		commandIDs[command.ID] = struct{}{}
		if len(command.Redirects) > maxRedirectsPerCommand {
			t.Fatalf(
				"command %d has %d redirects, max %d",
				command.ID,
				len(command.Redirects),
				maxRedirectsPerCommand,
			)
		}
		for _, redirect := range command.Redirects {
			if redirect.Target == "" {
				continue
			}
			if !utf8.ValidString(redirect.Target) ||
				strings.IndexByte(redirect.Target, 0) >= 0 ||
				len(redirect.Target) > maxScalarBytes {
				t.Fatalf(
					"invalid redirect target in command %d: %#v",
					command.ID,
					redirect,
				)
			}
		}
		switch command.Kind {
		case CommandKindProcess:
		case CommandKindShellRedirect:
			if command.Executable != "" ||
				command.Program != "" ||
				len(command.Argv) != 0 ||
				len(command.Arguments) != 0 ||
				!command.ArgvComplete ||
				command.Effect != EffectExecute ||
				len(command.Redirects) == 0 {
				t.Fatalf("invalid shell redirect command %d: %#v", command.ID, command)
			}
		default:
			t.Fatalf("invalid command kind in command %d: %#v", command.ID, command)
		}
		if len(command.Executable) > maxScalarBytes {
			t.Fatalf("oversized executable in command %d", command.ID)
		}
		expectedProgram := commandProgramForDialect(
			command.Executable,
			command.Dialect,
		)
		if command.Program != "" && command.Program != expectedProgram {
			t.Fatalf("unstable program in command %d: %#v", command.ID, command)
		}
		if !validDialect(command.Dialect) || command.Dialect == DialectNone ||
			command.Dialect == "" {
			t.Fatalf("invalid command dialect in command %d: %#v", command.ID, command)
		}
		switch command.Effect {
		case EffectExecute, EffectPreview, EffectUncertain:
		default:
			t.Fatalf("invalid command effect in command %d: %#v", command.ID, command)
		}
		if command.Kind == CommandKindProcess &&
			command.ArgvComplete && (command.Executable == "" ||
			len(command.Argv) != len(command.Arguments)) {
			t.Fatalf("invalid complete argv in command %d: %#v", command.ID, command)
		}
		if facts.Authoritative() &&
			command.Kind == CommandKindProcess &&
			command.Program == "" {
			t.Fatalf("authoritative command lacks a program: %#v", command)
		}
		if command.Kind == CommandKindProcess && command.ArgvComplete {
			if issue := validateArgv(command.Argv); issue != "" {
				t.Fatalf("invalid projected argv in command %d: %s (%#v)",
					command.ID, issue, command)
			}
		} else if command.Kind == CommandKindProcess &&
			len(command.Argv) > maxArgvItems {
			t.Fatalf("oversized incomplete argv in command %d", command.ID)
		} else if command.Kind == CommandKindProcess {
			total := 0
			for _, argument := range command.Argv {
				if len(argument) > maxScalarBytes {
					t.Fatalf("oversized incomplete argument in command %d", command.ID)
				}
				total += len(argument)
			}
			if total > maxArgvBytes {
				t.Fatalf("oversized incomplete argv bytes in command %d", command.ID)
			}
		}
	}
	for _, command := range facts.Commands {
		if command.ParentCommandID != 0 {
			if command.ParentCommandID == command.ID {
				t.Fatalf("command %d is its own parent", command.ID)
			}
			if _, ok := commandIDs[command.ParentCommandID]; !ok {
				t.Fatalf("command %d has missing parent %d", command.ID, command.ParentCommandID)
			}
		}
	}
	for _, fact := range facts.Paths {
		assertKnownCommandID(t, commandIDs, fact.CommandID)
		if len(fact.Value) > maxScalarBytes {
			t.Fatalf("oversized path fact: %#v", fact)
		}
	}
	for _, fact := range facts.Network {
		assertKnownCommandID(t, commandIDs, fact.CommandID)
		if len(fact.Host) > maxScalarBytes || len(fact.Scheme) > maxScalarBytes ||
			fact.Port < 0 || fact.Port > 65535 {
			t.Fatalf("invalid network fact: %#v", fact)
		}
	}
	for _, fact := range facts.DataFlows {
		assertKnownCommandID(t, commandIDs, fact.FromCommandID)
		assertKnownCommandID(t, commandIDs, fact.ToCommandID)
	}
}

func assertKnownCommandID(t testing.TB, commandIDs map[int64]struct{}, id int64) {
	t.Helper()
	if id == 0 {
		return
	}
	if _, ok := commandIDs[id]; !ok {
		t.Fatalf("fact references missing command ID %d", id)
	}
}
