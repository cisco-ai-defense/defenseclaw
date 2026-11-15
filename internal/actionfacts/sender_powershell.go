// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/psparse"
)

// The sender reader's PowerShell and cmd reading (GAP-0722). A call whose
// projection is not complete has its PowerShell source read with the same
// PowerShell parser the effects reader uses: each command it finds (a call
// operator & or . too) is classified like a POSIX call of its own words. A
// source the parser gave up on, a command name that is not a literal and a
// cmd source the projection did not read in full are Unreadable (the unknown
// tier): a partial parse never proves "no sender".

// readPowerShellSender reads one PowerShell source text for the unprojected
// reader.
func readPowerShellSender(text string) syntaxSenderResult {
	var res syntaxSenderResult
	if c := shellBoundCap(text); c != 0 {
		res.unknown = true
		res.hitCap(c)
		return res
	}
	script, err := psparse.Parse(text, psparse.Options{Dialect: psparse.DialectUnknown})
	if err != nil || script == nil || len(script.Diagnostics) > 0 {
		res.unknown = true
	}
	if script == nil {
		return res
	}
	psparse.WalkCommands(script, func(command *psparse.Command) {
		if len(res.calls) >= maxSenderOccurrences {
			res.unknown = true
			res.hitCap(boundedItems)
			return
		}
		name, ok := psparse.LiteralString(command.Name)
		if !ok || strings.TrimSpace(name) == "" {
			res.unknown = true
			return
		}
		var words []string
		dynamic := map[int]bool{}
		add := func(expr psparse.Expr) {
			if value, ok := psparse.LiteralString(expr); ok {
				words = append(words, value)
				return
			}
			dynamic[len(words)] = true
			words = append(words, "")
		}
		for _, element := range command.Elements {
			switch e := element.(type) {
			case *psparse.Parameter:
				words = append(words, e.Raw)
				if e.Colon != nil {
					add(e.Colon)
				}
			case *psparse.Arg:
				add(e.Value)
			}
		}
		if command.StopParsing != "" {
			words = append(words, strings.Fields(command.StopParsing)...)
		}
		fed := false
		for _, redirect := range command.Redirs {
			if redirect.Op == "<" {
				fed = true
			}
		}
		occurrence := senderOccurrence{name: senderProgramName(name), args: words, fed: fed}
		if len(dynamic) > 0 {
			occurrence.dynamic = dynamic
		}
		res.calls = append(res.calls, occurrence)
	})
	return res
}
