// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package shellparse provides the full shell parser shared by hook command
// proofs and per-command policy evaluation.
package shellparse

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Parse reads a command with the same Bash-then-POSIX grammar used for hook
// command proofs. Callers bound their inputs before parsing.
func Parse(command string) (*syntax.File, bool) {
	for _, variant := range []syntax.LangVariant{syntax.LangBash, syntax.LangPOSIX} {
		file, err := syntax.NewParser(syntax.Variant(variant)).Parse(strings.NewReader(command), "")
		if err == nil {
			return file, true
		}
	}
	return nil, false
}
