// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import "encoding/json"

// Call is one normalized tool invocation handed to Extract. It is the output
// of Normalize for the connector surfaces; callers may also build it directly.
type Call struct {
	Surface Surface
	Tool    string
	// Command is the raw shell/PowerShell/cmd text for a shell surface.
	Command string
	// Args is the JSON argument object for a file/patch/MCP surface.
	Args json.RawMessage
	// Argv is a structured argv, used for an argv surface.
	Argv []string
	// Workdir is the per-call working directory the connector supplied (Codex
	// workdir, Cursor cwd); relative targets resolve under it (review R3-10).
	Workdir string
}

// Options carries everything that is otherwise OS- or context-dependent, as
// explicit inputs, so Extract stays pure and testable anywhere.
type Options struct {
	Flavor Flavor
	// Dialect forces the shell grammar; DialectNone infers it.
	Dialect Dialect
	Home    string
	CWD     string
	// Drive is the current Windows drive letter ("C") used to place a Windows
	// path that names no drive of its own. Ignored for POSIX.
	Drive string
	// Env holds only trusted, resolved environment values a caller vouches for.
	// A variable expansion whose name is not here is dynamic_expansion.
	Env map[string]string
	// CaseInsensitive folds path case for Key() and placement (Windows always,
	// macOS defaults). Derived by the caller, never from GOOS here.
	CaseInsensitive bool
	// SessionFiles maps an absolute path to the text the session saw written to
	// it by an earlier Write/Edit in the same session (review P2). A script run
	// from such a path can be unwrapped one level.
	SessionFiles map[string]string
	// MaxEffects bounds the output; zero uses the package default.
	MaxEffects int
}

func (o Options) flavor() Flavor {
	if o.Flavor == FlavorWindows {
		return FlavorWindows
	}
	return FlavorPOSIX
}

func (o Options) maxEffects() int {
	if o.MaxEffects > 0 {
		return o.MaxEffects
	}
	return defaultMaxEffects
}

const (
	defaultMaxEffects = 256
	maxNestedDepth    = 1 // one unwrapped level of nested script text (lead)
	maxDataText       = 8 << 10
	maxSpellingBytes  = 4 << 10
	maxMCPDepth       = 6
	maxMCPNodes       = 256
)
