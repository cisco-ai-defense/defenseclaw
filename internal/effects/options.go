// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"encoding/json"
)

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
// AccountRecord is trusted account data from the hook's counted identity lookup.
type AccountRecord struct {
	Home  string
	Shell string
}

type Options struct {
	Flavor Flavor
	// Dialect forces the shell grammar; DialectNone infers it.
	Dialect Dialect
	Home    string
	CWD     string
	Account AccountRecord
	// Login is the active account's login name: ~Login names the account's
	// home (Home as the call starts, whatever HOME the call later sets), as the
	// shell's passwd lookup does (rel-1-0-10:GAP-1678). It is matched without
	// case, as a directory (AD, sssd) login resolves and as the ~<login> twin
	// of the hook reads it (GAP-2378). Empty: ~name is never the active account.
	Login string
	// Accounts maps another account's login name to its home, from a lookup
	// the caller vouches for (passwd, the managed identity map). A ~name not
	// here is unknown (rel-1-0-10:GAP-1677, GAP-0898).
	Accounts map[string]string
	// Drive is the current Windows drive letter ("C") used to place a Windows
	// path that names no drive of its own. Ignored for POSIX.
	Drive string
	// Env holds only trusted, resolved environment values a caller vouches for.
	// A variable expansion whose name is not here is dynamic_expansion.
	Env map[string]string
	// CaseInsensitive folds path case for Key() and placement (Windows always,
	// macOS defaults). Derived by the caller, never from GOOS here.
	CaseInsensitive bool
	// BSDUserland: the host runs the BSD (macOS) tools. A program named by its
	// system path (/bin/cp, /usr/bin/tee, ...) is then read with the BSD row of
	// the programs whose flags differ from GNU coreutils (cp, mv, ln, rm, unlink,
	// install, tee): a flag the BSD tool rejects is unaccounted (rel-1-0-10
	// GAP-0219). A bare name keeps the GNU row (gnubin may be first on PATH).
	// Derived by the caller (the host is macOS), never from GOOS here. Ignored
	// for the Windows flavor.
	BSDUserland bool
	// SessionFiles maps an absolute path to the text the session saw written to
	// it by an earlier Write/Edit in the same session (review P2). A script run
	// from such a path can be unwrapped one level.
	SessionFiles map[string]string
	// MaxEffects bounds the output; zero uses the package default.
	MaxEffects int
	// loginHome is the passwd home ~Login names: Home as the walk began. The
	// walker sets it once, so a call that assigns HOME moves ~ and ~/ but not
	// ~Login (bash reads ~login from the password database, never from HOME).
	loginHome string
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
	// maxNestedDepth is how many levels of nested script text are lowered
	// (sh -c inside eval inside source ...). Each level is counted work under
	// walkWorkBudget; past it the call has a nesting_limit unknown (DET111 D1:
	// a nested body is read, not judged as another spelling).
	maxNestedDepth   = 4
	maxDataText      = 8 << 10
	maxSpellingBytes = 4 << 10
	maxMCPDepth      = 6
	maxMCPNodes      = 256
)
