// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"path/filepath"
	"regexp"
	"strings"
)

// The protected elements of a target hook install, as the guardian counts a
// restore: it reports an element that did not match what DefenseClaw renders
// before a repair and matches it after (GAP-0754). A write to a file the agent
// also writes for its own settings is not a restore, so the evidence is the
// element and never the file.
const (
	// HookElementEntry is the DefenseClaw hook entry in the agent config.
	HookElementEntry = "hook entry"
	// HookElementRuntime is the hook runtime as a whole: a fault no single
	// runtime file owns (the contract lock, the fail mode the hooks were
	// rendered for, the render itself).
	HookElementRuntime = "hook runtime files"
	// hookElementFilePrefix starts the name of a runtime file element. Each
	// hook runtime file DefenseClaw renders in the data folder of the account
	// (the hook script, a shared script, a runtime record, the token file, a
	// managed plugin) is an element of its own: a repair that puts the hook
	// script back while another runtime file stays broken has restored the
	// script.
	hookElementFilePrefix = "hook runtime file "
)

// hookElementFileName is what a runtime file element may be named after: the
// base name of a file DefenseClaw renders.
var hookElementFileName = regexp.MustCompile(`^[A-Za-z0-9._@+-]{1,96}$`)

// hookRuntimeFileElement names the element of the runtime file at path.
func hookRuntimeFileElement(path string) string {
	return hookElementFilePrefix + filepath.Base(path)
}

// KnownHookElement says whether name is a protected element name the
// guardian recognizes. A worker runs as the user, so a name it reports is
// kept only in this form.
func KnownHookElement(name string) bool {
	if name == HookElementEntry || name == HookElementRuntime {
		return true
	}
	file, ok := strings.CutPrefix(name, hookElementFilePrefix)
	return ok && file != "." && file != ".." && hookElementFileName.MatchString(file)
}
