// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"bytes"
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

// The kinds of change the guardian names for a protected element it put back,
// read from the element before and after the repair.
const (
	// HookChangeDeleted is an element that was missing or had material
	// removed from it.
	HookChangeDeleted = "deleted"
	// HookChangeAppended is an element that held material the render does not.
	HookChangeAppended = "appended"
	// HookChangeEdited is an element whose material was changed.
	HookChangeEdited = "edited"
)

// KnownHookChange says whether name is a change kind the guardian names. A
// worker runs as the user, so a kind it reports is kept only in this form.
func KnownHookChange(name string) bool {
	return name == HookChangeDeleted || name == HookChangeAppended || name == HookChangeEdited
}

// ClassifyHookElementChange names what happened to an element that was put
// back: before is its content when the repair began (existed says it was
// there), after is its content when the repair ended. A file that was missing,
// or that lost lines, was deleted from; a file that gained lines or bytes was
// appended to; anything else was edited. The repair put back what the file
// lacked or took away what it held in excess, which is what names the change.
func ClassifyHookElementChange(before []byte, existed bool, after []byte) string {
	switch {
	case !existed:
		return HookChangeDeleted
	case bytes.Equal(before, after):
		return HookChangeEdited
	case len(before) < len(after) && (bytes.HasPrefix(after, before) || bytes.HasSuffix(after, before)):
		return HookChangeDeleted
	case len(before) > len(after) && (bytes.HasPrefix(before, after) || bytes.HasSuffix(before, after)):
		return HookChangeAppended
	}
	// A repair that only added lines undid a deletion and one that only took
	// lines away undid an append; one that did a good deal more of the one
	// than the other (a config reset to a stub) did the same. Lines swapped
	// for lines are an edit.
	lost, gained := lineDifference(before, after)
	switch {
	case gained > 0 && gained >= 2*lost:
		return HookChangeDeleted
	case lost > 0 && lost >= 2*gained:
		return HookChangeAppended
	}
	return HookChangeEdited
}

// lineDifference counts the lines before has that after lacks (lost by the
// repair) and the lines after has that before lacks (gained by it).
func lineDifference(before, after []byte) (lost, gained int) {
	counts := map[string]int{}
	for _, line := range strings.Split(string(before), "\n") {
		counts[line]++
	}
	for _, line := range strings.Split(string(after), "\n") {
		if counts[line] > 0 {
			counts[line]--
		} else {
			gained++
		}
	}
	for _, left := range counts {
		lost += left
	}
	return lost, gained
}
