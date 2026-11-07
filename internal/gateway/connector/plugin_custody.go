// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"errors"
	"fmt"
	"strings"
)

// ErrPluginFolderCustody marks the refusal to publish a managed plugin because
// another account can write into its folder chain or onto the plugin file. The
// error text names the folders and the one command that clears the refusal, or
// the link that must be replaced by hand, so a caller must not add the generic
// "close the agent" advice (GAP-0730).
var ErrPluginFolderCustody = errors.New("plugin folder is writable by another account")

// pluginCustodyError is cause (the first refusal the directory walk met) plus
// every element the same walk refuses. fix is the shell command that repairs
// what a command can repair (and nothing else); manual is what only a person
// can do, as prose: replace a link, give a path back to this account.
type pluginCustodyError struct {
	cause   error
	failing []string
	fix     string
	manual  string
}

func (e *pluginCustodyError) Error() string { return e.CauseText() + e.repairText() }

// CauseText is the refusal without its repair: the cause and every element the
// walk refuses.
func (e *pluginCustodyError) CauseText() string {
	text := fmt.Sprintf("%v", e.cause)
	if len(e.failing) > 1 {
		text += "; every folder or file to fix, outermost first: " + strings.Join(e.failing, ", ")
	}
	return text
}

// Repair is the command that repairs what a command can repair and the steps
// only a person can take, either of which may be empty.
func (e *pluginCustodyError) Repair() (fix, manual string) { return e.fix, e.manual }

// repairText is what Error appends to CauseText.
func (e *pluginCustodyError) repairText() string {
	var text string
	if e.fix != "" {
		text += "; fix: " + e.fix
	}
	if e.manual != "" {
		if e.fix != "" {
			text += "; then by hand: " + e.manual
		} else {
			text += "; by hand: " + e.manual
		}
	}
	return text
}

// RepairedRefusal is an error that carries its repair apart from its cause, so
// a caller that shows the two in separate fields never has to find the repair
// in the error text: a folder or link may be named with any text, including
// the words the text puts before the repair.
type RepairedRefusal interface {
	error
	CauseText() string
	Repair() (fix, manual string)
}

func (e *pluginCustodyError) Unwrap() []error { return []error{e.cause, ErrPluginFolderCustody} }

// PluginFolderRefusedBeforeChange reports whether err is the custody refusal
// itself, reached through single wrappers only. Setup raises it before it
// writes the plugin, the backup receipt or the lock, so the connector keeps
// the registration it had. A refusal joined with another failure (a
// rollback that met the same folder) is not the refusal alone: the other
// failure may have left a change behind, and errors.Is would still match
// (GAP-0798).
func PluginFolderRefusedBeforeChange(err error) bool {
	for ; err != nil; err = errors.Unwrap(err) {
		if _, ok := err.(*pluginCustodyError); ok {
			return true
		}
	}
	return false
}
