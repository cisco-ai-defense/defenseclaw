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

func (e *pluginCustodyError) Error() string {
	text := fmt.Sprintf("%v", e.cause)
	if len(e.failing) > 1 {
		text += "; every folder or file to fix, outermost first: " + strings.Join(e.failing, ", ")
	}
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

func (e *pluginCustodyError) Unwrap() []error { return []error{e.cause, ErrPluginFolderCustody} }
