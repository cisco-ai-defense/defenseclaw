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
// every element the same walk refuses and the command that fixes them all.
type pluginCustodyError struct {
	cause   error
	failing []string
	fix     string
}

func (e *pluginCustodyError) Error() string {
	if len(e.failing) > 1 {
		return fmt.Sprintf("%v; every folder or file to fix, outermost first: %s; fix: %s", e.cause, strings.Join(e.failing, ", "), e.fix)
	}
	return fmt.Sprintf("%v; fix: %s", e.cause, e.fix)
}

func (e *pluginCustodyError) Unwrap() []error { return []error{e.cause, ErrPluginFolderCustody} }
