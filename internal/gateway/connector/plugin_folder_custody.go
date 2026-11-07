// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import "errors"

// ErrAgentFolderCustody marks a setup refusal because a folder on the path of
// the agent's plugin (or the plugin file) can be written by another account.
// The folder is the one the user fixes first, and the error names the one
// command that fixes it (GAP-0730, GAP-0731). It is a permission problem
// of that folder, never a reason to close the agent or run an upgrade.
var ErrAgentFolderCustody = errors.New("agent plugin folder is writable by another account")

// agentFolderCustodyError is cause plus the command that removes it. Setup,
// doctor and a gateway start print the same folder and the same command.
type agentFolderCustodyError struct {
	cause error
	fix   string
}

func (e agentFolderCustodyError) Error() string { return e.cause.Error() + "; fix: " + e.fix }

func (e agentFolderCustodyError) Unwrap() []error { return []error{ErrAgentFolderCustody, e.cause} }
