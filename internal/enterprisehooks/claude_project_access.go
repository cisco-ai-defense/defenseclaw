// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"os"
)

// A refused access check removes the entire project, including local-scope
// definitions already parsed from .claude.json. A missing .mcp.json keeps
// local-scope definitions. Other read failures retain the account-wide
// unreadable marker so a stale inventory cannot be published.
type claudeProjectReadDecision uint8

const (
	claudeProjectKeep claudeProjectReadDecision = iota
	claudeProjectRefused
	claudeProjectUnreadable
)

// Only a project path check or open that returns ERROR_ACCESS_DENIED under
// the validated user token may carry this marker. Token and session failures
// must leave the whole account unreadable.
var errClaudeProjectAccessDenied = errors.New("Claude Code project access denied")

func decideClaudeProjectRead(accessErr, readErr error) claudeProjectReadDecision {
	if accessErr != nil {
		if errors.Is(accessErr, errClaudeProjectAccessDenied) {
			return claudeProjectRefused
		}
		return claudeProjectUnreadable
	}
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return claudeProjectUnreadable
	}
	return claudeProjectKeep
}
