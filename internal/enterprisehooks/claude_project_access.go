// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"os"
)

// A refused project path check removes the entire project, including
// local-scope definitions already parsed from .claude.json. A missing
// .mcp.json keeps local-scope definitions. File read failures retain the
// account-wide unreadable marker so a stale inventory cannot be published.
type claudeProjectReadDecision uint8

const (
	claudeProjectKeep claudeProjectReadDecision = iota
	claudeProjectRefused
	claudeProjectUnreadable
)

func decideClaudeProjectRead(refusalErr, readErr error) claudeProjectReadDecision {
	if refusalErr != nil {
		return claudeProjectRefused
	}
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return claudeProjectUnreadable
	}
	return claudeProjectKeep
}
