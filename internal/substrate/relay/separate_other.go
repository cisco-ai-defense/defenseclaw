// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package relay

import (
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// separate: actors are Linux; elsewhere (tests) the relay and the agent are
// not separated.
func separate(kit.RelayConfig) (*separation, string, error) { return nil, "", nil }

// withAgentFS runs fn (the relay and the agent are one user here).
func (sp *separation) withAgentFS(fn func()) bool { fn(); return true }
