// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// ownStatusUnprotectedAgents reads the agents the enumerator found it cannot
// protect; a seam for tests. A missing record is none.
var ownStatusUnprotectedAgents = readManagedUnprotectedAgents

// readManagedUnprotectedAgents reads the gateway's copy of the enumerator's
// unprotected-agents record (managed.HookGuardianUnprotectedAgentsFile): the
// same agents from the same scan the administrator's status and verify
// report, published with the guardian ledger's ownership and mode because
// the original is root-only. A missing record means the enumerator found
// none; one that cannot be trusted or parsed is an error, never "none".
func readManagedUnprotectedAgents(dataDir string) ([]enterprisehooks.UnprotectedAgent, error) {
	path := filepath.Join(managed.HookGuardianAuthorizationDir(dataDir), managed.HookGuardianUnprotectedAgentsFile)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return readGuardianRecord(func() ([]enterprisehooks.UnprotectedAgent, error) {
		if err := validateManagedGuardianAuthorization(path, "unprotected agents record"); err != nil {
			return nil, err
		}
		file, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open unprotected agents record: %w", err)
		}
		defer file.Close()
		data, err := io.ReadAll(io.LimitReader(file, enterprisehooks.UnprotectedAgentsMaxBytes+1))
		if err != nil {
			return nil, fmt.Errorf("read unprotected agents record: %w", err)
		}
		return enterprisehooks.ParseUnprotectedAgents(data)
	})
}

// ownUnprotectedAgents maps the caller's own entries of the unprotected-agents
// record by connector; "" holds an account-level entry (an account whose
// home is untrusted), which covers every connector. A record that cannot be
// read returns ok=false: the caller's protection is then not confirmed.
func (a *APIServer) ownUnprotectedAgents(uid int, name string) (map[string]enterprisehooks.UnprotectedAgent, bool) {
	agents, err := ownStatusUnprotectedAgents(a.configDataDir())
	if err != nil {
		return nil, false
	}
	mine := make(map[string]enterprisehooks.UnprotectedAgent)
	for _, agent := range agents {
		if agent.UID != nil && *agent.UID != uid || agent.UID == nil && (name == "" || agent.User != name) {
			continue
		}
		// Sorted by connector: the first entry of a connector speaks for it.
		if _, seen := mine[agent.Connector]; !seen {
			mine[agent.Connector] = agent
		}
	}
	return mine, true
}

// ownUnprotectedState is the own-status row for a connector the record lists
// as unprotected for the caller. Its text is the administrator's warning for
// that agent, reason and remedy included.
func ownUnprotectedState(agent enterprisehooks.UnprotectedAgent) map[string]any {
	reason := strings.TrimSpace(agent.Reason)
	if reason == "" {
		reason = agent.Code
	}
	return map[string]any{"protected": false, "state": "not protected: " + reason}
}
