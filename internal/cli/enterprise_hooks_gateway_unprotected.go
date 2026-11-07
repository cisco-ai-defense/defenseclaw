// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// publishEnterpriseHookGatewayUnprotectedAgents publishes the enumerator's
// completed scan for the gateway next to the guardian ledger: the same bytes
// as the protected unprotected-agents record (agents, install generation and
// the config stamp), which the gateway cannot read. A user's own status is
// answered from it, so it says what the administrator's status says about
// that user (rel-1-0-6 GAP-0789). A scan that found nothing is published too:
// an absent, old or unmatched copy is an unknown scan, never "nothing found".
// When the copy cannot be written the previous one is withdrawn, so it does
// not speak for a scan this cycle replaced.
func publishEnterpriseHookGatewayUnprotectedAgents(dataDir string, agents []enterprisehooks.UnprotectedAgent, configGeneration uint64, configSHA256 string) error {
	data, err := enterprisehooks.MarshalUnprotectedAgentsForConfig(agents, configGeneration, configSHA256)
	if err != nil {
		return err
	}
	path := filepath.Join(managed.HookGuardianAuthorizationDir(dataDir), managed.HookGuardianUnprotectedAgentsFile)
	if err := writeEnterpriseHookGatewayRecord(path, data); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}
