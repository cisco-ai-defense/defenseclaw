// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// enterpriseACPSetupState reports, as the enrolled user, whether the
// editor entry of an enrollment is set up for this home and enrollment: its
// contract lock exists for the enrolled profile and its central mode, the
// editor file it pins is in the home, and the entry there points at this
// home's token copy and lock. After an account rename that moved the home,
// list and verify said setup was done while the entry pointed at the old
// home and could not start (GAP-0693); after a re-enrollment under another
// profile they said so while the entry still had the replaced profile
// (GAP-0833). note says what does not match.
func enterpriseACPSetupState(dataDir, home, client, agent, profile, mode string) (done bool, note string) {
	lockPath := acpContractLockPath(dataDir, client, agent)
	if info, err := os.Lstat(lockPath); err != nil || !info.Mode().IsRegular() {
		return false, ""
	}
	body, err := safefile.ReadRegularFileBounded(lockPath, acp.MaxContractLockBytes)
	if err != nil {
		return false, "its contract lock " + lockPath + " cannot be read"
	}
	var lock acp.RuntimeContractLock
	if err := json.Unmarshal(body, &lock); err != nil {
		return false, "its contract lock " + lockPath + " is damaged"
	}
	configPath := filepath.Clean(lock.Client.ConfigPath)
	if relative, relErr := filepath.Rel(filepath.Clean(home), configPath); relErr != nil || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return false, fmt.Sprintf("the editor entry was set up in %s, outside the home %s", configPath, home)
	}
	if lock.Profile != profile {
		return false, fmt.Sprintf("the editor entry is set up for profile %s, not the enrolled profile %s", lock.Profile, profile)
	}
	document, _, err := readACPClientConfig(configPath)
	if err != nil {
		return false, "the editor file " + configPath + " cannot be read"
	}
	servers, _ := document["agent_servers"].(map[string]any)
	entry, _ := servers[acpManagedEntryName(agent)].(map[string]any)
	args, _ := entry["args"].([]any)
	if entry == nil {
		return false, "the editor file " + configPath + " has no DefenseClaw entry for " + agent
	}
	command, _ := entry["command"].(string)
	if !filepath.IsAbs(command) || !sameEnterpriseHookPath(command, lock.Guard.Path) {
		return false, fmt.Sprintf("the editor entry uses command %s, not the configured guard %s", command, lock.Guard.Path)
	}
	tokenPath, err := acp.EnterpriseUserTokenPath(dataDir, client, agent)
	if err != nil {
		return false, err.Error()
	}
	want := map[string]string{"--token-file": tokenPath, "--contract-lock": lockPath}
	for index := 0; index+1 < len(args); index++ {
		flag, _ := args[index].(string)
		expected, checked := want[flag]
		if !checked {
			continue
		}
		value, _ := args[index+1].(string)
		if !sameEnterpriseHookPath(value, expected) {
			return false, fmt.Sprintf("the editor entry uses %s %s, not %s", flag, value, expected)
		}
		delete(want, flag)
	}
	if len(want) > 0 {
		return false, "the editor entry in " + configPath + " is not a managed DefenseClaw entry"
	}
	if mode != "" && lock.Mode != mode {
		return false, fmt.Sprintf("the editor entry is set up for %s mode, but profile %s is in %s mode", lock.Mode, profile, mode)
	}
	return true, ""
}
