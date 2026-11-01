// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
// (GAP-0833); after the agent executable the lock pins changed, they said so
// while the guard refused to start (GAP-1156). note says what does not
// match.
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
	// A valid reserved entry does not protect a second editor entry that
	// launches the same agent without the guard. Inspect every entry because
	// the editor can start any one of them independently.
	names := make([]string, 0, len(servers))
	for name := range servers {
		if name != acpManagedEntryName(agent) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		other, _ := servers[name].(map[string]any)
		if acpEntryLaunchesAgentDirectly(other, agent) {
			return false, fmt.Sprintf("the editor entry %q in %s launches %s directly without the DefenseClaw guard; remove it or route it through the guard", name, configPath, agent)
		}
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
	if !acp.ClientConfigMatchesLock(lock, lockPath, client, agent) {
		// The guard refuses an entry whose pinned parts changed after setup,
		// the agent it starts among them (GAP-1154).
		return false, "the editor entry in " + configPath + " changed after setup, so its contract lock no longer matches it"
	}
	if mode != "" && lock.Mode != mode {
		return false, fmt.Sprintf("the editor entry is set up for %s mode, but profile %s is in %s mode", lock.Mode, profile, mode)
	}
	if err := acp.LockedExecutablesMatch(lock, acp.EntryAgentCommand(args, agent), command); err != nil {
		// The guard refuses to start when the agent or guard executable the
		// lock pins moved or changed after setup (GAP-1156).
		return false, fmt.Sprintf("the agent or guard executable it pins changed after setup (%v), so the guard refuses to start it", err)
	}
	return true, ""
}

// acpEntryLaunchesAgentDirectly recognizes the catalog's command and ACP
// argument prefix, including an env wrapper with variable assignments. Extra
// agent flags do not turn a direct route into a guarded one.
func acpEntryLaunchesAgentDirectly(entry map[string]any, agentID string) bool {
	agent, err := acp.LookupAgent(agentID)
	if err != nil || entry == nil {
		return false
	}
	command, _ := entry["command"].(string)
	values, _ := entry["args"].([]any)
	args := make([]string, 0, len(values))
	for _, value := range values {
		arg, ok := value.(string)
		if !ok {
			return false
		}
		args = append(args, arg)
	}
	base := func(path string) string {
		return strings.TrimSuffix(strings.ToLower(filepath.Base(path)), ".exe")
	}
	if base(command) == "env" {
		for len(args) > 0 && strings.Contains(args[0], "=") {
			args = args[1:]
		}
		if len(args) == 0 {
			return false
		}
		command, args = args[0], args[1:]
	}
	matches := func(command string, args []string) bool {
		if base(command) != base(agent.Command) || len(args) < len(agent.Args) {
			return false
		}
		for i, expected := range agent.Args {
			if args[i] != expected {
				return false
			}
		}
		return true
	}
	if matches(command, args) {
		return true
	}
	// An editor can pass the same launch through env -S, cmd /c or a shell
	// command. Treat a visible catalog command followed by its ACP prefix as
	// a direct route too; these wrappers do not make it a guarded entry.
	words := strings.Fields(command + " " + strings.Join(args, " "))
	for i := range words {
		candidate := strings.Trim(words[i], `'"&;|`)
		remaining := make([]string, 0, len(words)-i-1)
		for _, word := range words[i+1:] {
			remaining = append(remaining, strings.Trim(word, `'"&;|`))
		}
		if matches(candidate, remaining) {
			return true
		}
	}
	return false
}
