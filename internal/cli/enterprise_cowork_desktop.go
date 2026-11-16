// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// windowsCoworkDesktopBudget bounds the engine checks of one Windows status
// or verify run, as coworkDesktopBudget does on Linux and macOS.
var windowsCoworkDesktopBudget = 60 * time.Second

// windowsCoworkDesktopReasonMax bounds the reason an account was not checked.
const windowsCoworkDesktopReasonMax = 300

// windowsCoworkDesktopState is the claude_desktop member of the cowork block
// of a Windows standalone status or verify (cowork-1-0-8 GAP-0057): for every
// enrolled account, its Claude Desktop data folders and the Authenticode
// trust of the newest engine build in each, as folders
// (enterprisehooks.WindowsClaudeDesktopFolders) reads them. The Linux and
// macOS status printed this as "engine 2.1.317 trusted" (GAP-0031); Windows
// printed nothing. Accounts are named in this administrator view only.
func windowsCoworkDesktopState(accounts []enterprisestatus.EnrollmentAccount,
	folders func(sid string) ([]enterprisehooks.ClaudeDesktopFolder, error)) *enterprisestatus.CoworkDesktopState {
	listed := make([]enterprisestatus.EnrollmentAccount, 0, len(accounts))
	seen := map[string]bool{}
	for _, account := range accounts {
		name := strings.TrimSpace(account.Account)
		if name == "" || seen[strings.ToLower(name)] {
			continue
		}
		seen[strings.ToLower(name)] = true
		account.Account = name
		listed = append(listed, account)
	}
	sort.Slice(listed, func(i, j int) bool { return listed[i].Account < listed[j].Account })
	state := &enterprisestatus.CoworkDesktopState{AccountsKnown: true}
	if len(listed) > enterprisestatus.CoworkAccountsMax {
		listed, state.AccountsTruncated = listed[:enterprisestatus.CoworkAccountsMax], true
	}
	deadline := time.Now().Add(windowsCoworkDesktopBudget)
	for _, account := range listed {
		entry := enterprisestatus.CoworkDesktopAccount{Account: account.Account}
		switch {
		case strings.TrimSpace(account.SID) == "":
			entry.Reason = "the enrollment row names no SID"
		case time.Now().After(deadline):
			entry.Reason = "the time for engine checks of this run was spent"
		default:
			found, err := folders(account.SID)
			for _, folder := range found {
				install := windowsCoworkDesktopInstall(folder)
				state.Count(install)
				entry.Installs = append(entry.Installs, install)
			}
			if err != nil {
				entry.Reason = boundWindowsCoworkDesktopReason(err.Error())
			}
		}
		state.Accounts = append(state.Accounts, entry)
	}
	return state
}

// windowsCoworkDesktopInstall is one data folder as the cowork block reports
// it. Windows has no unsigned state of its own: a build without a signature
// that names Anthropic is untrusted.
func windowsCoworkDesktopInstall(folder enterprisehooks.ClaudeDesktopFolder) enterprisestatus.CoworkDesktopInstall {
	install := enterprisestatus.CoworkDesktopInstall{Deployment: folder.Deployment, Path: folder.Path,
		EngineVersion: folder.EngineVersion, EnginePath: folder.EnginePath}
	switch {
	case folder.Unverified != "":
		install.Trust, install.Reason = enterprisestatus.CoworkEngineUntrusted, boundWindowsCoworkDesktopReason(folder.Unverified)
	case folder.EngineVersion == "":
		install.Trust, install.EnginePath = enterprisestatus.CoworkEngineNotFound, ""
	default:
		install.Trust = enterprisestatus.CoworkEngineTrusted
	}
	return install
}

func boundWindowsCoworkDesktopReason(reason string) string {
	reason = strings.Join(strings.Fields(reason), " ")
	if len(reason) > windowsCoworkDesktopReasonMax {
		reason = reason[:windowsCoworkDesktopReasonMax] + "..."
	}
	return reason
}
