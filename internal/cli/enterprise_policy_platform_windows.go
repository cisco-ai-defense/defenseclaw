//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// pinStandaloneManagedEnv points an elevated administrator's (or
// LocalSystem's) policy command at the standalone managed deployment, with
// the same pins audit export uses, when the caller chose no config. Without
// it `enterprise policy show|verify` read the administrator's own
// %USERPROFILE%\.defenseclaw\config.yaml and exited 1. A standard
// account is told to use an elevated prompt: the managed config is
// administrator-only.
func pinStandaloneManagedEnv() error {
	return pinManagedAdministratorEnvironment(
		"enterprise policy",
		"this host has a managed DefenseClaw deployment; its machine policy can be inspected only from an elevated Administrator prompt or by the MDM agent",
	)
}

// standaloneEnrolledHomes is empty on Windows: the Copilot VS Code lock is
// not written there.
func standaloneEnrolledHomes(managed.StandaloneLayout) []string { return nil }

// standaloneEnterprisePolicyLayout resolves the layout from the protected
// HKLM machine roots, never from the caller's environment.
func standaloneEnterprisePolicyLayout() (managed.StandaloneLayout, string, string, error) {
	programFiles, err := trustedWindowsEnterpriseProgramFiles()
	if err != nil {
		return managed.StandaloneLayout{}, "", "", err
	}
	programData, err := trustedWindowsEnterpriseProgramData()
	if err != nil {
		return managed.StandaloneLayout{}, "", "", err
	}
	layout, err := managed.StandaloneWindowsLayoutForRoots(programFiles, programData)
	return layout, programFiles, programData, err
}

func enterprisePolicyTarget(name string) (enterprisehooks.TargetCredentials, error) {
	account, err := user.Lookup(name)
	if err != nil {
		return enterprisehooks.TargetCredentials{}, fmt.Errorf("look up user %q: %w", name, err)
	}
	return enterprisehooks.TargetCredentials{UserHome: account.HomeDir, UID: -1, GID: -1, SID: account.Uid}, nil
}

// runAsEnterprisePolicyTarget impersonates the target user (or runs
// directly when this process already is that user).
func runAsEnterprisePolicyTarget(target enterprisehooks.TargetCredentials, fn func() error) error {
	return enterprisehooks.RunAsTarget(target, fn)
}

// enterprisePolicyLiveAvailable refuses `enterprise policy verify --live` on
// a managed Windows host up front. The live check starts the real client as
// the target user and reads the gateway's audit database: Windows gives an
// administrator no way to start a process as another account, and a
// standard account cannot read the managed configuration or audit database,
// so neither account can run it. Without this refusal an administrator was
// told to run it from the user's own session and the user to use an
// elevated prompt.
func enterprisePolicyLiveAvailable() error {
	if !auditExportManagedHost() {
		return nil
	}
	return errors.New("enterprise policy verify --live is not available on a managed Windows host: Windows cannot start the client as another account, and a standard account cannot read the managed configuration. " +
		"Run `defenseclaw enterprise policy verify` from an elevated Administrator prompt for the static check; to see the hooks run, make a tool call in the client from the user's own session, " +
		"then read its record from the elevated prompt with `defenseclaw audit export --connector <connector> -o <file>`")
}

// enterprisePolicyLiveCredential: Windows has no setuid; the agent must be
// started from the target user's own session.
func enterprisePolicyLiveCredential(target enterprisehooks.TargetCredentials) func(*exec.Cmd) error {
	return func(*exec.Cmd) error {
		current, err := user.Current()
		if err != nil {
			return err
		}
		if !strings.EqualFold(current.Uid, target.SID) {
			return errors.New("on Windows run live verification from the target user's own session")
		}
		return nil
	}
}

// enterprisePolicyUnprotectedAgents reads the enumerator's
// unprotected-agents record next to manifestPath. A token that cannot read
// the protected record lists none. Replaceable in tests.
var enterprisePolicyUnprotectedAgents = func(manifestPath string) []enterprisehooks.UnprotectedAgent {
	agents, err := enterprisehooks.ReadWindowsUnprotectedAgents(manifestPath)
	if err != nil {
		return nil
	}
	return agents
}

// hookForeignGuardAccountHome returns the profile directory of the
// process token (never the agent's environment): the guardian installs
// DefenseClaw's per-user registrations there. Replaceable in tests.
var hookForeignGuardAccountHome = func() string {
	if account, err := user.Current(); err == nil && filepath.IsAbs(account.HomeDir) {
		return filepath.Clean(account.HomeDir)
	}
	return ""
}

// hookForeignGuardEnvHomes lists the homes the agent's environment names
// (USERPROFILE as inherited from the agent), which it may read hook config
// from. Replaceable in tests.
var hookForeignGuardEnvHomes = func() []string {
	return []string{os.Getenv("USERPROFILE")}
}
