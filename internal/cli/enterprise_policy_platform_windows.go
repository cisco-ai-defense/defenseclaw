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

// standaloneEnterprisePolicyLayout resolves the layout from the protected
// HKLM machine roots, never from the caller's environment.
// pinStandaloneManagedEnv is a no-op on Windows: the managed services and
// the lifecycle pass the machine config explicitly.
func pinStandaloneManagedEnv() error { return nil }

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
