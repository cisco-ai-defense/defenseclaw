//go:build !windows

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
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// standaloneEnterprisePolicyLayout returns the standalone layout and, on
// Windows only, the trusted machine roots.
func standaloneEnterprisePolicyLayout() (managed.StandaloneLayout, string, string, error) {
	layout, err := managed.StandaloneLayoutFor(runtime.GOOS)
	return layout, "", "", err
}

// standaloneClaudeMachineHookContract is empty off Windows: the Unix
// lifecycle renders the Claude Code hook drop-in itself.
func standaloneClaudeMachineHookContract(managed.StandaloneLayout) string { return "" }

// standaloneEnrolledHomes are the enrolled accounts' homes from the
// enumerator's root-only record, which the lifecycle's machine-policy
// publisher reads too. The Copilot VS Code lock gate checks each one;
// without them show and verify said no enrolled users were recorded while
// enterprise hooks status listed them (GAP-1137). An unreadable record is
// no homes.
func standaloneEnrolledHomes(layout managed.StandaloneLayout) []string {
	accounts, err := enterpriseHookLoadEligibleAccounts(enterprisehooks.UnixEligibleAccountsPath(layout.ManifestPath))
	if err != nil {
		return nil
	}
	homes := make([]string, 0, len(accounts))
	for _, account := range accounts {
		homes = append(homes, account.Home)
	}
	return homes
}

// pinStandaloneManagedEnv points an administrator's policy command at the
// standalone deployment when the host runs one and the caller chose no
// config, with the same pins the services run with. Without it root's
// per-user ~/.defenseclaw/config.yaml would be read instead.
func pinStandaloneManagedEnv() error {
	if strings.TrimSpace(os.Getenv(managed.ConfigPathEnv)) != "" {
		return nil
	}
	layout, err := managed.StandaloneLayoutFor(runtime.GOOS)
	if err != nil {
		return nil
	}
	descriptor, err := managed.LoadRuntimeDescriptor(layout.DescriptorPath)
	if errors.Is(err, managed.ErrNoRuntimeDescriptor) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("standalone runtime descriptor: %w", err)
	}
	if !managed.IsStandaloneProfile(descriptor.Profile) {
		return nil
	}
	for key, value := range map[string]string{
		managed.ConfigPathEnv:        layout.ConfigPath,
		"DEFENSECLAW_HOME":           layout.DataDir,
		managed.DeploymentModeEnv:    managed.DeploymentModeManagedEnterprise,
		managed.EnterpriseProfileEnv: managed.ProfileStandalone,
	} {
		if err := os.Setenv(key, value); err != nil {
			return err
		}
	}
	return nil
}

// enterprisePolicyTarget resolves a local account for per-user checks.
// enterprisePolicyLiveAvailable: Linux and macOS run the live check as root
// or as the target user.
func enterprisePolicyLiveAvailable() error { return nil }

// enterprisePolicyUnprotectedAgents is the Windows unprotected-agents
// listing of policy show; Linux and macOS status and verify report them.
var enterprisePolicyUnprotectedAgents = func(string) []enterprisehooks.UnprotectedAgent { return nil }

// enterprisePolicyTarget resolves the account through the platform resolver
// profile-explain uses (NSS on Linux, Open Directory on macOS): os/user in
// the static binary reads only /etc/passwd, so no SSSD, Okta or AD account
// resolved (GAP-0740).
func enterprisePolicyTarget(name string) (enterprisehooks.TargetCredentials, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// The hooks step checks the account again (its primary gid) before it
	// reads the files as the user; the standalone rules let that check use
	// NSS too, not only /etc/passwd, which is all a static build's os/user
	// reads (GAP-0740).
	configureEnterpriseHooksStandaloneUnix(ctx)
	resolver := unixidentity.Default(ctx)
	account, err := unixidentity.LookupAccountSpelling(resolver, name, unixidentity.DirectoryFactsFunc(ctx))
	if err != nil {
		// A uid names its account as profile-explain takes it: getent answers
		// a uid with the account name, which is not the spelling typed.
		uid, convErr := strconv.Atoi(name)
		if convErr != nil || uid < 0 {
			return enterprisehooks.TargetCredentials{}, fmt.Errorf("look up user %q: %w", name, err)
		}
		if account, err = resolver.LookupUID(uid); err != nil {
			return enterprisehooks.TargetCredentials{}, fmt.Errorf("look up user %q: %w", name, err)
		}
	}
	return enterprisehooks.TargetCredentials{UserHome: account.Home, UID: account.UID, GID: account.GID, Username: account.Name}, nil
}

// runAsEnterprisePolicyTarget reads the user's files with the user's own
// credentials when running as root, so a crafted symlink in a home cannot
// make the administrator read files the user could not.
func runAsEnterprisePolicyTarget(target enterprisehooks.TargetCredentials, fn func() error) error {
	if os.Geteuid() != 0 {
		if target.UID != os.Geteuid() {
			return errors.New("run as root or as the target user")
		}
		return fn()
	}
	return enterprisehooks.RunAsTarget(target, fn)
}

// enterprisePolicyLiveCredential starts the agent as the target user.
func enterprisePolicyLiveCredential(target enterprisehooks.TargetCredentials) func(*exec.Cmd) error {
	return func(cmd *exec.Cmd) error {
		if os.Geteuid() != 0 {
			if target.UID != os.Geteuid() {
				return errors.New("live verification must run as root or as the target user")
			}
			return nil
		}
		groups := []uint32{}
		if account, err := user.LookupId(strconv.Itoa(target.UID)); err == nil {
			if ids, err := unixidentity.AccountGroupIDs(context.Background(), account); err == nil {
				for _, id := range ids {
					if value, err := strconv.ParseUint(id, 10, 32); err == nil {
						groups = append(groups, uint32(value))
					}
				}
			}
		} else if ids, err := unixidentity.Default(context.Background()).GroupIDs(unixidentity.Account{
			Name: target.Username, UID: target.UID, GID: target.GID, Home: target.UserHome}); err == nil {
			// A directory account os/user cannot see keeps its groups too.
			for _, id := range ids {
				groups = append(groups, uint32(id))
			}
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
			Uid:    uint32(target.UID),
			Gid:    uint32(target.GID),
			Groups: groups,
		}}
		return nil
	}
}

// hookForeignGuardAccountHome returns the calling account's home from the
// system account database, never from the agent's environment: the
// guardian installs DefenseClaw's per-user registrations there. Release
// builds have no cgo, so os/user sees only /etc/passwd; a directory
// (LDAP, SSSD) account resolves through the same trusted NSS lookup the
// enumerator uses. Empty when neither resolves. Replaceable in tests.
var hookForeignGuardAccountHome = func() string {
	uid := os.Getuid()
	if account, err := user.LookupId(strconv.Itoa(uid)); err == nil && filepath.IsAbs(account.HomeDir) {
		return filepath.Clean(account.HomeDir)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if account, err := unixidentity.Default(ctx).LookupUID(uid); err == nil && filepath.IsAbs(account.Home) {
		return filepath.Clean(account.Home)
	}
	return ""
}

// hookForeignGuardEnvHomes lists the homes the agent's environment names
// ($HOME as inherited from the agent), which it may read hook config from.
// Replaceable in tests.
var hookForeignGuardEnvHomes = func() []string {
	return []string{os.Getenv("HOME")}
}
