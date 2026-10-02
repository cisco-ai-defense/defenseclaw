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

func enterprisePolicyTarget(name string) (enterprisehooks.TargetCredentials, error) {
	account, err := user.Lookup(name)
	if err != nil {
		return enterprisehooks.TargetCredentials{}, fmt.Errorf("look up user %q: %w", name, err)
	}
	uid, uidErr := strconv.Atoi(account.Uid)
	gid, gidErr := strconv.Atoi(account.Gid)
	if uidErr != nil || gidErr != nil {
		return enterprisehooks.TargetCredentials{}, fmt.Errorf("user %q has a non-numeric uid/gid", name)
	}
	return enterprisehooks.TargetCredentials{UserHome: account.HomeDir, UID: uid, GID: gid, Username: account.Username}, nil
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
			if ids, err := account.GroupIds(); err == nil {
				for _, id := range ids {
					if value, err := strconv.ParseUint(id, 10, 32); err == nil {
						groups = append(groups, uint32(value))
					}
				}
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
