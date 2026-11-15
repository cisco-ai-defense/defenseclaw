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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

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
	// The same deployment read the standard-user refusal makes, so tests
	// that fake one deployment see both.
	layout, descriptor, err := managedStandaloneAdminDeployment()
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
var enterprisePolicyUnprotectedAgents = func(string) ([]enterprisehooks.UnprotectedAgent, error) { return nil, nil }

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
	configureEnterpriseHooksStandaloneUnix()
	resolver := unixidentity.Default(ctx)
	account, err := unixidentity.LookupAdminAccountSpelling(resolver, name, unixidentity.DirectoryFactsFunc(ctx))
	if err != nil {
		// A uid names its account as profile-explain takes it: getent answers
		// a uid with the account name, which is not the spelling typed. A name
		// that resolves to nothing gets profile-explain's plain sentence and
		// its did-you-mean spelling (GAP-1089).
		uid, convErr := strconv.Atoi(name)
		if convErr != nil || uid < 0 {
			return enterprisehooks.TargetCredentials{}, unixidentity.AccountLookupError(name, unixidentity.QualifiedUserName(ctx, resolver, name), err)
		}
		if account, err = resolver.LookupUID(uid); err != nil {
			return enterprisehooks.TargetCredentials{}, unixidentity.AccountLookupError(name, "", err)
		}
	} else if !strings.ContainsAny(name, `@\`) && strings.Trim(name, "0123456789") != "" {
		// A bare name a local and a directory account share names both;
		// policy show refuses it as profile-explain does (GAP-1087).
		twins, err := unixidentity.SameNameAccounts(ctx, resolver, account)
		if len(twins) > 0 {
			refs := []useridentity.AccountRef{{ID: strconv.Itoa(account.UID), Name: account.Name}}
			for _, twin := range twins {
				refs = append(refs, useridentity.AccountRef{ID: strconv.Itoa(twin.UID), Name: twin.Name})
			}
			return enterprisehooks.TargetCredentials{}, &useridentity.AmbiguousAccountError{Name: name, Accounts: refs}
		}
		if err != nil {
			// The joined domains are unknown, so a directory twin cannot be
			// ruled out (GAP-1131).
			return enterprisehooks.TargetCredentials{}, err
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

// enterprisePolicyLiveGeteuid is os.Geteuid; tests replace it.
var enterprisePolicyLiveGeteuid = os.Geteuid

// enterprisePolicyLiveCredential starts the agent as the target user. From
// root it uses the hook worker's credential: the account resolver's groups,
// primary group first, capped at the platform's setgroups limit. The live
// check passed every group, and every macOS account has more than 16
// (sharepoint groups, a directory account's AD groups), so setgroups failed
// with EINVAL and Codex never started: "fork/exec ...: invalid argument"
// (sidecar F09).
func enterprisePolicyLiveCredential(target enterprisehooks.TargetCredentials) func(*exec.Cmd) error {
	return func(cmd *exec.Cmd) error {
		if euid := enterprisePolicyLiveGeteuid(); euid != 0 {
			if target.UID != euid {
				return errors.New("live verification must run as root or as the target user")
			}
			return nil
		}
		account := enterpriseHookWorkerAccount{UID: target.UID, GID: target.GID, User: target.Username, Home: target.UserHome}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: enterpriseHookWorkerCredential(account, enterpriseHookWorkerGroupIDs(account), enterpriseHookWorkerMaxGroups)}
		return nil
	}
}

// accountGroupNames names uid's groups through the account database the
// gateway's sandbox availability check reads (NSS on Linux, Open Directory
// on macOS), so directory groups count. os/user in the static binary reads
// only /etc/passwd and /etc/group: an AD account was "unknown userid" and
// its docker membership unreadable although getent resolved it (GAP-0275).
func accountGroupNames(uid int) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return accountGroupNamesFrom(unixidentity.Default(ctx), uid)
}

// accountGroupNamesFrom is accountGroupNames over resolver.
func accountGroupNamesFrom(resolver unixidentity.Resolver, uid int) ([]string, error) {
	account, err := resolver.LookupUID(uid)
	if err != nil {
		return nil, err
	}
	ids, err := resolver.GroupIDs(account)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(ids))
	for _, id := range ids {
		if g, err := resolver.LookupGroupID(id); err == nil {
			names = append(names, g.Name)
		}
	}
	return names, nil
}
