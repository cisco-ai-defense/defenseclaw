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
	"context"
	"errors"
	"fmt"
	"io"
	"os/user"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// The standalone Unix guardian (per-user workers, NSS fallback, reconcile
// lock) does not apply to Windows; these keep the shared call sites
// compiling and inert.

var errEnterpriseHooksStandaloneUnixOnly = errors.New("enterprise hooks: the standalone Unix guardian path is not available on Windows")

func enterpriseHooksStandaloneUnixActive() bool { return false }

func runEnterpriseHookReconcileOnceStandaloneUnix(context.Context) (enterpriseHookReconcileRun, error) {
	return enterpriseHookReconcileRun{Manifest: enterpriseHookManifest}, errEnterpriseHooksStandaloneUnixOnly
}

func runEnterpriseHookVerifyAttemptStandaloneUnix(context.Context) (enterpriseHookVerifyRun, error) {
	return enterpriseHookVerifyRun{Manifest: enterpriseHookManifest}, errEnterpriseHooksStandaloneUnixOnly
}

func enterpriseHookInstallTarget(ctx context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
	return enterprisehooks.Install(ctx, opts)
}

func writeEnterpriseHookStandaloneGuardianStateOrLog(io.Writer, string) {}

// enterpriseHookStandaloneLookupFallback resolves an account os/user could
// not. os/user also looks up the account's primary group in its domain, which
// fails for every Entra ID account ("No mapping between account names and
// security IDs was done"), so enterprise acp enroll, verify and revoke --user
// refused them; the LSA names the account and ProfileList gives its home, as
// enterprise policy show does (GAP-0242, GAP-0479). Secure Client keeps the
// lookup of main.
func enterpriseHookStandaloneLookupFallback(name string, lookupErr error) (*user.User, error) {
	if cfg != nil && cfg.SecureClientIntegration() {
		return nil, lookupErr
	}
	sid, _, err := enterprisePolicyAccount(name)
	if err != nil {
		return nil, lookupErr
	}
	home := enterprisePolicyProfileHome(sid)
	if home == "" {
		return nil, fmt.Errorf("%s has no profile on this computer yet (it has not signed in here)", sid)
	}
	return &user.User{Uid: sid, Username: name, HomeDir: home}, nil
}

// The Windows guardian takes a changed managed config in place, before a
// reconcile, so an edit of who is enrolled or which connectors are applies
// without a service stop (GAP-0716). The Unix guardian exits instead and its
// service manager restarts it; on Windows that exit is a service failure,
// whose restarts back off to a minute. Secure Client keeps its behaviour.

// enterpriseHookWindowsLoadedConfig is the sha256 of the config cfg was
// loaded from; empty off the standalone profile.
var enterpriseHookWindowsLoadedConfig string

// enterpriseHookWindowsConfigLoader loads a changed config as the guardian
// does at start; a seam for tests.
var enterpriseHookWindowsConfigLoader = func(path string) (*config.Config, error) {
	next, _, err := loadGatewayConfigV8(path)
	return next, err
}

func enterpriseHookWindowsConfigDigest() string {
	if cfg == nil || !cfg.StandaloneEnterprise() || cfg.SecureClientIntegration() || strings.TrimSpace(cfg.ConfigFilePath) == "" {
		return ""
	}
	raw, err := readWindowsEnterpriseBoundedFile(cfg.ConfigFilePath, 8<<20)
	if err != nil {
		return ""
	}
	return configwrite.SHA256Hex(raw)
}

// enterpriseHookStandaloneConfigFingerprint records the config the guardian
// started with. It returns "": the exit-on-change check is Unix only.
func enterpriseHookStandaloneConfigFingerprint() string {
	enterpriseHookWindowsLoadedConfig = enterpriseHookWindowsConfigDigest()
	return ""
}

func enterpriseHookStandaloneConfigChanged(string, io.Writer) bool { return false }

// enterpriseHookStandaloneConfigRefresh loads a changed config.yaml into cfg
// before a reconcile. A config that does not load is logged and the running
// one kept, so a bad edit cannot stop repair.
func enterpriseHookStandaloneConfigRefresh(w io.Writer) {
	if enterpriseHookWindowsLoadedConfig == "" {
		return
	}
	current := enterpriseHookWindowsConfigDigest()
	if current == "" || current == enterpriseHookWindowsLoadedConfig {
		return
	}
	next, err := enterpriseHookWindowsConfigLoader(cfg.ConfigFilePath)
	enterpriseHookWindowsLoadedConfig = current
	if err != nil || next == nil || !next.StandaloneEnterprise() || next.SecureClientIntegration() {
		fmt.Fprintf(w, "[hook-guardian] managed config changed but does not load; keeping the running config: %v\n", err)
		return
	}
	cfg = next
	fmt.Fprintf(w, "[hook-guardian] managed config changed; reconciling with it\n")
}
