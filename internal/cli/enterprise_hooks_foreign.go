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
	"io"
	"os"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// enterpriseForeignHookCleanup removes unapproved foreign hooks from one
// enrolled user's USER-level config for one connector on the standalone
// profile (backups under ~/.defenseclaw/foreign-hooks-backup). It runs as
// the user through RunAsTarget. The reconcile loop calls it after a
// per-user row verifies; the enumerator must call it for machine-policy
// connectors (which have no per-user manifest rows) once per eligible
// user. Secure Client and unmanaged configs return immediately.
// Replaceable in tests.
var enterpriseForeignHookCleanup = func(target enterprisehooks.TargetCredentials, connectorName, dataDir string) (enterprisepolicy.CleanupResult, error) {
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return enterprisepolicy.CleanupResult{}, nil
	}
	name := strings.ToLower(strings.TrimSpace(connectorName))
	layout, programFiles, programData, err := standaloneEnterprisePolicyLayout()
	if err != nil {
		return enterprisepolicy.CleanupResult{}, err
	}
	opts, err := enterprisepolicy.StandaloneOptions(layout, programFiles, programData, cfg)
	if err != nil {
		return enterprisepolicy.CleanupResult{}, err
	}
	policy := enterprisepolicy.BuildPublicPolicy(opts, []string{name}).Connectors[name]
	if !policy.Guard || policy.ForeignHooks != config.ForeignHooksRemove {
		return enterprisepolicy.CleanupResult{}, nil
	}
	request := enterprisepolicy.GuardRequest{
		Connector:     name,
		GOOS:          layout.GOOS,
		Home:          target.UserHome,
		AccountHome:   target.UserHome,
		HookBinary:    opts.HookBinary,
		Policy:        policy,
		OwnedCommands: perUserOwnedHookCommands(name, target.UserHome, dataDir),
	}
	return cleanEnterpriseForeignHooksAsTarget(target, request, time.Now())
}

// enterpriseForeignHookRunAsTarget runs fn as the user. Replaceable in tests
// (a test process cannot take on another profile's token).
var enterpriseForeignHookRunAsTarget = enterprisehooks.RunAsTarget

// cleanEnterpriseForeignHooksAsTarget cleans request's user config as
// target: the default locations and every location an environment variable
// moves it to.
func cleanEnterpriseForeignHooksAsTarget(target enterprisehooks.TargetCredentials, request enterprisepolicy.GuardRequest, now time.Time) (enterprisepolicy.CleanupResult, error) {
	var result enterprisepolicy.CleanupResult
	err := enterpriseForeignHookRunAsTarget(target, func() error {
		// The guardian has no user environment: the user's hooks recorded
		// the config locations their agents' environment redirects to, and
		// on Windows the user's persistent environment names more.
		redirects, redirectErr := enterprisepolicy.LoadEnvRedirects(target.UserHome, request.Connector)
		userEnv, userEnvErr := enterpriseForeignHookUserEnvRedirects(target, request)
		redirects = append(redirects, userEnv...)
		var cleanErr error
		result, cleanErr = enterprisepolicy.CleanUserForeignHooksWithRedirects(request, redirects, now)
		return errors.Join(cleanErr, redirectErr, userEnvErr)
	})
	return result, err
}

// enterpriseForeignHookCollectBlocks takes the foreign-hook blocks one
// user's hooks recorded, running as that user. Secure Client and unmanaged
// configs return immediately. Replaceable in tests.
var enterpriseForeignHookCollectBlocks = func(target enterprisehooks.TargetCredentials) ([]enterprisepolicy.BlockSummary, int, error) {
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return nil, 0, nil
	}
	var blocks []enterprisepolicy.BlockSummary
	dropped := 0
	err := enterpriseForeignHookRunAsTarget(target, func() error {
		var collectErr error
		blocks, dropped, collectErr = enterprisepolicy.CollectForeignHookBlocks(target.UserHome, time.Now())
		return collectErr
	})
	return blocks, dropped, err
}

// logEnterpriseForeignHookBlocks reports recorded blocks in the guardian
// log. The records come from a user-writable file: every field is bounded
// and stripped of control characters.
func logEnterpriseForeignHookBlocks(stderr io.Writer, user string, blocks []enterprisepolicy.BlockSummary, dropped int, collectErr string) {
	for i, block := range blocks {
		if i == enterprisepolicy.BlockSummaryLimit {
			break
		}
		fmt.Fprintf(stderr, "defenseclaw: enterprise foreign-hook guard: %s for %s (recorded by the user's hook)\n", foreignGuardLogField(block.String(), 2048), foreignGuardLogField(user, 256))
	}
	if dropped > 0 {
		fmt.Fprintf(stderr, "defenseclaw: enterprise foreign-hook guard: %d more blocked hook file(s) for %s not listed\n", dropped, foreignGuardLogField(user, 256))
	}
	if collectErr != "" {
		fmt.Fprintf(stderr, "defenseclaw: enterprise foreign-hook guard: block records for %s: %s\n", foreignGuardLogField(user, 256), foreignGuardLogField(collectErr, 512))
	}
}

func foreignGuardLogField(value string, limit int) string {
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, value)
	if len(value) > limit {
		return value[:limit]
	}
	return value
}

// reconcileEnterpriseForeignHooks is the reconcile loop's call site. Cleanup
// is best effort: the admin-owned hook still denies tool calls while an
// unapproved hook remains, so a failure here never fails the row.
func reconcileEnterpriseForeignHooks(opts enterprisehooks.InstallOptions) {
	result, err := enterpriseForeignHookCleanup(enterprisehooks.TargetCredentials{
		UserHome: opts.UserHome,
		UID:      opts.OwnerUID,
		GID:      opts.OwnerGID,
		SID:      opts.OwnerSID,
	}, opts.ConnectorName, opts.DataDir)
	for _, finding := range result.Removed {
		fmt.Fprintf(os.Stderr, "defenseclaw: enterprise foreign-hook guard: removed %s %s hook from %s (sha256:%s); backup in %s\n",
			finding.Connector, dashIfEmpty(finding.Event), finding.Path, finding.Digest, result.BackupDir)
	}
	for _, finding := range result.Reported {
		fmt.Fprintf(os.Stderr, "defenseclaw: enterprise foreign-hook guard: %s hook in %s left in place (%s)\n", finding.Connector, finding.Path, finding.Reason)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "defenseclaw: enterprise foreign-hook guard: cleanup for %s %s: %v\n", opts.ConnectorName, opts.UserHome, err)
	}
}
