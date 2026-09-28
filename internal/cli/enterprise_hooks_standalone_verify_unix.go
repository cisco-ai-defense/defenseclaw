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
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// The verify-only token readers never mint; replaceable in tests.
// runEnterpriseHookVerifyAttemptStandaloneUnix verifies the standalone
// Unix guardian without mutating anything. Every per-user check runs in
// the target user's worker; a target whose home is unavailable right now
// is pending only when the last reconcile recorded it pending too.
func runEnterpriseHookVerifyAttemptStandaloneUnix(ctx context.Context) (enterpriseHookVerifyRun, error) {
	run := enterpriseHookVerifyRun{Manifest: enterpriseHookManifest}
	if err := enterpriseHookManifestFileTrustCheck(enterpriseHookManifest); err != nil {
		return run, fmt.Errorf("enterprise hooks verify: manifest trust check failed: %w", err)
	}
	if err := enterpriseHookStandaloneRuntimeCheck(); err != nil {
		return run, err
	}
	manifest, manifestSHA256, err := enterprisehooks.LoadManifestWithSHA256(enterpriseHookManifest)
	if err != nil {
		return run, err
	}
	authorization, exists, authorizationErr := loadEnterpriseHookGuardianAuthorization(cfg.DataDir)
	activation, activationExists, activationErr := loadEnterpriseHookGuardianActivation(cfg.DataDir)
	guardianState, guardianStateExists, guardianStateErr := loadEnterpriseHookGuardianState(cfg.DataDir)
	freshnessErr := managed.ValidateHookGuardianFreshness(authorization.UpdatedAt, time.Now())
	switch {
	case authorizationErr != nil:
		run.AuthorizationErr = authorizationErr
	case !exists:
		run.AuthorizationErr = errors.New("protected hook guardian authorization is missing")
	case !authorization.OK || authorization.FailureCount != 0 ||
		authorization.SuccessCount+authorization.PendingCount != authorization.TargetCount:
		run.AuthorizationErr = fmt.Errorf("protected hook guardian authorization is incomplete (%d succeeded, %d pending, %d total)", authorization.SuccessCount, authorization.PendingCount, authorization.TargetCount)
	case freshnessErr != nil:
		run.AuthorizationErr = fmt.Errorf("protected hook guardian authorization is not fresh: %w", freshnessErr)
	case activationErr != nil:
		run.AuthorizationErr = activationErr
	case !activationExists:
		run.AuthorizationErr = errors.New("protected hook guardian activation is missing")
	case !activation.OK || activation.UpdatedAt != authorization.UpdatedAt || activation.ManifestSHA256 != manifestSHA256:
		run.AuthorizationErr = errors.New("protected hook guardian activation does not cover the current manifest bytes")
	}
	authenticatedPending := map[string]struct{}{}
	if run.AuthorizationErr == nil && (authorization.PendingCount != 0 || activation.PendingCount != 0) {
		switch {
		case guardianStateErr != nil:
			run.AuthorizationErr = guardianStateErr
		case !guardianStateExists:
			run.AuthorizationErr = errors.New("hook guardian state is missing for pending verification")
		default:
			authenticatedPending, err = enterpriseHookStandaloneAuthenticatedPending(manifest, guardianState, authorization, activation, enterpriseHookManifest, manifestSHA256)
			if err != nil {
				run.AuthorizationErr = err
			}
		}
	}

	apiAddr, proxyAddr := enterpriseHookListenAddrs()
	hookSocket, serviceUID, transportErr := enterpriseHookStandaloneHookTransport()
	resolver := enterprisehooks.StandaloneResolver()
	if caching, ok := resolver.(*unixidentity.CachingResolver); ok {
		caching.Reset()
	}
	jobs := map[int]*enterpriseHookWorkerJob{}
	dispatched := map[int]bool{}
	for _, target := range manifest.Targets {
		if !target.IsEnabled() {
			continue
		}
		row := enterpriseHookReconcileRow{
			User:      strings.TrimSpace(target.User),
			UserHome:  strings.TrimSpace(target.UserHome),
			Connector: strings.TrimSpace(target.Connector),
		}
		fail := func(err error) {
			row.Error = err.Error()
			run.Rows = append(run.Rows, row)
		}
		account, pendingReason, err := resolveEnterpriseHookStandaloneAccount(target, resolver)
		if err != nil {
			fail(err)
			continue
		}
		if pendingReason == "" {
			row.UserHome = account.Home
			row.UID = account.UID
			check := enterpriseHookCheckHome(account.Home, account.UID)
			row.HomeInode = check.Inode
			switch {
			case check.State == enterprisehooks.HomePending:
				pendingReason = check.Reason
			case check.State == enterprisehooks.HomeUntrusted:
				fail(errors.New("enterprise hooks: " + check.Reason))
				continue
			case target.HomeInode != 0 && check.Inode != target.HomeInode:
				pendingReason = "home was recreated after enumeration"
			}
		}
		if pendingReason != "" {
			if _, recorded := authenticatedPending[enterpriseHookProtectedTargetKey(row)]; !recorded {
				fail(fmt.Errorf("target is unavailable (%s) but the guardian has not recorded it pending", pendingReason))
				continue
			}
			row.Pending = true
			run.Rows = append(run.Rows, row)
			continue
		}
		if transportErr != nil {
			fail(transportErr)
			continue
		}
		identity := strconv.Itoa(account.UID)
		token, otlpToken, err := enterpriseHookUserTokenLoader(cfg.DataDir, target.Connector, identity)
		if err != nil {
			fail(err)
			continue
		}
		opts := enterprisehooks.InstallOptions{
			ConnectorName: target.Connector,
			UserHome:      account.Home,
			OwnerUID:      account.UID,
			OwnerGID:      account.GID,
			DataDir:       strings.TrimSpace(target.DataDir),
			APIAddr:       apiAddr,
			ProxyAddr:     proxyAddr,
			APIToken:      token,
			OTLPPathToken: otlpToken,
			HookFailMode:  cfg.EffectiveHookFailModeForConnector(target.Connector),
			GuardrailMode: cfg.EffectiveGuardrailModeForConnector(target.Connector),
			HILTEnabled:   cfg.EffectiveHILTForConnector(target.Connector).Enabled,
			AgentVersion:  strings.TrimSpace(target.AgentVersion),
			WorkspaceDir:  cfg.ConnectorWorkspaceDir(),

			ManagedHookSocket:      hookSocket,
			ManagedServiceUID:      serviceUID,
			HookCredentialIdentity: identity,
			ForeignHookGuardBinary: standaloneForeignHookGuardBinary(target.Connector),
		}
		index := len(run.Rows)
		run.Rows = append(run.Rows, row)
		dispatched[index] = true
		job, ok := jobs[account.UID]
		if !ok {
			job = &enterpriseHookWorkerJob{Account: account, Request: enterpriseHookWorkerRequest{Operation: enterpriseHookWorkerOpApply, Standalone: true}}
			jobs[account.UID] = job
		}
		job.Request.Targets = append(job.Request.Targets, enterpriseHookWorkerTarget{
			Index:   index,
			Mode:    enterpriseHookWorkerModeVerify,
			Options: enterpriseHookWorkerOptionsFrom(opts),
		})
	}

	outcomes := dispatchEnterpriseHookStandaloneJobs(ctx, jobs)
	for index := range dispatched {
		row := run.Rows[index]
		outcome, ok := outcomes[index]
		switch {
		case ok && outcome.ok:
			row.OK = true
			row.Result = outcome.result
			row.UserHome = outcome.result.UserHome
			row.Connector = outcome.result.Connector
		case ok && outcome.pending:
			row.Error = "target home became unavailable during verification"
		case ok:
			row.Error = outcome.err
		default:
			row.Error = errEnterpriseHookWorkerNoResult.Error()
		}
		if row.OK && exists && !enterpriseHookAuthorizationCovers(authorization, row) {
			row.OK = false
			row.Result = nil
			row.Error = "protected authorization does not cover target"
		}
		run.Rows[index] = row
	}
	for _, row := range run.Rows {
		switch {
		case row.Pending:
			run.Pending++
		case !row.OK:
			run.Failures++
		}
	}
	if run.AuthorizationErr == nil && exists && activationExists {
		if issues := enterpriseHookVerifyDispositionIssues(run, authorization, activation); len(issues) > 0 {
			run.AuthorizationErr = errors.New(strings.Join(issues, "; "))
		}
	}
	return run, nil
}

func enterpriseHookAuthorizationCovers(authorization enterpriseHookGuardianAuthorization, row enterpriseHookReconcileRow) bool {
	connectorName := strings.ToLower(strings.TrimSpace(row.Connector))
	for _, protected := range authorization.ProtectedTargets {
		if enterpriseHookRowMatches(protected, row.User, row.UserHome, "", connectorName) {
			return true
		}
	}
	return false
}

// enterpriseHookStandaloneAuthenticatedPending returns the targets the
// last reconcile recorded pending, after proving the guardian state, the
// ledger and the activation receipt describe the same reconcile of the
// exact enabled manifest. Unix rows are keyed by user (or home), not SID.
func enterpriseHookStandaloneAuthenticatedPending(
	manifest enterprisehooks.Manifest,
	state enterpriseHookGuardianState,
	authorization enterpriseHookGuardianAuthorization,
	activation enterpriseHookGuardianActivation,
	manifestPath,
	manifestSHA256 string,
) (map[string]struct{}, error) {
	if issues := compareEnterpriseHookGuardianRecords(state, authorization, activation, manifestPath, manifestSHA256); len(issues) != 0 {
		return nil, fmt.Errorf("protected guardian pending proof is invalid: %s", strings.Join(issues, "; "))
	}
	expected := map[string]struct{}{}
	for _, target := range manifest.Targets {
		if !target.IsEnabled() {
			continue
		}
		key := enterpriseHookProtectedTargetKey(enterpriseHookReconcileRow{
			User:      strings.TrimSpace(target.User),
			UserHome:  strings.TrimSpace(target.UserHome),
			Connector: strings.TrimSpace(target.Connector),
		})
		if key == "" {
			return nil, errors.New("protected guardian pending proof has an incomplete manifest target")
		}
		expected[key] = struct{}{}
	}
	if len(state.Results) != len(expected) {
		return nil, errors.New("protected guardian pending proof does not cover the exact enabled manifest")
	}
	pending := map[string]struct{}{}
	seen := map[string]struct{}{}
	for _, row := range state.Results {
		key := enterpriseHookProtectedTargetKey(row)
		if _, ok := expected[key]; !ok {
			return nil, errors.New("protected guardian pending proof contains a target outside the enabled manifest")
		}
		if _, duplicate := seen[key]; duplicate {
			return nil, errors.New("protected guardian pending proof contains a duplicate target")
		}
		seen[key] = struct{}{}
		if row.Pending {
			if row.OK || row.Result != nil || strings.TrimSpace(row.Error) != "" {
				return nil, errors.New("protected guardian pending proof contains a noncanonical pending target")
			}
			pending[key] = struct{}{}
		}
	}
	if len(pending) != state.PendingCount || len(pending) != authorization.PendingCount || len(pending) != activation.PendingCount {
		return nil, errors.New("protected guardian pending proof has inconsistent pending target counts")
	}
	return pending, nil
}
