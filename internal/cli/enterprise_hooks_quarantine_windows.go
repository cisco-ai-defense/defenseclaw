//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// enterpriseHookQuarantinePoll is how often the guardian looks for requests.
const enterpriseHookQuarantinePoll = time.Second

// enterpriseHookQuarantineDeferredPoll is how often the guardian retries the
// removals deferred until a signed-out user signs in again.
const enterpriseHookQuarantineDeferredPoll = 5 * time.Second

// startEnterpriseHookQuarantineRemovals answers the gateway's requests to
// remove a quarantined skill or plugin from an enrolled user's folder, which
// the gateway service may read but not delete in (GAP-0202). Standalone only:
// the Secure Client profile keeps its own behaviour.
func startEnterpriseHookQuarantineRemovals(ctx context.Context, errOut io.Writer) {
	current := cfg
	if current == nil || !current.StandaloneEnterprise() || current.SecureClientIntegration() {
		return
	}
	guardianDir := managed.HookGuardianAuthorizationDir(current.DataDir)
	channel := enforce.QuarantineRemovalChannelFor(current.DataDir, guardianDir)
	go func() {
		prepared := false
		var lastDeferred time.Time
		ticker := time.NewTicker(enterpriseHookQuarantinePoll)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			if !prepared {
				if err := os.MkdirAll(channel.ResultDir, 0o750); err == nil {
					prepared = setEnterpriseHookGuardianStateOwnership(channel.ResultDir) == nil
				}
				if !prepared {
					continue
				}
			}
			channel.ServeOnce(func(request enforce.QuarantineRemovalRequest) error {
				err := removeEnrolledQuarantinedSource(current, request, enterprisehooks.RemoveEnrolledUserAsset)
				outcome := "removed"
				switch {
				case errors.Is(err, enforce.ErrQuarantineRemovalDeferred):
					outcome = "deferred: " + err.Error()
				case err != nil:
					outcome = "refused: " + err.Error()
				}
				fmt.Fprintf(errOut, "[hook-guardian] quarantine %s %s: %s\n", request.TargetType, request.SourcePath, outcome)
				return err
			})
			if time.Since(lastDeferred) >= enterpriseHookQuarantineDeferredPoll {
				lastDeferred = time.Now()
				channel.ServeDeferred(func(request enforce.QuarantineRemovalRequest) error {
					err := removeEnrolledQuarantinedSource(current, request, enterprisehooks.RemoveEnrolledUserAssetInSession)
					switch {
					case err == nil:
						fmt.Fprintf(errOut, "[hook-guardian] quarantine %s %s: removed now that the user is signed in\n", request.TargetType, request.SourcePath)
					case !errors.Is(err, enforce.ErrQuarantineRemovalDeferred):
						fmt.Fprintf(errOut, "[hook-guardian] quarantine %s %s: deferred removal retry pending: %v\n", request.TargetType, request.SourcePath, err)
					}
					return err
				})
			}
		}
	}()
}

// removeEnrolledQuarantinedSource checks a request against the enrolled
// users' watched folders and the quarantine store, then removes the source as
// the user who owns it, with remove. A signed-out user without an S4U logon
// defers the removal to the next sign-in.
func removeEnrolledQuarantinedSource(current *config.Config, request enforce.QuarantineRemovalRequest, remove func(sid, home, path string) error) error {
	roots := enrolledWatchRootsForGuardian(current)
	dirs := make([]string, 0, len(roots))
	for _, root := range roots {
		dirs = append(dirs, root.Dir)
	}
	source, rootDir, err := enforce.VerifyQuarantineRemoval(request, dirs, current.QuarantineDir)
	if err != nil {
		return err
	}
	for _, root := range roots {
		if strings.EqualFold(filepath.Clean(root.Dir), filepath.Clean(rootDir)) {
			err := remove(root.SID, root.Home, source)
			if errors.Is(err, enterprisehooks.ErrEnrolledUserSignedOut) {
				return fmt.Errorf("%w: the owner of %s is signed out and the account has no S4U logon (a Microsoft Entra ID account); the guardian removes the folder when that user next signs in",
					enforce.ErrQuarantineRemovalDeferred, filepath.Base(root.Home))
			}
			return err
		}
	}
	return fmt.Errorf("no enrolled user owns %s", rootDir)
}

// enrolledWatchRootsForGuardian resolves the enrolled watch roots while no
// other goroutine of the guardian resolves connector paths for a user
// (connector.WithUserHomeDir): those overrides are process-wide, and one in
// the middle of the resolution dropped an Amp skills root, so the removal of
// a quarantined Amp skill was refused as outside the watched folders
// (GAP-0913).
func enrolledWatchRootsForGuardian(current *config.Config) []gateway.EnrolledWatchRoot {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return gateway.EnrolledWatchRoots(current)
	}
	var roots []gateway.EnrolledWatchRoot
	_ = connector.WithUserHomeDir(home, func() error {
		roots = gateway.EnrolledWatchRoots(current)
		return nil
	})
	return roots
}
