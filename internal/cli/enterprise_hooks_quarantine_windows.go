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
				if request.Kind == enforce.QuarantineRequestReadGrant {
					err := grantEnrolledAssetRead(current, request, enterprisehooks.GrantGatewayAssetRead)
					outcome := "granted the gateway read access"
					if err != nil {
						outcome = "read grant refused: " + err.Error()
					}
					fmt.Fprintf(errOut, "[hook-guardian] %s %s: %s\n", request.TargetType, request.SourcePath, outcome)
					return err
				}
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
						fmt.Fprintf(errOut, "[hook-guardian] quarantine %s %s: deferred removal dropped: %v\n", request.TargetType, request.SourcePath, err)
					}
					return err
				})
			}
		}
	}()
}

// removeEnrolledQuarantinedSource checks a request against the enrolled
// users' watched folders and the quarantine store, then removes the source as
// the user who owns it, with remove. A signed-out user Windows gives no S4U
// logon for defers the removal to the next sign-in.
func removeEnrolledQuarantinedSource(current *config.Config, request enforce.QuarantineRemovalRequest, remove func(sid, home, path string) error) error {
	roots := gateway.EnrolledWatchRoots(current)
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
				return fmt.Errorf("%w: %s", enforce.ErrQuarantineRemovalDeferred,
					enterprisehooks.SignedOutRemovalReason(root.SID, filepath.Base(root.Home), err))
			}
			return err
		}
	}
	return fmt.Errorf("no enrolled user owns %s", rootDir)
}

// grantEnrolledAssetRead checks a read grant request against the enrolled
// users' watched folders and has grant give the gateway service read access
// to the folder as the user who owns that watched folder (GAP-0825).
func grantEnrolledAssetRead(current *config.Config, request enforce.QuarantineRemovalRequest, grant func(sid, home, path string) error) error {
	roots := gateway.EnrolledWatchRoots(current)
	dirs := make([]string, 0, len(roots))
	for _, root := range roots {
		dirs = append(dirs, root.Dir)
	}
	source, rootDir, err := enforce.VerifyAssetReadGrant(request, dirs)
	if err != nil {
		return err
	}
	for _, root := range roots {
		if strings.EqualFold(filepath.Clean(root.Dir), filepath.Clean(rootDir)) {
			return grant(root.SID, root.Home, source)
		}
	}
	return fmt.Errorf("no enrolled user owns %s", rootDir)
}
