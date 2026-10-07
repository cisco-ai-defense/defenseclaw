//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
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
				err := removeEnrolledQuarantinedSource(current, request)
				outcome := "removed"
				if err != nil {
					outcome = "refused: " + err.Error()
				}
				fmt.Fprintf(errOut, "[hook-guardian] quarantine %s %s: %s\n", request.TargetType, request.SourcePath, outcome)
				return err
			})
		}
	}()
}

// removeEnrolledQuarantinedSource checks a request against the enrolled
// users' watched folders and the quarantine store, then removes the source as
// the user who owns it.
func removeEnrolledQuarantinedSource(current *config.Config, request enforce.QuarantineRemovalRequest) error {
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
			return enterprisehooks.RemoveEnrolledUserAsset(root.SID, root.Home, source)
		}
	}
	return fmt.Errorf("no enrolled user owns %s", rootDir)
}
