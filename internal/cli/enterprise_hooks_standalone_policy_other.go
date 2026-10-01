// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"io"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// The Windows standalone guardian steps have no equivalent in the shared
// reconcile on other platforms (the standalone Unix guardian has its own).

func enterpriseHookStandalonePlatformPrepare(io.Writer) {}

func enterpriseHookStandalonePlatformWatch(context.Context, io.Writer) {}

func enterpriseHookStandalonePlatformFinish(context.Context, io.Writer, []enterpriseHookReconcileRow, time.Time) {
}

func pruneWindowsStandalonePerUserEnrollments(enterprisehooks.Manifest, string) error { return nil }

func enterpriseHookStandalonePlatformRevokeUsers(context.Context, io.Writer, enterprisehooks.Manifest) error {
	return nil
}
