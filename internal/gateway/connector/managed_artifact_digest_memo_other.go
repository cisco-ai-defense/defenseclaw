//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"errors"
	"os"
)

// Outside Windows no managed hook runtime artifact is large and no hook
// binary is listed per target, so nothing is memoized. The seams are
// replaced in tests.
var (
	managedArtifactDigestMemoEligible = func(string) bool { return false }
	managedProtectedHookCopyEligible  = func(string) bool { return false }
	openManagedArtifactExclusive      = func(string) (*os.File, error) { return nil, errors.ErrUnsupported }
	managedArtifactStampOf            = func(*os.File) (managedArtifactStamp, bool) { return managedArtifactStamp{}, false }
	managedArtifactAttributeStampOf   = func(*os.File) (managedArtifactStamp, bool) { return managedArtifactStamp{}, false }
	endManagedArtifactChangeEpoch     = func(*os.File) error { return errors.ErrUnsupported }
)
