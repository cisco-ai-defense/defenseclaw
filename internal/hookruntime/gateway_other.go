// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookruntime

import (
	"errors"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

func LockVerifiedGateway(State) (*os.File, error) {
	return nil, errors.New("native gateway cold start is Windows-only")
}

func protectInstalledGateway(path string) error { return safefile.ProtectFile(path) }
