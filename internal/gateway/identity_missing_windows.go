// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"errors"
	"time"

	"golang.org/x/sys/windows"
)

func definitiveMissingAccount(err error) bool { return errors.Is(err, windows.ERROR_NONE_MAPPED) }

// missingAccountDirectoryAway is false on Windows: ERROR_NONE_MAPPED is the
// LSA's answer, which reliableMissingAccountConfirmation confirms.
var missingAccountDirectoryAway = func(string, time.Time) bool { return false }

// ERROR_NONE_MAPPED is a definitive absent SID.
func reliableMissingAccountConfirmation() bool { return true }
