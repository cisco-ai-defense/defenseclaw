// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acquire

import (
	"context"
	"errors"
)

// ErrHelperNotRoot is a helper socket served by a process that is not root.
var ErrHelperNotRoot = errors.New("acquire: the helper socket is not served by root")

// CheckRootSocket: an unmanaged Windows gateway never brokers through a
// socket its environment names; managed Windows uses the installer-owned path.
func CheckRootSocket(string) error {
	return errors.New("an unmanaged gateway does not broker through a sensor helper on Windows")
}

// NewRootHelper is not used on Windows (CheckRootSocket always refuses).
func NewRootHelper(socketPath string) *Helper { return NewHelper(socketPath) }

// ProbeRootHelper is not used on Windows.
func ProbeRootHelper(context.Context, string) error { return CheckRootSocket("") }

// RootSocketAwaitable: an unmanaged Windows gateway never waits for a helper.
func RootSocketAwaitable(string) bool { return false }
