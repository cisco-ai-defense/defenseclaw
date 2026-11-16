//go:build !windows && !linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtimeowner

import "os/user"

// lookupAccount resolves name through os/user, which asks Open Directory on
// macOS.
func lookupAccount(name string) (*user.User, error) { return user.Lookup(name) }
