//go:build !windows && !linux && !darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"errors"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// DefaultUIDRange is a conservative default for other Unix systems.
func DefaultUIDRange() (int, int) { return 1000, 60000 }

// Default returns the os/user resolver.
func Default(ctx context.Context) Resolver {
	return NewCachingResolver(NewOSUserResolver(ctx))
}

// DirectoryFactsFunc has no directory facts to offer here.
func DirectoryFactsFunc(context.Context) func(uid int) (useridentity.DirectoryFacts, bool) {
	return nil
}

func platformLocalUserLister(context.Context, commandRunner) ([]Account, error) {
	return nil, nil
}

func platformLocalAccounts(context.Context) (map[string]int, error) {
	return nil, errors.New("unixidentity: no local account reader on this platform")
}

func platformDirectoryConfigured() bool { return true }
