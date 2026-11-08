// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package testenv

import "testing"

// No connector resolves its folder from a per-user root other than the home
// and XDG_CONFIG_HOME, which SetHome and the tests already move.
func watchedUserRoots() []string { return nil }

func redirectedUserRoots(string) map[string]string { return nil }

// AssertOffRealRoamingProfile has no per-user root to check off Windows.
func AssertOffRealRoamingProfile(testing.TB) {}
