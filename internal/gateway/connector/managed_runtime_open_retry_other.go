// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

// managedRuntimeOpenTransient is false off Windows: POSIX opens do not take
// sharing locks, so openManagedRuntimeFile stays a single os.Open.
func managedRuntimeOpenTransient(error) bool { return false }
