// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package processutil

// Test hooks for the external pod-mode worker test (GAP-0828).
var RefuseUserNamespacesForTest = refuseUserNamespaces

// AllowPodRootForTest lets a helper that is root of its own user namespace,
// without capabilities, act as the pod's scan worker.
func AllowPodRootForTest() { podAllowRoot = true }
