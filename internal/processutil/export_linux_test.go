// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package processutil

// Test hooks for the external pod-mode worker test (GAP-0828).
var RefuseUserNamespacesForTest = refuseUserNamespaces

// PodMountsForTest gives a helper process the chart container's mount
// layout (GAP-1031): a read-only root and its own mount on each folder.
var PodMountsForTest = fakePodMounts
