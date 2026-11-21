//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

// ReclaimOwnTree is a Unix volume repair (a Kubernetes fsGroup); a Windows
// store is never on such a volume.
func ReclaimOwnTree(string) error { return nil }
