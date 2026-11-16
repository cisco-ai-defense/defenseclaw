// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

// prepareConnectorTestProcess has no helper modes or fixtures off Windows.
func prepareConnectorTestProcess() {}

// guardSecureClientTree has no Secure Client folders to watch off Windows.
func guardSecureClientTree() func() []string { return func() []string { return nil } }
