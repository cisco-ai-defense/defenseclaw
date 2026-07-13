//go:build !darwin && !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

func validateTrustedPathACL(string) error { return nil }
