//go:build !darwin && !windows && !linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import "io/fs"

func validateTrustedPathACL(string) error { return nil }

func validateStrictPathACL(string) error { return nil }

func validateAccountPathACL(string, int, string) error { return nil }

func modeWithoutACLMask(_ string, mode fs.FileMode) fs.FileMode { return mode }
