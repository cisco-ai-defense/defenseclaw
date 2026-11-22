// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin && !windows

package connector

// codexRequirementsUntrustedAccepted is the macOS admission of a system
// requirements file; no other platform accepts one that is not trusted.
func codexRequirementsUntrustedAccepted(string, error) bool { return false }
