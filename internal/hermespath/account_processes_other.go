// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows && !darwin

package hermespath

// runningProcessEvidence reads the account's running processes from /proc.
func runningProcessEvidence(uid int) ([]homeEvidence, error) {
	return procProcessEvidence(uid)
}
