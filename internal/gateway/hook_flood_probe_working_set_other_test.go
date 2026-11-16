// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

// hookFloodWorkingSet: the resident set comes from /proc on Linux.
func hookFloodWorkingSet() string { return "" }
