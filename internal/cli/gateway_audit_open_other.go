//go:build !darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

// The guardian repairs the gateway's audit store here; the gateway waits for
// it within a bounded budget and then exits.
const (
	gatewayAuditOpenWaitReason = "audit store unavailable at startup; waiting for the guardian to repair it: "
	gatewayAuditOpenUnbounded  = false
)

func repairGatewayAuditStorePlatform(string, string) {}
