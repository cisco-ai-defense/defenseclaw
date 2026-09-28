// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import "github.com/defenseclaw/defenseclaw/internal/winenterprise"

// refusePerUserGatewayBesideEnterprise stops a per-user gateway from starting
// on a Windows computer that has an administrator-managed enterprise
// deployment. Both would serve hooks on the same local port, and the managed
// hooks of every user fail closed while another listener holds it. It is a
// no-op off Windows and for the enterprise gateway service itself.
var refusePerUserGatewayBesideEnterprise = func() error {
	return winenterprise.RefusePerUser("start its gateway")
}
