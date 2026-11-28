//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"os"
	"strings"
)

// GatewayServiceAccount is the NT SERVICE account that may write the managed
// runtime tree, for a reader of a service-written runtime file. The gateway
// and guardian services carry it as the WindowsServiceAccountEnv pin in their
// registry Environment; a console the administrator opened (enterprise
// windows status, verify, doctor, hooks verify) carries no such pin, so a
// reader that took only the environment refused the Modify entry the gateway
// service holds on the runtime folder and inherits onto the files it writes
// (GAP-0081).
//
// An unpinned binary that sits in a standalone install root gets the gateway
// service the installer registered for that root and no other: the
// production account for the production root, the run-scoped account for a
// certification root. The account is derived from the protected install
// location of the running binary, never from a name the caller supplies. A
// process outside every install root, Secure Client included, keeps the pin
// alone, so an unpinned process there stays on the administrator-only rule.
func GatewayServiceAccount() string {
	if account := strings.TrimSpace(os.Getenv(WindowsServiceAccountEnv)); account != "" {
		return account
	}
	if service := windowsStandaloneInstallService(); service != "" {
		return `NT SERVICE\` + service
	}
	return ""
}

// DeploymentGatewayService is the gateway service of this deployment, for a
// check that must recognise that service's grants and no other: the service
// of GatewayServiceAccount (the WindowsServiceAccountEnv pin the managed
// services carry, else the service the installer registered for the install
// root of the running binary) when it is the production gateway or a
// run-scoped certification gateway (DefenseClawCertGateway_<10 lowercase
// hex>, the pattern the installer and the hook enumerator use), and the
// production gateway otherwise. Another service, an account outside NT
// SERVICE or a malformed scope is never returned (rel-1-0-10 GAP-2125: the
// agent config owner heal took only the production gateway, so a
// certification install's enumerator read grant was never recognised).
func DeploymentGatewayService() string {
	const prefix = `NT SERVICE\`
	account := GatewayServiceAccount()
	if len(account) > len(prefix) && strings.EqualFold(account[:len(prefix)], prefix) {
		name := account[len(prefix):]
		if strings.EqualFold(name, StandaloneWindowsGatewaySvc) {
			return StandaloneWindowsGatewaySvc
		}
		if managedServiceCertGateway.MatchString(name) {
			return name
		}
	}
	return StandaloneWindowsGatewaySvc
}
