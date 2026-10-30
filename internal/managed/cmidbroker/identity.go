// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cmidbroker

import (
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
)

const (
	defaultGatewayService = "DefenseClawGateway"
	defaultBrokerService  = "DefenseClawCMIDBroker"
	localPipePrefix       = `\\.\pipe\`
)

var certificationGatewayPattern = lazyregexp.New(`^DefenseClawCertGateway_([a-f0-9]{10})$`)

// ValidateIdentityBinding ensures all names describe one production or
// certification scope. The pipe leaf is exactly the broker service name, so a
// protected service environment cannot redirect the gateway to a different
// DefenseClaw-prefixed pipe.
func ValidateIdentityBinding(brokerService, gatewayService, pipeName string) error {
	expectedBroker := ""
	switch {
	case gatewayService == defaultGatewayService:
		expectedBroker = defaultBrokerService
	case certificationGatewayPattern.MatchString(gatewayService):
		scope := certificationGatewayPattern.FindStringSubmatch(gatewayService)[1]
		expectedBroker = defaultBrokerService + "_" + scope
	default:
		return fmt.Errorf("%w: invalid gateway service identity", ErrProtocol)
	}
	if brokerService != expectedBroker {
		return fmt.Errorf("%w: broker and gateway service scopes differ", ErrProtocol)
	}
	if pipeName != localPipePrefix+expectedBroker ||
		strings.Contains(strings.TrimPrefix(pipeName, localPipePrefix), `\`) {
		return fmt.Errorf("%w: pipe and broker service identities differ", ErrProtocol)
	}
	return nil
}

// gatewayServiceAccountAccepted reports whether an SCM ServiceStartName is a
// supported logon account for the gateway service: LocalSystem, or the
// gateway's own virtual account used by earlier releases. Hosts upgrading
// between the two keep a working broker.
func gatewayServiceAccountAccepted(startName, gatewayServiceName string) bool {
	startName = strings.TrimSpace(startName)
	return strings.EqualFold(startName, "LocalSystem") ||
		strings.EqualFold(startName, `NT AUTHORITY\SYSTEM`) ||
		strings.EqualFold(startName, `NT SERVICE\`+gatewayServiceName)
}
