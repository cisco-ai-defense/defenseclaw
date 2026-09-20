// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cmidbroker

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	defaultGatewayService = "DefenseClawGateway"
	defaultBrokerService  = "DefenseClawCMIDBroker"
	localPipePrefix       = `\\.\pipe\`
)

var certificationGatewayPattern = regexp.MustCompile(`^DefenseClawCertGateway_([a-f0-9]{10})$`)

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
