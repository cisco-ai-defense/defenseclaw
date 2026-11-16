// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookexec

import (
	"errors"
	"fmt"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"net"
)

func verifyManagedConnectedTuple(client, server *net.TCPAddr, serviceName string) error {
	if serviceName != managed.StandaloneWindowsGatewaySvc {
		return errors.New("managed gateway service name is untrusted")
	}
	clientEndpoint, err := managedIPv4EndpointFromAddr(client)
	if err != nil {
		return err
	}
	serverEndpoint, err := managedIPv4EndpointFromAddr(server)
	if err != nil {
		return err
	}
	servicePID, err := queryManagedGatewayServicePID(serviceName)
	if err != nil {
		return fmt.Errorf("inspect protected gateway service: %w", err)
	}
	connectedPID, err := connectedManagedGatewayPIDForEndpoints(clientEndpoint, serverEndpoint)
	if err != nil || connectedPID != servicePID {
		return errors.New("connected gateway socket does not belong to the protected service")
	}
	recheckedPID, err := queryManagedGatewayServicePID(serviceName)
	if err != nil || recheckedPID != servicePID {
		return errors.New("managed gateway service changed during peer verification")
	}
	return nil
}
