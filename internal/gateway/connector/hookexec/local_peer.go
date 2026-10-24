// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

// VerifyLocalConnectedTuple checks the owner of the accepted server socket
// for a connection to a local service DefenseClaw does not run. Only this
// account or the system account may receive sensitive local-stack requests.
// The exact connected tuple is checked before a request writes any bytes.
func VerifyLocalConnectedTuple(local, remote string) error {
	client, server, err := parseConnectedLoopbackTuple(local, remote)
	if err != nil {
		return err
	}
	return verifyLocalPeerTuple(client, server)
}
