// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"fmt"
	"net"
)

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

// VerifyLocalPeer is the one check that a loopback TCP connection
// DefenseClaw opened to a local service it does not run itself (the bundled
// observability stack's collector) reaches that service and not another
// account: the accepted server socket must belong to this account or to the
// system account (root, LocalSystem), which can read this account's data
// anyway. A socket of any other account, or one whose owner cannot be read,
// is sent no byte (GAP-1087). It refuses to send; it never blocks a call.
func VerifyLocalPeer(conn net.Conn) error {
	local, localOK := conn.LocalAddr().(*net.TCPAddr)
	remote, remoteOK := conn.RemoteAddr().(*net.TCPAddr)
	if !localOK || !remoteOK {
		return fmt.Errorf("local peer is not a TCP connection")
	}
	return verifyLocalPeerTuple(local, remote)
}
