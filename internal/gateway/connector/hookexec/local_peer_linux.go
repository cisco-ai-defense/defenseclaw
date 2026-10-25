// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"errors"
	"net"
	"os"
)

func verifyLocalPeerTuple(client, server *net.TCPAddr) error {
	return verifyLocalPeerIn(procSelfNet, client, server)
}

func verifyLocalPeerIn(procNet string, client, server *net.TCPAddr) error {
	uid, err := findConnectedTCPUID(procNet, client, server)
	if err != nil {
		return err
	}
	if uid != os.Geteuid() && uid != 0 {
		return errors.New("local peer socket belongs to another account")
	}
	return nil
}
