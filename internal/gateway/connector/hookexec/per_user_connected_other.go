// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin && !windows

package hookexec

import (
	"errors"
	"net"
)

func verifyLocalPeerTuple(_, _ *net.TCPAddr) error {
	return errors.New("local peer socket ownership is unavailable on this OS")
}

func verifyPerUserConnectedTuple(_, _ *net.TCPAddr) error {
	return errors.New("connected gateway socket ownership is unavailable on this OS")
}
