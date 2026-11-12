//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxapi

import (
	"net"

	"golang.org/x/sys/unix"
)

type credentialStatusConn struct {
	*net.UnixConn
	evidence *statusPeerEvidence
}

// Linux systemd owns the listening socket, so SO_PEERCRED names the user
// manager. SO_PASSCRED instead identifies the process writing each response.
func statusPeerConn(conn net.Conn, evidence *statusPeerEvidence) net.Conn {
	u, ok := conn.(*net.UnixConn)
	if !ok {
		return conn
	}
	raw, err := u.SyscallConn()
	if err != nil {
		return conn
	}
	var sockErr error
	if err = raw.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1)
	}); err != nil || sockErr != nil {
		return conn
	}
	return &credentialStatusConn{UnixConn: u, evidence: evidence}
}

func (c *credentialStatusConn) Read(p []byte) (int, error) {
	control := make([]byte, unix.CmsgSpace(unix.SizeofUcred))
	n, oobn, flags, _, err := c.ReadMsgUnix(p, control)
	if n > 0 {
		if flags&unix.MSG_CTRUNC != 0 {
			c.evidence.invalid = true
		}
		msgs, parseErr := unix.ParseSocketControlMessage(control[:oobn])
		if parseErr != nil {
			c.evidence.invalid = true
		}
		found := false
		for _, msg := range msgs {
			if msg.Header.Level != unix.SOL_SOCKET || msg.Header.Type != unix.SCM_CREDENTIALS {
				continue
			}
			cred, credErr := unix.ParseUnixCredentials(&msg)
			if credErr != nil || found {
				c.evidence.invalid = true
				continue
			}
			found = true
			c.evidence.record(int(cred.Pid), int(cred.Uid))
		}
		if !found {
			c.evidence.invalid = true
		}
	}
	return n, err
}
