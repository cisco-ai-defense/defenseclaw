// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package peerbroker

import (
	"errors"
	"net"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/peercred"
)

// Verifier is the kernel lookup the broker runs (peercred.VerifyLoopbackTCPPeer
// in production; fakes in the tests).
type Verifier func(local, remote *net.TCPAddr, serverPID uint32, want peercred.TCPConnOwner) (peercred.PeerIdentity, error)

// Answer decides one request from the authenticated gateway process
// callerPID and returns the encoded response: a malformed request is a
// refusal too, so the gateway always gets one bounded answer. It runs no
// other operation.
func Answer(message []byte, callerPID uint32, verify Verifier) ([]byte, string) {
	response := Response{Version: ProtocolVersion}
	var request Request
	local, remote, err := (*net.TCPAddr)(nil), (*net.TCPAddr)(nil), decodeStrict(message, &request)
	if err == nil {
		local, remote, err = request.addresses()
	}
	switch {
	case err != nil || callerPID == 0 || verify == nil:
		response.Error = RefusedBadRequest
	default:
		identity, verifyErr := verify(local, remote, callerPID, peercred.TCPConnOwner{PID: request.PID, CreateTime: request.CreateTime})
		switch {
		case verifyErr == nil && sidPattern.MatchString(identity.SID):
			response.OK, response.SID = true, identity.SID
		case errors.Is(verifyErr, peercred.ErrPeerNotFound):
			response.Error = RefusedNotFound
		case errors.Is(verifyErr, peercred.ErrNotAccepted):
			response.Error = RefusedNotAccepted
		case errors.Is(verifyErr, peercred.ErrOwnerChanged):
			response.Error = RefusedOwnerChanged
		default:
			response.Error = RefusedUnverified
		}
	}
	encoded, err := encodeBounded(response)
	if err != nil {
		encoded, _ = encodeBounded(Response{Version: ProtocolVersion, Error: RefusedUnverified})
		return encoded, RefusedUnverified
	}
	if response.OK {
		return encoded, "verified"
	}
	return encoded, response.Error
}

// Event is one broker log line: the stage, the outcome category and the
// gateway PID (stage create: the PID of the process holding the pipe name,
// 0 when unknown). It never carries a SID or an account name.
type Event struct {
	Stage     string
	Outcome   string
	ClientPID uint32
	Duration  time.Duration
}
