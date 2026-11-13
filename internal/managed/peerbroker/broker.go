// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package peerbroker is the guardian peer SID broker of managed Windows
// route-only (S1 Q7 lead ruling 2026-11-13). The guardian (LocalSystem)
// serves one question on a named pipe whose DACL lets only the gateway
// service SID connect: which account and session own the client end of a
// loopback TCP connection the gateway accepted. The gateway sends the
// connection 4-tuple (TCP, so the protocol is implied) and the PID and
// creation time it read from the kernel TCP table; the broker answers only
// when the authenticated gateway owns the server end, that PID still owns
// the client end with that creation time, and the process started no later
// than the connection (PID reuse). It keeps no other operation, so the
// gateway needs no SeDebugPrivilege and has no in-process fallback.
package peerbroker

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"github.com/defenseclaw/defenseclaw/internal/peercred"
)

const (
	// ProtocolVersion is the request and response version.
	ProtocolVersion = 1
	// MaxMessageBytes bounds a request and a response.
	MaxMessageBytes = 1024
	// OperationTimeout bounds one exchange on both ends.
	OperationTimeout = 2 * time.Second
	// GatewayServiceEnv names the gateway service in the protected service
	// environment of both the gateway and the guardian.
	GatewayServiceEnv = "DEFENSECLAW_WINDOWS_GATEWAY_SERVICE_NAME"

	defaultGatewayService  = "DefenseClawGateway"
	defaultGuardianService = "DefenseClawHookGuardian"
	defaultPipeLeaf        = "DefenseClawPeerBroker"
	certGuardianPrefix     = "DefenseClawCertGuardian_"
	localPipePrefix        = `\\.\pipe\`
)

var (
	// ErrUnavailable: no broker answered (not installed, not running, its
	// pipe is held by a process that is not the guardian, or a timeout).
	// Managed Windows route-only refuses every caller meanwhile.
	ErrUnavailable = errors.New("peer broker unavailable")
	// ErrRefused: the broker answered and did not verify the peer.
	ErrRefused = errors.New("peer broker refused the lookup")
	// ErrProtocol: a malformed request or response.
	ErrProtocol = errors.New("peer broker protocol violation")
	// ErrUnsupportedPlatform: the broker exists only on Windows.
	ErrUnsupportedPlatform = errors.New("peer broker is supported only on Windows")
)

var certGatewayPattern = lazyregexp.New(`^DefenseClawCertGateway_([a-f0-9]{10})$`)

// Names are the service and pipe names of one production or certification
// scope, all derived from the gateway service name.
type Names struct {
	Gateway  string
	Guardian string
	Pipe     string
}

// NamesFor derives the guardian service and the pipe from the gateway
// service name; any other gateway name is refused.
func NamesFor(gatewayService string) (Names, error) {
	if gatewayService == defaultGatewayService {
		return Names{Gateway: gatewayService, Guardian: defaultGuardianService, Pipe: localPipePrefix + defaultPipeLeaf}, nil
	}
	if m := certGatewayPattern.FindStringSubmatch(gatewayService); m != nil {
		return Names{Gateway: gatewayService, Guardian: certGuardianPrefix + m[1], Pipe: localPipePrefix + defaultPipeLeaf + "_" + m[1]}, nil
	}
	return Names{}, fmt.Errorf("%w: invalid gateway service identity", ErrProtocol)
}

// Request is the one question: who owns the client end of the connection
// local (the address the gateway accepted it on) and remote (the client)?
type Request struct {
	Version    int    `json:"version"`
	PID        uint32 `json:"pid"`
	CreateTime uint64 `json:"create_time"`
	Local      string `json:"local"`
	Remote     string `json:"remote"`
}

// Response is the answer: the token user SID and session of the client
// process, or a refusal category.
type Response struct {
	Version int    `json:"version"`
	OK      bool   `json:"ok"`
	SID     string `json:"sid,omitempty"`
	Session uint32 `json:"session,omitempty"`
	Error   string `json:"error,omitempty"`
}

// Refusal categories (never a secret, never an account name).
const (
	RefusedBadRequest   = "bad_request"
	RefusedNotFound     = "not_found"
	RefusedNotAccepted  = "not_accepted"
	RefusedOwnerChanged = "owner_changed"
	RefusedUnverified   = "unverified"
)

var sidPattern = lazyregexp.New(`^S-1-[0-9]{1,14}(-[0-9]{1,10}){1,15}$`)

// NewRequest builds the request for a connection.
func NewRequest(local, remote *net.TCPAddr, owner peercred.TCPConnOwner) (Request, error) {
	if local == nil || remote == nil {
		return Request{}, fmt.Errorf("%w: missing address", ErrProtocol)
	}
	request := Request{Version: ProtocolVersion, PID: owner.PID, CreateTime: owner.CreateTime, Local: unmapped(local), Remote: unmapped(remote)}
	if _, _, err := request.addresses(); err != nil {
		return Request{}, err
	}
	return request, nil
}

// unmapped spells an address without the IPv4-mapped IPv6 form.
func unmapped(a *net.TCPAddr) string {
	ap := a.AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()).String()
}

// addresses validates the request and returns its loopback endpoints.
func (r Request) addresses() (*net.TCPAddr, *net.TCPAddr, error) {
	if r.Version != ProtocolVersion || r.PID == 0 || r.PID == 4 || r.CreateTime == 0 {
		return nil, nil, fmt.Errorf("%w: invalid request fields", ErrProtocol)
	}
	parse := func(value string) (*net.TCPAddr, error) {
		ap, err := netip.ParseAddrPort(value)
		if err != nil || ap.Port() == 0 || ap.Addr().Zone() != "" || !ap.Addr().Unmap().IsLoopback() {
			return nil, fmt.Errorf("%w: invalid loopback address", ErrProtocol)
		}
		return net.TCPAddrFromAddrPort(ap), nil
	}
	local, err := parse(r.Local)
	if err != nil {
		return nil, nil, err
	}
	remote, err := parse(r.Remote)
	if err != nil {
		return nil, nil, err
	}
	return local, remote, nil
}

// EncodeRequest returns the bounded JSON of a valid request.
func EncodeRequest(r Request) ([]byte, error) {
	if _, _, err := r.addresses(); err != nil {
		return nil, err
	}
	return encodeBounded(r)
}

// DecodeResponse parses and validates a response; ok answers carry a SID.
func DecodeResponse(message []byte) (peercred.PeerIdentity, error) {
	var r Response
	if err := decodeStrict(message, &r); err != nil || r.Version != ProtocolVersion {
		return peercred.PeerIdentity{}, fmt.Errorf("%w: malformed response", ErrProtocol)
	}
	if !r.OK {
		if r.SID != "" || r.Session != 0 || !refusalCategory(r.Error) {
			return peercred.PeerIdentity{}, fmt.Errorf("%w: malformed refusal", ErrProtocol)
		}
		return peercred.PeerIdentity{}, fmt.Errorf("%w: %s", ErrRefused, r.Error)
	}
	if r.Error != "" || !sidPattern.MatchString(r.SID) {
		return peercred.PeerIdentity{}, fmt.Errorf("%w: malformed answer", ErrProtocol)
	}
	return peercred.PeerIdentity{SID: r.SID, SessionID: r.Session}, nil
}

func refusalCategory(v string) bool {
	switch v {
	case RefusedBadRequest, RefusedNotFound, RefusedNotAccepted, RefusedOwnerChanged, RefusedUnverified:
		return true
	}
	return false
}

func decodeStrict(message []byte, destination any) error {
	if len(message) == 0 || len(message) > MaxMessageBytes {
		return errors.New("message size")
	}
	decoder := json.NewDecoder(bytes.NewReader(message))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("extra JSON value")
	}
	return nil
}

func encodeBounded(v any) ([]byte, error) {
	message, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if len(message) == 0 || len(message) > MaxMessageBytes {
		return nil, fmt.Errorf("%w: message exceeds bounds", ErrProtocol)
	}
	return message, nil
}
