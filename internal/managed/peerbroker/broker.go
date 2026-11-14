// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package peerbroker is the guardian peer SID broker of managed Windows
// route-only (S1 Q7 lead ruling 2026-11-13). The guardian (LocalSystem)
// serves one question on a named pipe whose DACL lets only the gateway
// service SID connect: which account owns the client end of a loopback TCP
// connection the gateway accepted. The gateway sends the connection 4-tuple
// (TCP, so the protocol is implied) and the PID and creation time it read
// from the kernel TCP table; the broker answers only when the authenticated
// gateway owns the server end, that PID still owns the client end with that
// creation time, and the process started no later than the connection (PID
// reuse). It keeps no other operation, so the gateway needs no
// SeDebugPrivilege and has no in-process fallback.
//
// The pipe name is new on every guardian start (a random suffix) and is
// published in a file only LocalSystem and Administrators can write, so no
// account can create the pipe before the guardian does (REVIEW-code-winroute
// P2-1).
package peerbroker

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"github.com/defenseclaw/defenseclaw/internal/peercred"
)

const (
	// ProtocolVersion is the request, response and published-name version.
	ProtocolVersion = 1
	// MaxMessageBytes bounds a request, a response and the published name.
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
	publishedFileBase      = "peer-broker-pipe"
	// pipeSuffixBytes is the random part of the pipe name (hex encoded).
	pipeSuffixBytes = 16
)

var (
	// ErrUnavailable: no broker answered (not published, not running, its
	// pipe is held by a process that is not the guardian, busy, or a
	// timeout). Managed Windows route-only refuses every caller meanwhile.
	// UnavailableError carries the category.
	ErrUnavailable = errors.New("peer broker unavailable")
	// ErrRefused: the broker answered and did not verify the peer.
	ErrRefused = errors.New("peer broker refused the lookup")
	// ErrProtocol: a malformed request or response.
	ErrProtocol = errors.New("peer broker protocol violation")
	// ErrUnsupportedPlatform: the broker exists only on Windows.
	ErrUnsupportedPlatform = errors.New("peer broker is supported only on Windows")
)

// Why the broker is unavailable (UnavailableError.Reason; never a secret,
// a path or an account name).
const (
	// UnavailableNoService: the gateway service environment names no valid
	// gateway service.
	UnavailableNoService = "no_gateway_service"
	// UnavailableNotPublished: no valid published pipe name (the guardian
	// broker has not started).
	UnavailableNotPublished = "not_published"
	// UnavailableHeld: the published pipe is served by a process that is not
	// the guardian (HolderPID names it when known).
	UnavailableHeld = "held"
	// UnavailableBusy: every broker slot is in use.
	UnavailableBusy = "busy"
	// UnavailableNoAnswer: the pipe did not open or the exchange failed.
	UnavailableNoAnswer = "no_answer"
)

// UnavailableError is ErrUnavailable with its category.
type UnavailableError struct {
	Reason string
	// HolderPID is the process serving the pipe instead of the guardian
	// (Reason held), 0 when unknown.
	HolderPID uint32
}

func (e *UnavailableError) Error() string {
	if e.HolderPID != 0 {
		return fmt.Sprintf("%s: %s (pid %d)", ErrUnavailable, e.Reason, e.HolderPID)
	}
	return fmt.Sprintf("%s: %s", ErrUnavailable, e.Reason)
}

// Is makes errors.Is(err, ErrUnavailable) hold.
func (e *UnavailableError) Is(target error) bool { return target == ErrUnavailable }

func unavailable(reason string) error { return &UnavailableError{Reason: reason} }

// Describe is the fixed status text of a lookup error: the category only,
// never raw Win32 or internal error text (doctor row Route-only peer
// broker).
func Describe(err error) string {
	var u *UnavailableError
	switch {
	case err == nil:
		return ""
	case errors.As(err, &u):
		switch u.Reason {
		case UnavailableNoService:
			return "the gateway service environment names no gateway service"
		case UnavailableNotPublished:
			return "the hook guardian has not published its broker pipe"
		case UnavailableHeld:
			if u.HolderPID != 0 {
				return fmt.Sprintf("the broker pipe is held by process %d, not the hook guardian", u.HolderPID)
			}
			return "the broker pipe is held by a process that is not the hook guardian"
		case UnavailableBusy:
			return "the broker is busy"
		}
		return "the broker did not answer"
	case errors.Is(err, ErrRefused):
		for _, category := range refusalCategories {
			if strings.HasSuffix(err.Error(), ": "+category) {
				return "the broker refused the lookup (" + category + ")"
			}
		}
		return "the broker refused the lookup"
	case errors.Is(err, ErrUnavailable):
		return "the broker did not answer"
	}
	return "the lookup failed"
}

var certGatewayPattern = lazyregexp.New(`^DefenseClawCertGateway_([a-f0-9]{10})$`)

// Names are the service names, the pipe name prefix and the published-name
// file of one production or certification scope, all derived from the
// gateway service name.
type Names struct {
	Gateway  string
	Guardian string
	// PipePrefix is the pipe name without its random per-start suffix.
	PipePrefix string
	// File is the base name of the published-name file in <data dir>\hooks.
	File string
}

// NamesFor derives the guardian service, the pipe prefix and the published
// file from the gateway service name; any other gateway name is refused.
func NamesFor(gatewayService string) (Names, error) {
	if gatewayService == defaultGatewayService {
		return Names{Gateway: gatewayService, Guardian: defaultGuardianService, PipePrefix: localPipePrefix + defaultPipeLeaf, File: publishedFileBase + ".json"}, nil
	}
	if m := certGatewayPattern.FindStringSubmatch(gatewayService); m != nil {
		return Names{Gateway: gatewayService, Guardian: certGuardianPrefix + m[1], PipePrefix: localPipePrefix + defaultPipeLeaf + "_" + m[1], File: publishedFileBase + "_" + m[1] + ".json"}, nil
	}
	return Names{}, fmt.Errorf("%w: invalid gateway service identity", ErrProtocol)
}

// PublishedPath is the published-name file under the machine data dir.
func (n Names) PublishedPath(dataDir string) string {
	return filepath.Join(dataDir, "hooks", n.File)
}

// NewPipeName is a fresh pipe name of this scope: the prefix and a random
// suffix, so no account can create it before the guardian does.
func (n Names) NewPipeName() (string, error) {
	raw := make([]byte, pipeSuffixBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return n.PipePrefix + "_" + hex.EncodeToString(raw), nil
}

// validPipeName reports a pipe name NewPipeName gives for this scope.
func (n Names) validPipeName(name string) bool {
	suffix, ok := strings.CutPrefix(name, n.PipePrefix+"_")
	if !ok || len(suffix) != 2*pipeSuffixBytes {
		return false
	}
	for _, c := range suffix {
		if (c < 0x30 || c > 0x39) && (c < 0x61 || c > 0x66) {
			return false
		}
	}
	return true
}

// Published is the published-name record: the pipe the guardian serves now
// and the guardian process PID (the client also requires the pipe server
// to be that process).
type Published struct {
	Version int    `json:"version"`
	Pipe    string `json:"pipe"`
	PID     uint32 `json:"pid"`
}

// EncodePublished returns the bounded JSON of a valid record.
func (n Names) EncodePublished(p Published) ([]byte, error) {
	if p.Version != ProtocolVersion || p.PID == 0 || !n.validPipeName(p.Pipe) {
		return nil, fmt.Errorf("%w: invalid published pipe name", ErrProtocol)
	}
	return encodeBounded(p)
}

// DecodePublished parses and validates a published-name record of this
// scope.
func (n Names) DecodePublished(raw []byte) (Published, error) {
	var p Published
	if err := decodeStrict(raw, &p); err != nil || p.Version != ProtocolVersion || p.PID == 0 || !n.validPipeName(p.Pipe) {
		return Published{}, fmt.Errorf("%w: invalid published pipe name", ErrProtocol)
	}
	return p, nil
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

// Response is the answer: the token user SID of the client process, or a
// refusal category.
type Response struct {
	Version int    `json:"version"`
	OK      bool   `json:"ok"`
	SID     string `json:"sid,omitempty"`
	Error   string `json:"error,omitempty"`
}

// Refusal categories (never a secret, never an account name).
const (
	RefusedBadRequest   = "bad_request"
	RefusedNotFound     = "not_found"
	RefusedNotAccepted  = "not_accepted"
	RefusedOwnerChanged = "owner_changed"
	RefusedUnverified   = "unverified"
	// RefusedBusy: every broker slot is in use (the gateway reads it as
	// unavailable, UnavailableBusy).
	RefusedBusy = "busy"
)

var refusalCategories = []string{RefusedBadRequest, RefusedNotFound, RefusedNotAccepted, RefusedOwnerChanged, RefusedUnverified, RefusedBusy}

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
// A busy refusal is unavailable (UnavailableBusy), not a refusal.
func DecodeResponse(message []byte) (peercred.PeerIdentity, error) {
	var r Response
	if err := decodeStrict(message, &r); err != nil || r.Version != ProtocolVersion {
		return peercred.PeerIdentity{}, fmt.Errorf("%w: malformed response", ErrProtocol)
	}
	if !r.OK {
		if r.SID != "" || !refusalCategory(r.Error) {
			return peercred.PeerIdentity{}, fmt.Errorf("%w: malformed refusal", ErrProtocol)
		}
		if r.Error == RefusedBusy {
			return peercred.PeerIdentity{}, unavailable(UnavailableBusy)
		}
		return peercred.PeerIdentity{}, fmt.Errorf("%w: %s", ErrRefused, r.Error)
	}
	if r.Error != "" || !sidPattern.MatchString(r.SID) {
		return peercred.PeerIdentity{}, fmt.Errorf("%w: malformed answer", ErrProtocol)
	}
	return peercred.PeerIdentity{SID: r.SID}, nil
}

func refusalCategory(v string) bool {
	for _, category := range refusalCategories {
		if v == category {
			return true
		}
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
