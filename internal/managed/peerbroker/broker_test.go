// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package peerbroker

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/peercred"
)

const testSID = "S-1-5-21-100-200-300-1001"

var (
	testLocal  = &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 18970}
	testRemote = &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 51234}
	testOwner  = peercred.TCPConnOwner{PID: 4242, CreateTime: 133_000_000_000_000_000}
)

func TestNamesForBindsOneScope(t *testing.T) {
	got, err := NamesFor("DefenseClawGateway")
	if err != nil || got.Guardian != "DefenseClawHookGuardian" || got.Pipe != `\\.\pipe\DefenseClawPeerBroker` {
		t.Fatalf("production names = %+v, %v", got, err)
	}
	got, err = NamesFor("DefenseClawCertGateway_0123456789")
	if err != nil || got.Guardian != "DefenseClawCertGuardian_0123456789" || got.Pipe != `\\.\pipe\DefenseClawPeerBroker_0123456789` {
		t.Fatalf("certification names = %+v, %v", got, err)
	}
	for _, bad := range []string{"", "DefenseClawGateway2", "OtherGateway", "DefenseClawCertGateway_XYZ", `DefenseClawCertGateway_0123456789\x`} {
		if _, err := NamesFor(bad); err == nil {
			t.Fatalf("NamesFor(%q) accepted", bad)
		}
	}
}

func encodeTestRequest(t *testing.T) []byte {
	t.Helper()
	request, err := NewRequest(testLocal, testRemote, testOwner)
	if err != nil {
		t.Fatal(err)
	}
	message, err := EncodeRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	return message
}

// TestAnswerAsksTheKernelOnlyForTheAuthenticatedCaller: the verifier gets
// the request endpoints, the authenticated gateway PID as the server owner
// and the PID and creation time the gateway read; the answer round-trips.
func TestAnswerAsksTheKernelOnlyForTheAuthenticatedCaller(t *testing.T) {
	var gotServer uint32
	var gotWant peercred.TCPConnOwner
	verify := func(local, remote *net.TCPAddr, serverPID uint32, want peercred.TCPConnOwner) (peercred.PeerIdentity, error) {
		if !local.IP.Equal(testLocal.IP) || local.Port != testLocal.Port || remote.Port != testRemote.Port {
			t.Fatalf("verifier got %v -> %v", remote, local)
		}
		gotServer, gotWant = serverPID, want
		return peercred.PeerIdentity{SID: testSID, SessionID: 3}, nil
	}
	response, outcome := Answer(encodeTestRequest(t), 900, verify)
	identity, err := DecodeResponse(response)
	if err != nil || identity.SID != testSID || identity.SessionID != 3 || outcome != "verified" {
		t.Fatalf("answer = %+v, %v (%s)", identity, err, outcome)
	}
	if gotServer != 900 || gotWant != testOwner {
		t.Fatalf("verifier asked for server %d want %+v", gotServer, gotWant)
	}
}

func TestAnswerRefusals(t *testing.T) {
	ok := func(*net.TCPAddr, *net.TCPAddr, uint32, peercred.TCPConnOwner) (peercred.PeerIdentity, error) {
		return peercred.PeerIdentity{SID: testSID}, nil
	}
	failWith := func(err error) Verifier {
		return func(*net.TCPAddr, *net.TCPAddr, uint32, peercred.TCPConnOwner) (peercred.PeerIdentity, error) {
			return peercred.PeerIdentity{}, err
		}
	}
	good := string(encodeTestRequest(t))
	cases := []struct {
		name     string
		message  string
		caller   uint32
		verify   Verifier
		category string
	}{
		{"not JSON", "nope", 900, ok, RefusedBadRequest},
		{"unknown field", strings.Replace(good, "{", `{"op":"token",`, 1), 900, ok, RefusedBadRequest},
		{"two values", good + good, 900, ok, RefusedBadRequest},
		{"oversize", good + strings.Repeat(" ", MaxMessageBytes), 900, ok, RefusedBadRequest},
		{"wrong version", strings.Replace(good, `"version":1`, `"version":2`, 1), 900, ok, RefusedBadRequest},
		{"system PID", strings.Replace(good, `"pid":4242`, `"pid":4`, 1), 900, ok, RefusedBadRequest},
		{"no creation time", strings.Replace(good, `"create_time":133000000000000000`, `"create_time":0`, 1), 900, ok, RefusedBadRequest},
		{"remote address", strings.Replace(good, `"remote":"127.0.0.1:51234"`, `"remote":"10.0.0.5:51234"`, 1), 900, ok, RefusedBadRequest},
		{"zoned address", strings.Replace(good, `"local":"127.0.0.1:18970"`, `"local":"[::1%eth0]:18970"`, 1), 900, ok, RefusedBadRequest},
		{"port zero", strings.Replace(good, `"local":"127.0.0.1:18970"`, `"local":"127.0.0.1:0"`, 1), 900, ok, RefusedBadRequest},
		{"unauthenticated caller", good, 0, ok, RefusedBadRequest},
		{"connection gone", good, 900, failWith(peercred.ErrPeerNotFound), RefusedNotFound},
		{"caller did not accept it", good, 900, failWith(peercred.ErrNotAccepted), RefusedNotAccepted},
		{"PID or creation time differ", good, 900, failWith(peercred.ErrOwnerChanged), RefusedOwnerChanged},
		{"reused PID or access denied", good, 900, failWith(errors.New("started after the connection")), RefusedUnverified},
		{"verifier returned no SID", good, 900, failWith(nil), RefusedUnverified},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response, outcome := Answer([]byte(tc.message), tc.caller, tc.verify)
			identity, err := DecodeResponse(response)
			if !errors.Is(err, ErrRefused) || identity.SID != "" || outcome != tc.category || !strings.Contains(err.Error(), tc.category) {
				t.Fatalf("answer = %+v, %v (%s); want refusal %s", identity, err, outcome, tc.category)
			}
		})
	}
}

func TestDecodeResponseRejectsMalformedAnswers(t *testing.T) {
	for _, message := range []string{
		``,
		`{"version":1,"ok":true}`,
		`{"version":1,"ok":true,"sid":"alice"}`,
		`{"version":1,"ok":true,"sid":"` + testSID + `","error":"x"}`,
		`{"version":1,"ok":false,"sid":"` + testSID + `","error":"unverified"}`,
		`{"version":1,"ok":false,"error":"something else"}`,
		`{"version":2,"ok":true,"sid":"` + testSID + `"}`,
		`{"version":1,"ok":true,"sid":"` + testSID + `","token":"x"}`,
	} {
		if identity, err := DecodeResponse([]byte(message)); err == nil || identity.SID != "" {
			t.Fatalf("DecodeResponse(%s) = %+v, %v; want an error", message, identity, err)
		}
	}
}

func TestNewRequestRefusesNonLoopback(t *testing.T) {
	if _, err := NewRequest(testLocal, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 5}, testOwner); err == nil {
		t.Fatal("a non-loopback client was accepted")
	}
	if _, err := NewRequest(testLocal, testRemote, peercred.TCPConnOwner{PID: 4242}); err == nil {
		t.Fatal("a request without a creation time was accepted")
	}
	v6 := &net.TCPAddr{IP: net.ParseIP("::1"), Port: 18970}
	if _, err := NewRequest(v6, &net.TCPAddr{IP: net.ParseIP("::1"), Port: 50000}, testOwner); err != nil {
		t.Fatalf("IPv6 loopback refused: %v", err)
	}
}
