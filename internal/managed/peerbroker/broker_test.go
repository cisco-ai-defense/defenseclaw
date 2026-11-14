// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package peerbroker

import (
	"errors"
	"fmt"
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
	if err != nil || got.Guardian != "DefenseClawHookGuardian" || got.PipePrefix != `\\.\pipe\DefenseClawPeerBroker` || got.File != "peer-broker-pipe.json" {
		t.Fatalf("production names = %+v, %v", got, err)
	}
	got, err = NamesFor("DefenseClawCertGateway_0123456789")
	if err != nil || got.Guardian != "DefenseClawCertGuardian_0123456789" || got.PipePrefix != `\\.\pipe\DefenseClawPeerBroker_0123456789` || got.File != "peer-broker-pipe_0123456789.json" {
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
		return peercred.PeerIdentity{SID: testSID}, nil
	}
	response, outcome := Answer(encodeTestRequest(t), 900, verify)
	identity, err := DecodeResponse(response)
	if err != nil || identity.SID != testSID || outcome != "verified" {
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
		`{"version":1,"ok":true,"sid":"` + testSID + `","session":1}`,
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

// TestPipeNamesAreFreshPerStart: every start gets another random name of
// its scope, so no account can create the pipe before the guardian does
// (REVIEW-code-winroute P2-1).
func TestPipeNamesAreFreshPerStart(t *testing.T) {
	names, _ := NamesFor("DefenseClawCertGateway_0123456789")
	other, _ := NamesFor("DefenseClawGateway")
	first, err := names.NewPipeName()
	if err != nil {
		t.Fatal(err)
	}
	second, _ := names.NewPipeName()
	if first == second || !names.validPipeName(first) || !names.validPipeName(second) {
		t.Fatalf("pipe names %q, %q", first, second)
	}
	if other.validPipeName(first) {
		t.Fatal("a certification pipe name is valid for production")
	}
	for _, bad := range []string{names.PipePrefix, names.PipePrefix + "_", names.PipePrefix + "_" + strings.Repeat("A", 32), names.PipePrefix + "_" + strings.Repeat("a", 31), names.PipePrefix + "_" + strings.Repeat("a", 33), `\\.\pipe\Other_` + strings.Repeat("a", 32)} {
		if names.validPipeName(bad) {
			t.Fatalf("validPipeName(%q) accepted", bad)
		}
	}
}

// TestPublishedRecordRoundTrip: the published record names a pipe of the
// scope and a PID; anything else is refused on both ends.
func TestPublishedRecordRoundTrip(t *testing.T) {
	names, _ := NamesFor("DefenseClawGateway")
	pipe, _ := names.NewPipeName()
	raw, err := names.EncodePublished(Published{Version: ProtocolVersion, Pipe: pipe, PID: 1234})
	if err != nil {
		t.Fatal(err)
	}
	got, err := names.DecodePublished(raw)
	if err != nil || got.Pipe != pipe || got.PID != 1234 {
		t.Fatalf("decode = %+v, %v", got, err)
	}
	if _, err := names.EncodePublished(Published{Version: ProtocolVersion, Pipe: names.PipePrefix, PID: 1234}); err == nil {
		t.Fatal("a fixed pipe name was published")
	}
	for _, bad := range []string{
		``,
		`{"version":1,"pipe":"` + strings.ReplaceAll(pipe, `\`, `\\`) + `","pid":0}`,
		`{"version":2,"pipe":"` + strings.ReplaceAll(pipe, `\`, `\\`) + `","pid":5}`,
		`{"version":1,"pipe":"` + strings.ReplaceAll(names.PipePrefix, `\`, `\\`) + `","pid":5}`,
		`{"version":1,"pipe":"` + strings.ReplaceAll(pipe, `\`, `\\`) + `","pid":5,"extra":1}`,
		string(raw) + string(raw),
	} {
		if _, err := names.DecodePublished([]byte(bad)); err == nil {
			t.Fatalf("DecodePublished(%s) accepted", bad)
		}
	}
}

// TestBusyIsUnavailableAndDescribeIsFixedText: a busy broker is
// unavailable (not a refusal), and the status text is a fixed category, never
// raw error text.
func TestBusyIsUnavailableAndDescribeIsFixedText(t *testing.T) {
	_, err := DecodeResponse([]byte(`{"version":1,"ok":false,"error":"busy"}`))
	var u *UnavailableError
	if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrRefused) || !errors.As(err, &u) || u.Reason != UnavailableBusy {
		t.Fatalf("busy = %v; want unavailable busy", err)
	}
	_, refused := DecodeResponse([]byte(`{"version":1,"ok":false,"error":"not_found"}`))
	cases := map[string]error{
		"the broker is busy":                                           err,
		"the broker refused the lookup (not_found)":                    refused,
		"the broker pipe is held by process 77, not the hook guardian": &UnavailableError{Reason: UnavailableHeld, HolderPID: 77},
		"the hook guardian has not published its broker pipe":          unavailable(UnavailableNotPublished),
		"the broker did not answer":                                    fmt.Errorf("%w: open: The system cannot find the file C:\\secret", ErrUnavailable),
		"the lookup failed":                                            errors.New("Access is denied. pid 4242"),
	}
	for want, in := range cases {
		if got := Describe(in); got != want {
			t.Fatalf("Describe(%v) = %q; want %q", in, got, want)
		}
	}
}
