// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// TLS framing needed to read a ClientHello (RFC 8446 section 5, RFC 6066
// section 3).
const (
	tlsRecordAlert          = 21
	tlsRecordHandshake      = 22
	tlsHandshakeClientHello = 1
	tlsRecordHeaderLen      = 5
	tlsMaxPlaintext         = 1 << 14
	tlsExtServerName        = 0
	tlsSNIHostName          = 0
	tlsAlertFatal           = 2
	tlsAlertAccessDenied    = 49
	tlsAlertDecodeError     = 50

	// maxClientHelloLen bounds the ClientHello message the way crypto/tls
	// bounds any handshake message.
	maxClientHelloLen = 1 << 16
	// maxFirstFlight bounds everything buffered while the ClientHello is
	// read: record headers, the hello, and bytes pipelined after it.
	maxFirstFlight = 2 * maxClientHelloLen
	firstReadSize  = 4 << 10
)

var (
	errMalformedClientHello = errors.New("egress: malformed TLS ClientHello")
	errFlightTooLong        = errors.New("egress: first flight too long to classify")
	errTunnelRefused        = errors.New("egress: tunnel refused")
)

// flightKind classifies a tunnel's first flight.
type flightKind int

const (
	flightUnknown flightKind = iota // not classifiable yet
	flightEmpty                     // the client closed without sending
	flightTLS                       // a TLS ClientHello, screened for its server name
	flightHTTP                      // an HTTP request line: inspected request by request
	flightOpaque                    // anything else
)

// screenFirstFlight reads the client's first bytes in an established CONNECT
// tunnel, classifies them, and returns them for relaying:
//
//   - A TLS ClientHello naming another host than the CONNECT target is
//     decided again for that server name (SNI). Otherwise a CONNECT to an
//     allowed name or address followed by SNI pastebin.com would reach any
//     blocked site served from the same CDN addresses, in open and
//     allowlist mode alike. A refused tunnel gets a fatal TLS alert.
//   - An HTTP request line (flightHTTP) makes the tunnel carry HTTP/1.x
//     requests that relayRequests checks one by one, since a Host header
//     could front for another site the same way.
//   - Anything else is relayed only on a port the operator added to the
//     port list (a database, SSH): the CONNECT target decided the
//     destination and no name inside can select another. On the web ports
//     it is refused, and so is HTTP/2 without TLS, whose request names
//     cannot be read without decoding it.
//
// Bytes are buffered until they can be classified, for at most
// HeaderTimeout and maxFirstFlight. Only the visible server name is
// checked: an Encrypted Client Hello's outer name and a Host header inside
// the TLS session are out of reach without terminating TLS.
func (p *Proxy) screenFirstFlight(t *tunnel, client net.Conn, r io.Reader) ([]byte, flightKind, error) {
	buf := make([]byte, firstReadSize)
	n, err := r.Read(buf)
	if n == 0 {
		if errors.Is(err, io.EOF) {
			return nil, flightEmpty, nil // pipe sees the EOF again and half-closes upstream
		}
		return nil, flightUnknown, err
	}
	// A client sends its whole ClientHello or request line at once; one that
	// stalls halfway is holding the tunnel open without a checkable name.
	_ = client.SetReadDeadline(time.Now().Add(p.headerTimeout))
	defer func() { _ = client.SetReadDeadline(time.Time{}) }()
	if buf[0] != tlsRecordHandshake {
		flight, kind, err := readUntilClassified(buf[:n], r)
		switch {
		case err != nil:
			p.refuseTunnel(t, client, "The tunnel's first bytes did not arrive in full in time, or are too long, to tell TLS, "+
				"HTTP/1.x and other protocols apart.")
			return nil, flightUnknown, errTunnelRefused
		case kind == flightOpaque && isWebPort(t.dec.Port):
			p.refuseTunnel(t, client, fmt.Sprintf("The tunnel to port %d carried neither TLS nor an HTTP/1.x request. "+
				"Tunnels to the web ports carry only TLS or HTTP/1.x requests for the tunnel's own host (HTTP/2 needs TLS); "+
				"other protocols need a port the operator adds to openshell.egress.ports.", t.dec.Port))
			return nil, flightUnknown, errTunnelRefused
		}
		return flight, kind, nil
	}
	flight, name, err := readClientHello(buf[:n], r)
	if errors.Is(err, errMalformedClientHello) {
		dec := blocked(Decision{Host: t.dec.Host, Port: t.dec.Port, Mode: t.dec.Mode}, CategoryInvalidDestination, SourceGuard, "")
		dec.Reason = "The tunnel's TLS ClientHello is malformed or too large for its server name to be checked."
		p.refuseInTunnel(t, client, dec, tlsAlertDecodeError)
		return nil, flightUnknown, errTunnelRefused
	}
	if err != nil {
		return nil, flightUnknown, err
	}
	// Recorded before it is decided, so a recheck that replaces the
	// tunnel's policy meanwhile decides it again (Proxy.revise).
	pol := t.sawServerName(name)
	if dec, refused := serverNameRefusal(t, pol.pr, pol.d, name); refused {
		p.refuseInTunnel(t, client, dec, tlsAlertAccessDenied)
		return nil, flightUnknown, errTunnelRefused
	}
	return flight, flightTLS, nil
}

// isWebPort reports the default web ports, where only TLS and HTTP/1.x are
// relayed.
func isWebPort(port int) bool { return slices.Contains(DefaultPorts(), port) }

// readUntilClassified reads more of a non-TLS first flight until
// classifyFlight can tell what it is, within maxFirstFlight.
func readUntilClassified(data []byte, r io.Reader) ([]byte, flightKind, error) {
	for {
		if kind := classifyFlight(data); kind != flightUnknown {
			return data, kind, nil
		}
		if len(data) >= maxFirstFlight {
			return data, flightUnknown, errFlightTooLong
		}
		data = slices.Grow(data, firstReadSize)
		m, err := r.Read(data[len(data):min(cap(data), maxFirstFlight)])
		data = data[:len(data)+m]
		if err != nil && m == 0 {
			if errors.Is(err, io.EOF) {
				return data, flightUnknown, io.ErrUnexpectedEOF
			}
			return data, flightUnknown, err
		}
	}
}

// classifyFlight tells an HTTP request line from other protocols. HTTP is
// recognized generously (leading empty lines, any whitespace, any case of
// "HTTP/", any version) so that nothing a lenient server would take for a
// request escapes inspection; flightUnknown means the bytes so far could
// still be the start of a request line.
func classifyFlight(data []byte) flightKind {
	rest := bytes.TrimLeft(data, "\r\n")
	if len(rest) == 0 {
		return flightUnknown
	}
	line, complete := rest, false
	if i := bytes.IndexByte(rest, '\n'); i >= 0 {
		line, complete = rest[:i], true
	}
	method := line
	if i := bytes.IndexAny(line, " \t"); i >= 0 {
		method = line[:i]
	}
	for _, c := range method {
		if !isTokenChar(c) {
			return flightOpaque
		}
	}
	for _, c := range line {
		if (c < 0x20 && c != '\t' && c != '\r') || c == 0x7f {
			return flightOpaque
		}
	}
	if !complete {
		return flightUnknown
	}
	fields := strings.Fields(string(line))
	if len(fields) == 3 && fields[0] == "PRI" && fields[1] == "*" && fields[2] == "HTTP/2.0" {
		return flightOpaque // HTTP/2 prior knowledge
	}
	for _, f := range fields[min(1, len(fields)):] {
		if len(f) >= 5 && strings.EqualFold(f[:5], "HTTP/") {
			return flightHTTP
		}
	}
	return flightOpaque
}

// isTokenChar reports an RFC 9110 tchar.
func isTokenChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

// serverNameRefusal decides the server name a tunnel's ClientHello asked
// for, for pr with d. No name, the CONNECT target itself, and IP literals
// (RFC 6066 forbids them in SNI, and they cannot select a virtual host by
// name) need no second decision.
func serverNameRefusal(t *tunnel, pr Principal, d *Decider, name string) (Decision, bool) {
	if name == "" {
		return Decision{}, false
	}
	host, addr, err := normalizeHost(name)
	if err != nil {
		dec := blocked(Decision{Host: sanitizeHost(name), Port: t.dec.Port, Mode: t.dec.Mode}, CategoryInvalidDestination, SourceGuard, "")
		dec.Reason = "The tunnel's TLS server name (SNI) is not a valid host name."
		return dec, true
	}
	if addr.IsValid() || host == t.dec.Host {
		return Decision{}, false
	}
	dec := d.Decide(pr, host, t.dec.Port)
	if dec.Allowed {
		return Decision{}, false
	}
	dec.Reason = fmt.Sprintf("The tunnel to %s asked for %s in its TLS server name (SNI). %s", t.dec.Host, host, dec.Reason)
	return dec, true
}

// refuseInTunnel ends an established tunnel that failed its server-name
// check. The client already has its 200, so it gets a fatal TLS alert
// (OpenSSL clients report "tlsv1 alert access denied") instead of the JSON
// body; the blocked event carries the decision and the tunnel id.
func (p *Proxy) refuseInTunnel(t *tunnel, client net.Conn, dec Decision, alert byte) {
	t.refused.Store(true)
	p.recordRefusal(t.principal, t.method, dec, statusFor(dec), t.started, t.id)
	_ = client.SetWriteDeadline(time.Now().Add(rawWriteTimeout))
	if _, err := client.Write([]byte{tlsRecordAlert, 3, 3, 0, 2, tlsAlertFatal, alert}); err == nil {
		// Drain briefly so unread client bytes do not turn the close into
		// a reset that discards the alert.
		_ = closeWrite(client)
		_ = client.SetReadDeadline(time.Now().Add(lingerTimeout))
		_, _ = io.Copy(io.Discard, io.LimitReader(client, lingerDiscardLimit))
	}
}

// refuseTunnel ends an established tunnel whose plaintext content was
// refused: bytes the port does not carry, or an HTTP request for another
// host. The client already has its 200, so the JSON refusal is written into
// the tunnel as an HTTP response (what an HTTP client there reads, and a
// readable first line for anything else), and the tunnel closes.
func (p *Proxy) refuseTunnel(t *tunnel, client net.Conn, reason string) {
	dec, status := p.recordTunnelRefusal(t, reason)
	writeRaw(client, status, reasonPhrase(status, &dec), nil, p.blockResponse(t.principal, dec))
}

// recordTunnelRefusal marks t refused for its plaintext content and reports
// the refusal.
func (p *Proxy) recordTunnelRefusal(t *tunnel, reason string) (Decision, int) {
	dec := blocked(Decision{Host: t.dec.Host, Port: t.dec.Port, Mode: t.dec.Mode}, CategoryInvalidDestination, SourceGuard, "")
	dec.Reason = reason
	t.refused.Store(true)
	status := statusFor(dec)
	p.recordRefusal(t.principal, t.method, dec, status, t.started, t.id)
	return dec, status
}

// readClientHello reads the rest of a TLS ClientHello whose first bytes are
// in data. It returns every byte read, all of which must still be relayed,
// and the host_name from the server_name extension ("" when there is none).
// The hello may be split across any number of handshake records; any other
// record before it completes, and any hello a TLS server would reject for
// its server name (duplicate server_name extensions or host names), is
// malformed.
func readClientHello(data []byte, r io.Reader) ([]byte, string, error) {
	need := func(n int) error {
		if n > maxFirstFlight {
			return errMalformedClientHello
		}
		for len(data) < n {
			data = slices.Grow(data, n-len(data))
			m, err := r.Read(data[len(data):min(cap(data), maxFirstFlight)])
			data = data[:len(data)+m]
			if err != nil && len(data) < n {
				if errors.Is(err, io.EOF) {
					return io.ErrUnexpectedEOF
				}
				return err
			}
		}
		return nil
	}
	var hello []byte
	pos := 0
	for {
		if err := need(pos + tlsRecordHeaderLen); err != nil {
			return data, "", err
		}
		hdr := data[pos : pos+tlsRecordHeaderLen]
		length := int(binary.BigEndian.Uint16(hdr[3:]))
		if hdr[0] != tlsRecordHandshake || hdr[1] != 3 || length == 0 || length > tlsMaxPlaintext {
			return data, "", errMalformedClientHello
		}
		pos += tlsRecordHeaderLen
		if err := need(pos + length); err != nil {
			return data, "", err
		}
		hello = append(hello, data[pos:pos+length]...)
		pos += length
		if len(hello) < 4 {
			continue
		}
		if hello[0] != tlsHandshakeClientHello {
			return data, "", errMalformedClientHello
		}
		msgLen := int(hello[1])<<16 | int(hello[2])<<8 | int(hello[3])
		if msgLen > maxClientHelloLen {
			return data, "", errMalformedClientHello
		}
		if len(hello) >= 4+msgLen {
			name, err := clientHelloServerName(hello[4 : 4+msgLen])
			return data, name, err
		}
	}
}

// clientHelloServerName extracts the host_name from a ClientHello body.
func clientHelloServerName(msg []byte) (string, error) {
	s := cryptobyte.String(msg)
	var sessionID, suites, compression, exts cryptobyte.String
	if !s.Skip(2+32) || // legacy_version, random
		!s.ReadUint8LengthPrefixed(&sessionID) ||
		!s.ReadUint16LengthPrefixed(&suites) ||
		!s.ReadUint8LengthPrefixed(&compression) {
		return "", errMalformedClientHello
	}
	if s.Empty() {
		return "", nil // no extensions
	}
	if !s.ReadUint16LengthPrefixed(&exts) || !s.Empty() {
		return "", errMalformedClientHello
	}
	var (
		name    string
		seenSNI bool
	)
	for !exts.Empty() {
		var (
			typ  uint16
			body cryptobyte.String
		)
		if !exts.ReadUint16(&typ) || !exts.ReadUint16LengthPrefixed(&body) {
			return "", errMalformedClientHello
		}
		if typ != tlsExtServerName {
			continue
		}
		if seenSNI {
			return "", errMalformedClientHello
		}
		seenSNI = true
		var list cryptobyte.String
		if !body.ReadUint16LengthPrefixed(&list) || !body.Empty() || list.Empty() {
			return "", errMalformedClientHello
		}
		for !list.Empty() {
			var (
				nameType uint8
				host     cryptobyte.String
			)
			if !list.ReadUint8(&nameType) || !list.ReadUint16LengthPrefixed(&host) || host.Empty() {
				return "", errMalformedClientHello
			}
			if nameType != tlsSNIHostName {
				continue
			}
			if name != "" {
				return "", errMalformedClientHello
			}
			name = string(host)
		}
	}
	return name, nil
}
