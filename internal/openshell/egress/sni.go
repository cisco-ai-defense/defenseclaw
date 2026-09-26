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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
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
	errServerNameRefused    = errors.New("egress: tunnel refused for its TLS server name")
)

// screenFirstFlight reads the client's first bytes in an established CONNECT
// tunnel and returns them for relaying. The proxy never terminates TLS, but a
// tunnel that opens with a ClientHello naming another host than the CONNECT
// target is decided again for that server name (SNI). Otherwise a CONNECT to
// an allowed name or address followed by SNI pastebin.com would reach any
// blocked site served from the same CDN addresses, in open and allowlist mode
// alike. A refused tunnel gets a fatal TLS alert and errServerNameRefused.
// Bytes that do not start a TLS handshake are relayed untouched.
//
// Only the visible server name is checked: an Encrypted Client Hello's outer
// name and a Host header inside the TLS session are out of reach without
// terminating TLS.
func (p *Proxy) screenFirstFlight(t *tunnel, d *Decider, client net.Conn, r io.Reader) ([]byte, error) {
	buf := make([]byte, firstReadSize)
	n, err := r.Read(buf)
	if n == 0 {
		if errors.Is(err, io.EOF) {
			return nil, nil // pipe sees the EOF again and half-closes upstream
		}
		return nil, err
	}
	if buf[0] != tlsRecordHandshake {
		return buf[:n], nil
	}
	// A TLS client sends its whole ClientHello at once; one that stalls
	// halfway is holding the tunnel open without a checkable name.
	_ = client.SetReadDeadline(time.Now().Add(p.helloTimeout))
	flight, name, err := readClientHello(buf[:n], r)
	_ = client.SetReadDeadline(time.Time{})
	if errors.Is(err, errMalformedClientHello) {
		dec := blocked(Decision{Host: t.dec.Host, Port: t.dec.Port, Mode: t.dec.Mode}, CategoryInvalidDestination, SourceGuard, "")
		dec.Reason = "The tunnel's TLS ClientHello is malformed or too large for its server name to be checked."
		p.refuseInTunnel(t, client, dec, tlsAlertDecodeError)
		return nil, errServerNameRefused
	}
	if err != nil {
		return nil, err
	}
	if dec, refused := serverNameRefusal(t, d, name); refused {
		p.refuseInTunnel(t, client, dec, tlsAlertAccessDenied)
		return nil, errServerNameRefused
	}
	return flight, nil
}

// serverNameRefusal decides the server name a tunnel's ClientHello asked
// for. No name, the CONNECT target itself, and IP literals (RFC 6066 forbids
// them in SNI, and they cannot select a virtual host by name) need no second
// decision.
func serverNameRefusal(t *tunnel, d *Decider, name string) (Decision, bool) {
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
	dec := d.Decide(t.principal, host, t.dec.Port)
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
