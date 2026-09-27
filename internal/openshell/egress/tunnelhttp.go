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
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Plain HTTP inside a CONNECT tunnel.
//
// Clients such as undici (Node's fetch under NODE_USE_ENV_PROXY) send
// http:// requests through CONNECT instead of in absolute form. The tunnel
// was decided for its CONNECT host, but a Host header could name any other
// site served from the same address (a CDN), so each request is read,
// required to be for the tunnel's own host, and written upstream again;
// the upstream's responses are copied back byte for byte. A 101 Switching
// Protocols answer to an Upgrade request (ws://) turns the rest of the
// tunnel into a plain relay.

// pendingDepth bounds requests forwarded ahead of their responses.
const pendingDepth = 64

var (
	errHeaderTooLarge = errors.New("egress: tunnel request header too large")
	// aLongTimeAgo is a deadline that wakes a pending read at once.
	aLongTimeAgo = time.Unix(1, 0)
)

// httpSession coordinates the two directions of a tunnel that carries HTTP:
// the upload side forwards requests and tells the download side, which
// follows the responses, what to expect.
type httpSession struct {
	switching atomic.Bool
	// tracking is closed once the download side follows responses.
	tracking chan struct{}
	// lost is closed once it no longer does (the upstream finished, or sent
	// something that is not a response to a forwarded request).
	lost     chan struct{}
	lostOnce sync.Once
	pending  chan pendingRequest
}

// pendingRequest is a forwarded request whose response has not been read.
type pendingRequest struct {
	method string
	// verdict, set for Upgrade requests, receives whether the upstream
	// switched protocols.
	verdict chan bool
}

func newHTTPSession() *httpSession {
	return &httpSession{
		tracking: make(chan struct{}),
		lost:     make(chan struct{}),
		pending:  make(chan pendingRequest, pendingDepth),
	}
}

func (hs *httpSession) markLost() { hs.lostOnce.Do(func() { close(hs.lost) }) }

// start switches the download side from copying to following responses. It
// interrupts the download side's pending read and waits until it follows.
func (hs *httpSession) start(upstream net.Conn) {
	hs.switching.Store(true)
	_ = upstream.SetReadDeadline(aLongTimeAgo)
	select {
	case <-hs.tracking:
	case <-hs.lost:
	}
}

func (hs *httpSession) enqueue(e pendingRequest) {
	select {
	case hs.pending <- e:
	case <-hs.lost:
	}
}

// upgraded waits for the upstream's answer to an Upgrade request. Without
// response tracking it reports false, so the tunnel stays inspected.
func (hs *httpSession) upgraded(e pendingRequest) bool {
	select {
	case ok := <-e.verdict:
		return ok
	case <-hs.lost:
		select {
		case ok := <-e.verdict:
			return ok
		default:
			return false
		}
	}
}

// relayDown copies upstream bytes to the client. When the tunnel turns out
// to carry HTTP it switches to following the responses, still copying every
// byte as it arrives.
func (p *Proxy) relayDown(t *tunnel, client, upstream net.Conn, touch func(), hs *httpSession) error {
	defer hs.markLost()
	err := pipe(client, upstream, touch, func(n int) bool {
		t.flow.addDown(int64(n))
		return true
	})
	if err == nil || !hs.switching.Load() || !errors.Is(err, os.ErrDeadlineExceeded) {
		return err
	}
	_ = upstream.SetReadDeadline(time.Time{})
	// Bytes before the first request cannot be a response to it.
	unsolicited := t.flow.down.Load() > 0
	close(hs.tracking)
	tee := &teeReader{src: upstream, dst: client, touch: touch, flow: t.flow}
	br := bufio.NewReaderSize(tee, relayBufferSize)
	if !unsolicited {
		trackResponses(br, hs)
	}
	hs.markLost()
	_, err = io.Copy(io.Discard, br)
	if tee.werr != nil {
		return tee.werr
	}
	if err == nil {
		_ = closeWrite(client)
	}
	return err
}

// trackResponses follows the framing of the upstream's responses to answer
// Upgrade requests. It returns when it can no longer tell where responses
// start: after a protocol switch, unsolicited or unparseable bytes, or the
// end of the stream. Everything it reads has already been copied.
func trackResponses(br *bufio.Reader, hs *httpSession) {
	for {
		if _, err := br.Peek(1); err != nil {
			return
		}
		var e pendingRequest
		select {
		case e = <-hs.pending:
		default:
			return // a request is always queued before it is written
		}
		for {
			resp, err := http.ReadResponse(br, &http.Request{Method: e.method})
			if err != nil {
				return
			}
			if resp.StatusCode == http.StatusSwitchingProtocols {
				if e.verdict != nil {
					e.verdict <- true
				}
				return
			}
			if resp.StatusCode < http.StatusOK {
				continue // 100 Continue and other interim responses
			}
			if e.verdict != nil {
				e.verdict <- false
			}
			_, err = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				return
			}
			break
		}
	}
}

// teeReader copies what it reads from the upstream to the client, counting
// it as download.
type teeReader struct {
	src, dst net.Conn
	touch    func()
	flow     *flow
	werr     error
}

func (r *teeReader) Read(b []byte) (int, error) {
	n, err := r.src.Read(b)
	if n > 0 {
		r.touch()
		r.flow.addDown(int64(n))
		if _, werr := r.dst.Write(b[:n]); werr != nil {
			r.werr = werr
			return n, werr
		}
		r.touch()
	}
	return n, err
}

// relayRequests forwards the HTTP/1.x requests the client sends in a tunnel.
// Each head is read within HeaderTimeout and MaxHeaderBytes, as for
// absolute-form requests, and must be for the tunnel's host; the request is
// then written upstream with its body (chunked bodies stay chunked), counted
// against the large-upload threshold. Pipelined requests follow each other
// without waiting for responses. An Upgrade request waits for the upstream's
// answer: after 101 Switching Protocols the rest of the tunnel is relayed as
// is.
func (p *Proxy) relayRequests(t *tunnel, client net.Conn, src io.Reader, upstream net.Conn, touch func(), up func(int) bool, hs *httpSession) error {
	limit := &headLimit{r: src}
	br := bufio.NewReader(limit)
	w := &uploadWriter{dst: upstream, touch: touch, account: up}
	for {
		// Bytes read from here to the end of the head count against
		// MaxHeaderBytes; the read buffer (4 KiB) is the slack, as for the
		// HTTP server. Waiting for the next request is bounded by the tunnel
		// idle timeout, its head, once it starts, by HeaderTimeout.
		limit.arm(int64(p.maxHeaderBytes))
		if err := skipEmptyLines(br); err != nil {
			if errors.Is(err, io.EOF) {
				_ = closeWrite(upstream)
				return nil
			}
			if errors.Is(err, errHeaderTooLarge) {
				p.refuseTunnel(t, client, "The tunnel's HTTP request header is too large.")
				return errTunnelRefused
			}
			return err
		}
		_ = client.SetReadDeadline(time.Now().Add(p.headerTimeout))
		req, err := http.ReadRequest(br)
		_ = client.SetReadDeadline(time.Time{})
		limit.disarm()
		if err == nil && req.ProtoMajor != 1 {
			err = fmt.Errorf("egress: HTTP/%d.%d request in a tunnel", req.ProtoMajor, req.ProtoMinor)
		}
		if err != nil {
			p.refuseTunnel(t, client, "The tunnel's HTTP request is malformed, not HTTP/1.x, too large or too slow to arrive.")
			return errTunnelRefused
		}
		if reason, ok := tunnelRequestHost(req, t.dec); !ok {
			p.refuseTunnel(t, client, reason)
			return errTunnelRefused
		}
		if _, ok := req.Header["User-Agent"]; !ok {
			req.Header["User-Agent"] = []string{""} // keep Write from adding Go's own
		}
		e := pendingRequest{method: req.Method}
		upgrade := wantsUpgrade(req.Header)
		if upgrade {
			e.verdict = make(chan bool, 1)
		}
		hs.enqueue(e)
		if err := req.Write(w); err != nil {
			return err
		}
		if upgrade && hs.upgraded(e) {
			return pipe(upstream, br, touch, up)
		}
	}
}

// tunnelRequestHost checks that a request read inside a tunnel is for the
// tunnel's own host. ReadRequest has already folded an absolute-form
// request's URL host into req.Host (the URL wins over a Host header, and
// Write sends only req.Host upstream). A missing Host is filled in with the
// tunnel's host; a port, when given, must be the tunnel's port.
func tunnelRequestHost(req *http.Request, dec Decision) (string, bool) {
	if req.Host == "" {
		req.Host = dec.Host
		if strings.Contains(dec.Host, ":") {
			req.Host = "[" + dec.Host + "]"
		}
		return "", true
	}
	name, port := req.Host, ""
	if h, pt, err := net.SplitHostPort(req.Host); err == nil {
		name, port = h, pt
	}
	host, _, err := normalizeHost(name)
	if err == nil && host == dec.Host {
		if port == "" {
			return "", true
		}
		if n, ok := parsePort(port); ok && n == dec.Port {
			return "", true
		}
	}
	return fmt.Sprintf("The HTTP request in the tunnel to %s asked for %s. Requests in a CONNECT tunnel must be for the "+
		"tunnel's own host and port; send requests for other hosts through their own tunnel or as absolute-form requests.",
		net.JoinHostPort(dec.Host, fmt.Sprint(dec.Port)), sanitizeHost(req.Host)), false
}

// skipEmptyLines waits for the next request line, dropping the empty lines a
// server ignores before one (RFC 9112 section 2.2, such as a stray CRLF
// after a body); ReadRequest would take one for a malformed request.
func skipEmptyLines(br *bufio.Reader) error {
	for {
		b, err := br.Peek(1)
		if err != nil {
			return err
		}
		if b[0] != '\r' && b[0] != '\n' {
			return nil
		}
		_, _ = br.Discard(1)
	}
}

// wantsUpgrade reports an HTTP/1.1 protocol upgrade request.
func wantsUpgrade(h http.Header) bool {
	if h.Get("Upgrade") == "" {
		return false
	}
	for _, v := range h.Values("Connection") {
		for _, token := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return true
			}
		}
	}
	return false
}

// headLimit bounds the bytes read while a request head is armed.
type headLimit struct {
	r     io.Reader
	n     int64
	armed bool
}

func (l *headLimit) arm(n int64) { l.n, l.armed = n, true }
func (l *headLimit) disarm()     { l.armed = false }

func (l *headLimit) Read(b []byte) (int, error) {
	if !l.armed {
		return l.r.Read(b)
	}
	if l.n <= 0 {
		return 0, errHeaderTooLarge
	}
	if int64(len(b)) > l.n {
		b = b[:l.n]
	}
	n, err := l.r.Read(b)
	l.n -= int64(n)
	return n, err
}

// uploadWriter counts what is written upstream against the large-upload
// threshold before writing it, as pipe does for relayed bytes.
type uploadWriter struct {
	dst     net.Conn
	touch   func()
	account func(int) bool
}

func (w *uploadWriter) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	w.touch()
	if !w.account(len(b)) {
		return 0, errLargeUpload
	}
	n, err := w.dst.Write(b)
	w.touch()
	return n, err
}
