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
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

// BlockResponse is the JSON body of a blocked request. It is written for
// the agent as much as for humans: Message and HowToUnblock are complete
// sentences the agent can relay to the user.
type BlockResponse struct {
	Error        string   `json:"error"`
	Message      string   `json:"message"`
	Host         string   `json:"host,omitempty"`
	Port         int      `json:"port,omitempty"`
	Category     Category `json:"category,omitempty"`
	Reason       string   `json:"reason,omitempty"`
	Rule         string   `json:"rule,omitempty"`
	Source       Source   `json:"source,omitempty"`
	Feed         string   `json:"feed,omitempty"`
	FeedVersion  string   `json:"feed_version,omitempty"`
	Mode         Mode     `json:"mode,omitempty"`
	Sandbox      string   `json:"sandbox,omitempty"`
	Unblockable  bool     `json:"unblockable"`
	HowToUnblock string   `json:"how_to_unblock"`
}

// ErrorResponse is the JSON body of every other proxy-generated error.
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Host    string `json:"host,omitempty"`
	Port    int    `json:"port,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

const (
	errCodeBlocked       = "egress_blocked"
	errCodeAuth          = "proxy_auth_required"
	errCodeNotProxy      = "not_a_proxy_request"
	errCodeUnreachable   = "upstream_unreachable"
	errCodeShuttingDown  = "proxy_shutting_down"
	proxyAuthenticate    = `Basic realm="DefenseClaw egress"`
	rawWriteTimeout      = 10 * time.Second
	lingerTimeout        = 500 * time.Millisecond
	lingerDiscardLimit   = 64 << 10
	maxReasonPhraseBytes = 96
)

var safeSandboxRef = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func sandboxRef(p Principal) string {
	for _, ref := range []string{p.SandboxName, p.SandboxID} {
		if safeSandboxRef.MatchString(ref) {
			return ref
		}
	}
	return ""
}

func sandboxFlag(p Principal) string {
	if ref := sandboxRef(p); ref != "" {
		return " --sandbox " + ref
	}
	return ""
}

// DefaultUnblockHint explains how a blocked destination can be allowed. The
// commands it names are the `defenseclaw sandbox unblock` surface.
func DefaultUnblockHint(p Principal, d Decision) string {
	switch {
	case d.Category == CategoryIPLiteral:
		return fmt.Sprintf("Retry with the site's host name instead of its IP address. If the IP address itself is needed, tell "+
			"the user DefenseClaw blocked it; they can allow it with `defenseclaw sandbox unblock %s%s`. "+
			"Do not try to reach it another way.", d.Host, sandboxFlag(p))
	case d.Unblockable:
		cmd := "defenseclaw sandbox unblock " + d.Host + sandboxFlag(p)
		return fmt.Sprintf("Tell the user DefenseClaw blocked this destination. They can allow it for this sandbox with `%s`, "+
			"for every sandbox with `defenseclaw sandbox unblock %s --always`, or from the DefenseClaw activity feed. "+
			"Do not try to reach it another way.", cmd, d.Host)
	case d.Category == CategoryHostInternal:
		return "This cannot be unblocked: sandboxes never reach this machine, link-local or cloud metadata addresses. " +
			"If the user wants the sandbox to use a service on this machine, they can relaunch it with " +
			"`defenseclaw sandbox run --host-port PORT`."
	case d.Category == CategoryPrivateNetwork:
		return "Tell the user DefenseClaw blocked this private-network destination. `defenseclaw sandbox unblock` does not " +
			"open private networks; the operator can, by adding the exact host name or the IP address to " +
			"openshell.egress.allow in the DefenseClaw configuration (a \"*.\" wildcard opens private addresses only " +
			"for intranet names such as *.corp). Do not try to reach it another way."
	case d.Category == CategoryPortNotAllowed:
		return "Only the configured web ports are relayed. The operator can add ports with openshell.egress.ports in the " +
			"DefenseClaw configuration; prefer an HTTPS alternative (for example an HTTPS git remote instead of SSH)."
	case d.Category == CategoryOperatorBlock:
		return "The operator blocked this destination (openshell.egress.block or firewall rules); only a DefenseClaw " +
			"configuration change can allow it."
	case d.Category == CategoryRateLimited:
		return "Wait for open connections to finish, then retry with fewer parallel connections."
	case d.Category == CategoryInvalidDestination:
		return "Send CONNECT host:port or an absolute http:// or https:// URL with a valid host name."
	}
	return "Only a DefenseClaw configuration change can allow this destination."
}

func (p *Proxy) blockResponse(pr Principal, d Decision) BlockResponse {
	hint := p.hint
	if hint == nil {
		hint = DefaultUnblockHint
	}
	target := d.Host
	if d.Port > 0 {
		target = net.JoinHostPort(d.Host, strconv.Itoa(d.Port))
	}
	return BlockResponse{
		Error:        errCodeBlocked,
		Message:      fmt.Sprintf("DefenseClaw blocked sandbox egress to %s (%s): %s", target, d.Category, d.Reason),
		Host:         d.Host,
		Port:         d.Port,
		Category:     d.Category,
		Reason:       d.Reason,
		Rule:         d.Rule,
		Source:       d.Source,
		Feed:         d.Feed,
		FeedVersion:  d.FeedVersion,
		Mode:         d.Mode,
		Sandbox:      sandboxRef(pr),
		Unblockable:  d.Unblockable,
		HowToUnblock: hint(pr, d),
	}
}

func authRequiredResponse() ErrorResponse {
	return ErrorResponse{
		Error: errCodeAuth,
		Message: "The DefenseClaw egress proxy needs this sandbox's proxy credentials. Use the HTTPS_PROXY/HTTP_PROXY " +
			"value the sandbox was started with, including its user:password part.",
	}
}

func notProxyResponse() ErrorResponse {
	return ErrorResponse{
		Error: errCodeNotProxy,
		Message: "This is the DefenseClaw sandbox egress proxy. Send CONNECT or absolute-form proxy requests by " +
			"configuring it as HTTPS_PROXY/HTTP_PROXY.",
	}
}

func shuttingDownResponse() ErrorResponse {
	return ErrorResponse{Error: errCodeShuttingDown, Message: "The DefenseClaw egress proxy is shutting down; retry shortly."}
}

func unreachableResponse(host string, port int, reason string) ErrorResponse {
	return ErrorResponse{
		Error:   errCodeUnreachable,
		Message: fmt.Sprintf("The DefenseClaw egress proxy could not reach %s: %s.", net.JoinHostPort(host, strconv.Itoa(port)), reason),
		Host:    host,
		Port:    port,
		Reason:  reason,
	}
}

// statusFor maps a refusal to its HTTP status.
func statusFor(d Decision) int {
	switch d.Category {
	case CategoryInvalidDestination:
		return http.StatusBadRequest
	case CategoryRateLimited:
		return http.StatusTooManyRequests
	}
	return http.StatusForbidden
}

// reasonPhrase is the status-line text of raw CONNECT refusals. Clients
// such as Python's http.client surface it in their error message ("Tunnel
// connection failed: 403 Blocked by DefenseClaw (paste_site)") when they
// ignore the body.
func reasonPhrase(status int, d *Decision) string {
	if status == http.StatusForbidden && d != nil {
		return "Blocked by DefenseClaw (" + string(d.Category) + ")"
	}
	if text := http.StatusText(status); text != "" {
		return text
	}
	return "Error"
}

func sanitizeReasonPhrase(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s) && len(b) < maxReasonPhraseBytes; i++ {
		if c := s[i]; c >= 0x20 && c <= 0x7e {
			b = append(b, c)
		}
	}
	return string(b)
}

func mustJSON(v any) []byte {
	body, err := json.Marshal(v)
	if err != nil {
		// Only fixed struct types with string and int fields are encoded.
		return []byte(`{"error":"internal"}`)
	}
	return append(body, '\n')
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	body := mustJSON(v)
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Content-Length", strconv.Itoa(len(body)))
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// writeRaw writes a complete HTTP/1.1 response to a hijacked connection and
// closes it, lingering briefly so data the client already sent (a pipelined
// TLS ClientHello, say) does not turn the close into a reset that loses the
// response.
func writeRaw(conn net.Conn, status int, reason string, extra http.Header, v any) {
	body := mustJSON(v)
	h := http.Header{}
	for k, vs := range extra {
		h[k] = vs
	}
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Content-Length", strconv.Itoa(len(body)))
	h.Set("Cache-Control", "no-store")
	h.Set("Connection", "close")
	var b bytes.Buffer
	fmt.Fprintf(&b, "HTTP/1.1 %03d %s\r\n", status, sanitizeReasonPhrase(reason))
	_ = h.Write(&b)
	b.WriteString("\r\n")
	b.Write(body)
	_ = conn.SetWriteDeadline(time.Now().Add(rawWriteTimeout))
	_, err := conn.Write(b.Bytes())
	if err == nil {
		_ = closeWrite(conn)
		_ = conn.SetReadDeadline(time.Now().Add(lingerTimeout))
		_, _ = io.Copy(io.Discard, io.LimitReader(conn, lingerDiscardLimit))
	}
	_ = conn.Close()
}
