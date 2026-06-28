// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package netguard provides shared SSRF defenses for outbound HTTP
// flows: dial-time IP validation, redirect rejection, URL credential
// scrubbing, and inline-credential rejection.
//
// All HTTP clients that send to untrusted or partially-trusted
// destinations (webhooks, MCP scanners, the proxy passthrough
// branches, registry sync) MUST use these helpers so that the
// post-validation dial cannot be redirected to a private/loopback/
// link-local address via DNS rebinding, redirects, or attacker-
// controlled provider hostnames that happen to share an allowed
// suffix.
package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// ErrPrivateAddress is returned by Dial / CheckRedirect when an
// outbound connection target resolves (or rebinds) to an address in
// a private, loopback, link-local, multicast, or cloud-metadata
// range. Callers MUST treat it as a hard failure and never retry
// against the same hostname.
var ErrPrivateAddress = errors.New("netguard: destination resolves to private/reserved address")

// ErrRedirectBlocked is returned by CheckRedirect when an upstream
// response attempts to redirect the client. Outbound redirects are
// disabled by default because validate-once-then-dial is unsafe
// against attacker-controlled redirects.
var ErrRedirectBlocked = errors.New("netguard: outbound redirects are disabled")

// ErrInlineCredentials is returned when a URL contains userinfo. We
// never forward inline credentials because they can leak through
// proxy logs, error messages, retries, and reverse-DNS records.
var ErrInlineCredentials = errors.New("netguard: URL contains inline credentials")

// ErrUnsupportedScheme is returned when a URL uses a scheme other
// than http or https. file://, gopher://, ftp://, and similar are
// rejected up-front because they bypass HTTP-level controls.
var ErrUnsupportedScheme = errors.New("netguard: only http/https schemes are supported")

// extraReservedCIDRs lists ranges that aren't covered by the
// standard IsPrivate / IsLinkLocal predicates but are still SSRF
// attack surfaces in practice. Cloud metadata endpoints, the IMDSv1
// IPv6 magic address, the AWS Service Endpoint reserved space, and
// the IPv6 ULA range round out the deny-list.
//
// 100.64.0.0/10 (RFC 6598 carrier-grade NAT) is included by default
// because it is the canonical "private overlay" address space —
// AWS Cloud WAN, GCP private overlay, and most carrier NAT deploys
// land here. Operators running over Tailscale (which uses 100.64/10
// for its mesh addresses) opt out of CGNAT blocking with
// DEFENSECLAW_ALLOW_CGNAT=1, which mirrors the gateway-side hatch
// in internal/gateway/provider.go::extraReservedNets so both
// predicates classify the same set of IPs as unsafe under the same
// configuration. Loopback, RFC 1918, link-local, IMDS, ECS task
// metadata, and IPv6 ULA stay blocked unconditionally.
var extraReservedCIDRs = func() []string {
	base := []string{
		"169.254.169.254/32", // EC2/Azure/GCP metadata service
		"169.254.170.2/32",   // ECS task metadata endpoint
		"fd00::/8",           // IPv6 ULA
	}
	if !cgnatAllowed() {
		base = append(base, "100.64.0.0/10") // RFC 6598 carrier-grade NAT
	}
	return base
}()

// cgnatAllowed mirrors the gateway-side check; broken out so the
// init-time decision is auditable from a single call site.
func cgnatAllowed() bool {
	return os.Getenv("DEFENSECLAW_ALLOW_CGNAT") == "1"
}

var parsedExtraReserved []*net.IPNet

func init() {
	for _, cidr := range extraReservedCIDRs {
		_, n, err := net.ParseCIDR(cidr)
		if err == nil {
			parsedExtraReserved = append(parsedExtraReserved, n)
		}
	}
}

// IsPrivateOrReserved reports whether ip lies in any range that
// netguard considers unsafe to forward to from an authenticated
// outbound caller. The set is the union of:
//
//   - net.IP.IsLoopback / IsPrivate / IsLinkLocalUnicast /
//     IsLinkLocalMulticast / IsMulticast / IsUnspecified
//   - extraReservedCIDRs (cloud metadata + CGNAT + IPv6 ULA)
func IsPrivateOrReserved(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() {
		return true
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return true
	}
	for _, n := range parsedExtraReserved {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// RejectInlineCredentials returns ErrInlineCredentials when u
// contains a userinfo component. Callers should invoke this on every
// untrusted URL before logging it OR forwarding it.
func RejectInlineCredentials(u *url.URL) error {
	if u == nil {
		return nil
	}
	if u.User != nil {
		return ErrInlineCredentials
	}
	return nil
}

// secretQueryKeys is the case-insensitive deny-list of query
// parameters whose values are scrubbed before logging. Hand-curated
// to cover the common provider/webhook/auth shapes.
var secretQueryKeys = map[string]struct{}{
	"key":                  {},
	"api_key":              {},
	"api-key":              {},
	"apikey":               {},
	"token":                {},
	"access_token":         {},
	"refresh_token":        {},
	"id_token":             {},
	"client_secret":        {},
	"client_token":         {},
	"signature":            {},
	"x-amz-signature":      {},
	"x-amz-credential":     {},
	"x-amz-security-token": {},
	"sig":                  {},
	"auth":                 {},
	"authorization":        {},
	"password":             {},
	"passwd":               {},
	"pwd":                  {},
	"secret":               {},
	"routing_key":          {},
	"webhook_token":        {},
}

// ScrubURL returns a string representation of u safe for logs:
//
//   - userinfo is removed entirely (no `user:pass@` prefix);
//   - query parameters whose name is in secretQueryKeys (case-insensitive)
//     have their value replaced with `<redacted>`;
//   - the rest of the URL (scheme, host, port, path, fragment) is
//     preserved so operators can still triage by host/path.
//
// Pass extra (case-insensitive) keys to redact in addition to the
// curated default set.
func ScrubURL(u *url.URL, extra ...string) string {
	if u == nil {
		return ""
	}
	cp := *u
	cp.User = nil
	if cp.RawQuery != "" {
		q := cp.Query()
		for k := range q {
			lk := strings.ToLower(k)
			if _, ok := secretQueryKeys[lk]; ok {
				q.Set(k, "<redacted>")
				continue
			}
			for _, ex := range extra {
				if strings.EqualFold(k, ex) {
					q.Set(k, "<redacted>")
					break
				}
			}
		}
		cp.RawQuery = q.Encode()
	}
	return cp.String()
}

// ScrubURLString parses raw and applies ScrubURL. On parse failure
// it returns a safe placeholder so callers can never accidentally
// log credential-bearing strings.
func ScrubURLString(raw string, extra ...string) string {
	u, err := url.Parse(raw)
	if err != nil || u == nil {
		return "<unparseable-url>"
	}
	return ScrubURL(u, extra...)
}

// EndpointForDisplay returns a URL safe for health/status surfaces. Unlike
// ScrubURL, it removes the entire query and fragment because those surfaces do
// not need request parameters and arbitrary provider-specific keys may carry
// credentials.
func EndpointForDisplay(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u == nil {
		return "<unparseable-url>"
	}
	u.User = nil
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	return u.String()
}

// SafeDialContext returns a DialContext function suitable for a
// http.Transport that:
//
//   - resolves the host immediately before connect;
//   - rejects every resolved address that IsPrivateOrReserved;
//   - dials a public address selected from the resolved set.
//
// Time-of-check-time-of-use is bounded to a single hostname lookup
// per dial because the transport invokes DialContext on every
// connection, so DNS rebinding between resolution and connect is
// limited to the OS resolver's caching window.
//
// Pass nil to use net.DefaultResolver and net.Dialer with sensible
// defaults (10s connect, 30s keepalive).
func SafeDialContext(d *net.Dialer, r *net.Resolver) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if d == nil {
		d = &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	}
	if r == nil {
		r = net.DefaultResolver
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		// Literal IP — validate without DNS.
		if ip := net.ParseIP(host); ip != nil {
			if IsPrivateOrReserved(ip) {
				return nil, fmt.Errorf("%w (ip=%s)", ErrPrivateAddress, ip.String())
			}
			return d.DialContext(ctx, network, addr)
		}
		// Resolve and require every answer to be public. Refusing
		// the dial when ANY answer is private is conservative but
		// closes the rebinding hole where a hostname returns one
		// public + one private answer.
		ips, err := r.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("%w (host=%s)", ErrPrivateAddress, host)
		}
		var public *net.IPAddr
		for i := range ips {
			ip := ips[i].IP
			if IsPrivateOrReserved(ip) {
				return nil, fmt.Errorf("%w (host=%s ip=%s)", ErrPrivateAddress, host, ip.String())
			}
			if public == nil {
				public = &ips[i]
			}
		}
		return d.DialContext(ctx, network, net.JoinHostPort(public.IP.String(), port))
	}
}

// BlockRedirects is a CheckRedirect callback that always returns
// ErrRedirectBlocked, suitable for http.Client.CheckRedirect on
// outbound flows where the validation step happens before dial.
//
// Callers that legitimately need redirects MUST replace this with a
// custom CheckRedirect that re-validates each new target through
// SafeDialContext semantics.
func BlockRedirects(req *http.Request, via []*http.Request) error {
	return ErrRedirectBlocked
}

// SafeHTTPClient builds a http.Client that uses SafeDialContext for
// every dial and refuses redirects. Pass a positive timeout for the
// total request budget; default 30s.
func SafeHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:         SafeDialContext(nil, nil),
			TLSHandshakeTimeout: 10 * time.Second,
			IdleConnTimeout:     30 * time.Second,
			MaxIdleConns:        16,
			DisableKeepAlives:   false,
		},
		CheckRedirect: BlockRedirects,
	}
}

// ValidateOutboundURL is the single entry point used by webhook
// dispatchers, registry fetches, and other "user supplied an
// arbitrary URL" code paths. It enforces:
//
//  1. http or https scheme;
//  2. no inline credentials;
//  3. host is not literal-IP that lies in a private/reserved range
//     and (when DNS resolution succeeds) every resolved address is
//     public.
//
// DNS resolution is best-effort: a transient resolver failure does
// not pass the gate. Callers that absolutely need to allow unresolvable
// hostnames at config time should re-validate immediately before the
// first delivery.
func ValidateOutboundURL(ctx context.Context, raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("netguard: parse url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, ErrUnsupportedScheme
	}
	if err := RejectInlineCredentials(u); err != nil {
		return nil, err
	}
	host := u.Hostname()
	if host == "" {
		return nil, errors.New("netguard: missing host")
	}
	if ip := net.ParseIP(host); ip != nil {
		if IsPrivateOrReserved(ip) {
			return nil, fmt.Errorf("%w (ip=%s)", ErrPrivateAddress, ip.String())
		}
		return u, nil
	}
	resolveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(resolveCtx, host)
	if err != nil {
		return nil, fmt.Errorf("netguard: resolve %s: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w (host=%s no addresses)", ErrPrivateAddress, host)
	}
	for _, ipa := range ips {
		if IsPrivateOrReserved(ipa.IP) {
			return nil, fmt.Errorf("%w (host=%s ip=%s)", ErrPrivateAddress, host, ipa.IP.String())
		}
	}
	return u, nil
}
