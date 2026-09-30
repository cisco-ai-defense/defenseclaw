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

// Package egress is the DefenseClaw sandbox egress proxy: the general web
// path out of an OpenShell sandbox.
//
// OpenShell relays a sandbox's HTTPS_PROXY/HTTP_PROXY traffic to
// 127.0.0.1:<egress port> through a `protocol: tcp` + `tls: skip` policy
// rule, so the proxy sees plain HTTP proxy requests arriving from loopback:
//
//   - CONNECT tunnels carry HTTPS traffic as opaque bytes. The proxy never
//     terminates TLS, so pinning clients keep working; it reads only the
//     ClientHello's server name (SNI) and ends a tunnel whose SNI names a
//     destination it would block, so an allowed name or address cannot front
//     for a blocked site on the same CDN. A tunnel that carries plain
//     HTTP/1.x instead (undici's ProxyAgent, and so Node's fetch with
//     NODE_USE_ENV_PROXY, tunnels http:// URLs by default) has each request
//     read and forwarded only when its Host is the tunnel's own host, for
//     the same reason; after a WebSocket upgrade (ws://) it is relayed as
//     is, and other upgrade offers (h2c, TLS/1.0) are stripped so the
//     tunnel stays inspected.
//     Other protocols (SSH, databases) are relayed only on ports the
//     operator added; on the web ports 80 and 443 they, and HTTP/2 without
//     TLS, are refused with a 400 inside the tunnel.
//   - Absolute-form requests (plain http://, rarely https://) are forwarded
//     with hop-by-hop headers and the proxy credential stripped.
//
// Every request carries its sandbox's own proxy credential (the userinfo of
// HTTPS_PROXY, sent as Proxy-Authorization: Basic). The credential only
// authorizes egress the sandbox already has; it exists to attribute each
// tunnel to a binding and to rate-limit per sandbox.
//
// A Decider allows or blocks each destination. Open mode (the "open" profile)
// allows destination names by default, blocks the embedded exfiltration and
// abuse feed, and reaches IP-literal destinations only after an unblock (a
// literal would sidestep the name-based feed); allowlist mode (the
// "balanced" profile) allows only the curated allowlist.
// The administrator's block and allow-only lists, the operator block and
// allow lists and per-sandbox or persistent unblock decisions layer on top
// (Decider.Decide lists the order). Every sandbox's credential carries its
// own Decider (Principal.Decider), built from the sandbox's resolved policy
// by packs.Effective.EgressDecider, so the proxy never merges one
// sandbox's policy into another's. A tunnel is decided when it opens and
// again whenever its binding's credential or policy changes (Proxy.Recheck,
// SetDecider), so a revoked credential or a tightened policy also ends the
// tunnels already open. Checks that open a path the proxy does not guard,
// such as approving a direct OpenShell rule for a name, apply the same
// dial-time address rules through LookupHost and Decider.CheckAddrs.
//
// Hostnames are resolved on the proxy side as fully qualified names, never
// through the host's DNS search domains. Every DNS answer is checked by
// the netguard SSRF policy immediately before the connection and the dial
// targets the checked address literal, so DNS rebinding between check and
// dial has nothing to exploit. This machine and what only it reaches
// (loopback, its own interface addresses, host-internal names, link-local,
// metadata, reserved and translated addresses) are never reachable
// (host_internal). Private networks (RFC 1918, CGNAT and ULA addresses, the
// other hosts on this machine's public subnets, at least the /64 of a global
// IPv6 address, and intranet names) are reachable only where an operator
// allow rule names them (private_network): the exact name, an intranet
// wildcard such as *.corp, or the address. A wildcard under a public domain
// never opens private addresses, and unblocks never open them.
//
// Blocked requests get a JSON 403 body that explains the reason and how to
// ask for an unblock. Every decision, tunnel close and large upload to a
// first-seen host is reported to an EventSink, and the Counter keeps byte
// totals per tunnel and per destination. A sandbox whose policy blocks large
// uploads (Principal.BlockLargeUploads) has the upload that crosses its
// threshold cut and later ones to that destination refused, until an
// unblock or an operator allow entry names the destination.
package egress
