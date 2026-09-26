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
//     for a blocked site on the same CDN. A tunnel that does not start with
//     a TLS ClientHello is refused with a 400 inside the tunnel, because
//     plain HTTP there could do the same through its Host header.
//   - Absolute-form requests (plain http://, rarely https://) are forwarded
//     with hop-by-hop headers and the proxy credential stripped. Plain HTTP
//     must use this form, where every request is decided; clients that
//     tunnel http:// URLs through CONNECT (undici's ProxyAgent, and so
//     Node's fetch with NODE_USE_ENV_PROXY, does by default) get that 400.
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
// Operator block and allow lists and per-sandbox or persistent unblock
// decisions layer on top.
//
// Hostnames are resolved on the proxy side. Every DNS answer is checked by
// the netguard SSRF policy immediately before the connection and the dial
// targets the checked address literal, so private, loopback, link-local,
// CGNAT, ULA, metadata, reserved and translated addresses, and this machine's
// own interface addresses, are unreachable and DNS rebinding between check
// and dial has nothing to exploit.
//
// Blocked requests get a JSON 403 body that explains the reason and how to
// ask for an unblock. Every decision, tunnel close and large upload to a
// first-seen host is reported to an EventSink, and the Counter keeps byte
// totals per tunnel and per destination.
package egress
