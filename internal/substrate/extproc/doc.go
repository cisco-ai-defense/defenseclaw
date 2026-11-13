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

// Package extproc is the DefenseClaw egress callout for Agent Substrate: an
// Envoy ext_proc v3 processor that atenet-egress calls for every request an
// actor sends to a host its EgressPolicy allows.
//
// Substrate's egress gateway runs the callout after the EgressPolicy and
// after credential injection, so the callout sees the request headers as they
// will leave the cluster: injected service credentials and the actor JWT
// included. It never sees requests the policy denied. Its only identity for
// the actor is the filter state Envoy sets,
// spiffe://<trust domain>/worker-for-actor/<atespace>/<name>; there is no
// actor UID, SNI or source address, so the UID comes from a UIDResolver.
//
// For each request the Engine decides, in order:
//
//  1. who sent it (the actor SPIFFE identity; a request without one is
//     refused);
//  2. DefenseClaw's own hosts (the actor listener): allowed without
//     inspection, never body-buffered;
//  3. the live actor UID (UIDResolver, cached; Control API outages follow
//     the failure mode after the stale window). A decision made on a
//     cached entry stands only once the leader confirmed the incarnation:
//     the chain check (7) answers only the name's live incarnation, and a
//     refusal or unchecked step no chain answer confirmed resolves the name
//     again; a changed registration decides the request again from the
//     start (GAP-0234, GAP-0237);
//  4. the egress feeds and the profile's host lists, through the OpenShell
//     egress Decider (internal/openshell/egress), not a fork of it;
//  5. the profile's URL and method rules;
//  6. secret and DLP scans of the URL and headers (internal/secretshape),
//     exact-value DLP for the profile's actor_secrets, and placeholders sent
//     to hosts their secret is not bound to;
//  7. an egress-type tool chain whose predecessor is in the actor's window
//     (ChainChecker, 20 ms budget; a miss or timeout allows);
//  8. ask-required hosts (AskSink);
//  9. body mode (D9): MCP and admin-listed hosts only, when the egress
//     filter allows a mode_override (upstream #3817), 1 MiB cap, never SSE
//     or model traffic. MCP JSON-RPC tools/call bodies go through the same
//     tool rules the hooks use (ToolJudge).
//
// Known limit (GAP-0067): upstream #3817 allows a single override mode, which
// buffers the response body too, so an MCP server answering an inspected
// tools/call with an event stream reaches the actor only when the stream
// ends. The upstream ask for a second allowed mode (response body NONE) is
// drafted by lane U; overrideMode changes to it once a release has it.
//
// A refusal is an ImmediateResponse 403 with the DefenseClaw JSON body
// (egress.BlockResponse); an allowed request gets x-defenseclaw-decision.
// Every allowed or refused request becomes an observed_egress step
// (ChainSink, asynchronous, bounded) and a log.egress.* event. Credential
// headers, configured secret headers, placeholders and secret values are
// redacted before anything is logged (Redactor).
package extproc
