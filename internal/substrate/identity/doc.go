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

// Package identity verifies who calls the DefenseClaw gateway on Agent
// Substrate.
//
//   - ActorVerifier: the actor JWT that Substrate egress puts in the
//     x-defenseclaw-actor header of every actor request (Agent Substrate
//     v1.0.0 docs/guides/actor-jwts.md). OIDC discovery over TLS with the
//     projected trust bundle, kid lookup with a rate-limited refetch,
//     ES256 or RS256, aud, exp and nbf with 60 s skew, sub starting with
//     actor/ (worker-for-actor/ tokens refused), and the actor UID checked
//     live against the control API (cached 60 s), so a recreated
//     same-name actor's old token is refused.
//   - PersonVerifier: the admin listener's people (the launcher's OIDC
//     device-flow tokens) and CI workloads (workload_oidc).
//   - SessionSigner: the short-lived, person-bound relay session tokens
//     (typ dcrelay+jwt) the admin listener issues and the actor relay
//     accepts.
//
// Errors are *Error values with a closed Reason; no message carries token
// bytes or claim values. The control API adapter (ateapi) lives in the
// ateactors subpackage, so this package links without the vendored
// Substrate protos.
package identity
