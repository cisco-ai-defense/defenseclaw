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

//go:build !s7bench

package gateway

// toolJudgeNonceFor returns the nonce of one judge call. Every build but the
// benchmark harness draws it from crypto/rand for every call; seed (the
// session and the call) is not used. The s7bench build has its own
// toolJudgeNonceFor (s7bench_nonce.go): the two are build-tag twins, so no
// code can switch a shipped gateway to the derived nonce (rel-1-0-10:GAP-0846).
func toolJudgeNonceFor(string) string { return newToolJudgeNonce() }
