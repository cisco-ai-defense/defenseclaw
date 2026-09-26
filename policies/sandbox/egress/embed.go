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

// Package egress embeds the curated sandbox egress feeds that ship with
// DefenseClaw, so the egress proxy works without a repository checkout or an
// installed data directory. The proxy itself lives in
// internal/openshell/egress, which parses and validates these bytes.
package egress

import _ "embed"

//go:embed blocklist.yaml
var blocklist []byte

//go:embed allowlist.yaml
var allowlist []byte

// BlocklistYAML returns a copy of the built-in blocklist feed.
func BlocklistYAML() []byte { return append([]byte(nil), blocklist...) }

// AllowlistYAML returns a copy of the built-in allowlist feed used by the
// balanced (allowlist-mode) profile.
func AllowlistYAML() []byte { return append([]byte(nil), allowlist...) }
