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

// Package sandbox embeds DefenseClaw's built-in OpenShell sandbox policy
// packs. Each pack lives at <name>/pack.yaml; internal/openshell/packs loads
// and validates them with the same strict rules as custom packs.
package sandbox

import "embed"

//go:embed open/pack.yaml balanced/pack.yaml strict/pack.yaml
var builtinPacks embed.FS

var builtinPackNames = []string{"open", "balanced", "strict"}

// BuiltinPackNames lists the built-in packs from loosest to strictest.
func BuiltinPackNames() []string {
	return append([]string(nil), builtinPackNames...)
}

// BuiltinPacks returns the embedded pack files, keyed <name>/pack.yaml.
func BuiltinPacks() embed.FS {
	return builtinPacks
}
