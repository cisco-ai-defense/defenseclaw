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

package manager

import "strings"

// scopeID is the egress principal's sandbox id, which scopes per-sandbox
// unblocks: the OpenShell id, or the name for a gateway that reports none.
func scopeID(id, name string) string {
	if id != "" {
		return id
	}
	return "name:" + name
}

func cutPrefix(s, prefix string) (string, bool) {
	return strings.CutPrefix(s, prefix)
}
