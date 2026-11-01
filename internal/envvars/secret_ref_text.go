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

package envvars

import (
	"regexp"
	"strings"
)

// secretRefTextRE is a quoted "source" key followed by a colon inside braces:
// the Python repr and the JSON form, any key order. Same pattern as
// connector_paths.is_secret_ref_text in the Python CLI.
var secretRefTextRE = regexp.MustCompile(`^\{.*["']source["']\s*:.*\}$`)

// IsSecretRefText reports whether a gateway token value is the text of an
// OpenClaw SecretRef object rather than a token. DefenseClaw 1.0.5 and 1.0.6
// wrote OPENCLAW_GATEWAY_TOKEN={source: ...} to ~/.defenseclaw/.env before
// init failed on such a reference (issue #1404). That text is never a token,
// so every gateway token reader ignores it.
func IsSecretRefText(value string) bool {
	return secretRefTextRE.MatchString(strings.TrimSpace(value))
}
