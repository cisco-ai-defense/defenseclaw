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

package scanner

import (
	"context"
	"strings"
)

// Scanner defines the interface that all scanner implementations must satisfy.
// Built-in scanners wrap external CLI tools. Plugins implement this interface
// as standalone gRPC binaries discovered in ~/.defenseclaw/plugins/.
type Scanner interface {
	Name() string
	Version() string
	SupportedTargets() []string
	Scan(ctx context.Context, target string) (*ScanResult, error)
}

// scannerFailureText is a scanner subprocess's stderr as it is reported to the
// caller: a Python traceback is cut to its exception line, so interpreter and
// package paths and scanner source lines do not reach CLI or API output
// (GAP-0229). ScanResult.ScanError keeps the full text for diagnostics.
func scannerFailureText(stderr string) string {
	text := strings.TrimSpace(stderr)
	head, _, found := strings.Cut(text, "Traceback (most recent call last)")
	if !found {
		return text
	}
	last := text[strings.LastIndex(text, "\n")+1:]
	return strings.TrimSpace(strings.TrimSpace(head) + " " + strings.TrimSpace(last))
}
