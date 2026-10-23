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

package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The complete config.yaml example on the configuration reference page must
// pass the shipped schema, so a key the schema no longer accepts fails CI
// instead of reaching readers who copy the example.
func TestReferenceConfigurationExampleMatchesSchema(t *testing.T) {
	page := filepath.Join("..", "..", "docs-site", "content", "docs", "reference", "configuration", "index.mdx")
	data, err := os.ReadFile(page)
	if err != nil {
		t.Skipf("docs page not available: %v", err)
	}
	// A Windows checkout has CRLF line ends; the example is read as LF.
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	const fence = "```yaml\nconfig_version: 9"
	start := strings.Index(text, fence)
	if start < 0 {
		t.Fatalf("the complete example (a yaml block that starts with config_version: 9) is missing from %s", page)
	}
	body := text[start+len("```yaml\n"):]
	end := strings.Index(body, "\n```")
	if end < 0 {
		t.Fatalf("the complete example in %s has no closing fence", page)
	}
	// Validate the example exactly as a reader copies it.
	example := body[:end]
	if err := ValidateV8SchemaBytes(page, []byte(example+"\n")); err != nil {
		t.Fatalf("the complete config example does not match the config_version 9 schema: %v", err)
	}
	// A placeholder the schema does not catch (a free-form string) would
	// still break a copied file, so placeholders live only in comments.
	for n, line := range strings.Split(example, "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		if placeholder.MatchString(line) {
			t.Errorf("line %d of the complete example holds a placeholder outside a comment: %q", n+1, line)
		}
	}
}

// placeholder matches a <name> placeholder such as <64 hex digits>.
var placeholder = regexp.MustCompile(`<[^<>\s][^<>]*>`)
