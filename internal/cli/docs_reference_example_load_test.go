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

package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The complete config.yaml example on the configuration reference page must
// load the way `config validate` loads it (schema, semantic checks and the
// runtime decode), not only pass the schema: an unquoted 2024-10-21 is a YAML
// date, which the schema accepts and the runtime decode refuses.
func TestReferenceConfigurationExampleLoads(t *testing.T) {
	page := filepath.Join("..", "..", "docs-site", "content", "docs", "reference", "configuration.mdx")
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
	example := body[:end] + "\n"
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	// The example names its credentials by environment variable; a reader
	// sets them, so the test does too.
	for _, name := range envName.FindAllString(example, -1) {
		t.Setenv(name, "docs-example-value")
	}
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(example), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfigV8File(path, filepath.Join(dir, ".defenseclaw")); err != nil {
		t.Fatalf("the complete config example does not load: %v", err)
	}
}

// envName matches an environment variable name such as DEFENSECLAW_LLM_KEY.
var envName = regexp.MustCompile(`\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b`)
