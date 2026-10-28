// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

const regexCookbookPage = "../../docs-site/content/docs/policies/regex-cookbook.mdx"

var (
	cookbookExcerpt  = regexp.MustCompile("(?s)```yaml title=\"policies/guardrail/strict/rules/([a-z-]+\\.yaml) \\(excerpt\\)\"\n(.*?)```")
	cookbookTableRow = regexp.MustCompile("(?m)^\\| `([A-Z0-9-]+)` \\| `(.*)` \\| .* \\|$")
	cookbookSample   = regexp.MustCompile("(?m)^\\| (.+) \\| (`[A-Z0-9-]+`|none: .+) \\|$")
)

// The rules the regex cookbook quotes are the ones the strict pack ships.
func TestRegexCookbookQuotesTheShippedStrictRules(t *testing.T) {
	page := readCookbookPage(t)
	shipped := map[string]map[string]any{}
	files, err := filepath.Glob(filepath.Join("..", "..", "policies", "guardrail", "strict", "rules", "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("strict pack rules: %v %v", files, err)
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Rules []map[string]any `yaml:"rules"`
		}
		if err := yaml.Unmarshal(data, &doc); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		for _, rule := range doc.Rules {
			shipped[filepath.Base(file)+"/"+rule["id"].(string)] = rule
		}
	}
	excerpts := cookbookExcerpt.FindAllStringSubmatch(page, -1)
	if len(excerpts) < 5 {
		t.Fatalf("found %d rule excerpts on the page", len(excerpts))
	}
	for _, excerpt := range excerpts {
		var rules []map[string]any
		if err := yaml.Unmarshal([]byte(excerpt[2]), &rules); err != nil {
			t.Fatalf("%s excerpt: %v", excerpt[1], err)
		}
		for _, rule := range rules {
			want := shipped[excerpt[1]+"/"+rule["id"].(string)]
			if want == nil {
				t.Errorf("the page quotes %s from %s, which the strict pack does not ship", rule["id"], excerpt[1])
				continue
			}
			for key, value := range rule {
				if !reflect.DeepEqual(value, want[key]) {
					t.Errorf("%s %s on the page is %v; the strict pack has %v", rule["id"], key, value, want[key])
				}
			}
		}
	}
	rows := cookbookTableRow.FindAllStringSubmatch(page, -1)
	if len(rows) < 5 {
		t.Fatalf("found %d pattern table rows on the page", len(rows))
	}
	for _, row := range rows {
		want := shipped["secrets.yaml/"+row[1]]
		if want == nil {
			t.Errorf("the page lists %s, which the strict secrets.yaml does not ship", row[1])
			continue
		}
		if got := strings.ReplaceAll(row[2], `\|`, "|"); got != want["pattern"] {
			t.Errorf("%s pattern on the page is %q; the strict pack has %q", row[1], got, want["pattern"])
		}
	}
}

// rel-1-0-4 GAP-0591: the sample tool calls on the regex cookbook get the
// finding the page says. Its readers tried the AWS documentation key and a
// bare private-key header, which the gateway does not report, and concluded
// that secret rules do not run on tool calls.
func TestRegexCookbookSamplesMatchTheShippedRules(t *testing.T) {
	page := readCookbookPage(t)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		t.Fatal(err)
	}
	key := string(pem.EncodeToMemory(block))
	samples := cookbookSample.FindAllStringSubmatch(page, -1)
	if len(samples) < 4 {
		t.Fatalf("found %d sample rows on the page", len(samples))
	}
	for _, sample := range samples {
		call, finding := sample[1], sample[2]
		req := claudeCodeHookRequest{HookEventName: "PreToolUse", ToolName: "Bash"}
		switch {
		case strings.HasPrefix(call, "`cat` of a key that `ssh-keygen -t ed25519` wrote"):
			req.HookEventName = "PostToolUse"
			req.ToolInput = map[string]interface{}{"command": "cat ~/.ssh/id_ed25519"}
			req.ToolResponse = map[string]interface{}{"stdout": key}
		case strings.HasPrefix(call, "`") && strings.HasSuffix(call, "`") && strings.Count(call, "`") == 2:
			req.ToolInput = map[string]interface{}{"command": strings.Trim(call, "`")}
		default:
			t.Fatalf("sample %q is not a command this test can run", call)
		}
		cfg := &config.Config{}
		cfg.Guardrail.Mode = "action"
		cfg.Guardrail.Connector = "claudecode"
		api := &APIServer{scannerCfg: cfg}
		resp := api.evaluateClaudeCodeHook(context.Background(), req)
		if strings.HasPrefix(finding, "none") {
			if len(resp.Findings) != 0 {
				t.Errorf("%s: findings %v, the page says none", call, resp.Findings)
			}
			continue
		}
		rule := strings.Trim(finding, "`")
		found := false
		for _, got := range resp.Findings {
			found = found || strings.HasPrefix(got, rule+":")
		}
		if !found {
			t.Errorf("%s: findings %v, the page says %s", call, resp.Findings, rule)
		}
		// The page says a regex match in a tool call alerts and does not block.
		if resp.Action != "allow" {
			t.Errorf("%s: action %q, the page says the call is not blocked", call, resp.Action)
		}
	}
}

func readCookbookPage(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(regexCookbookPage)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
