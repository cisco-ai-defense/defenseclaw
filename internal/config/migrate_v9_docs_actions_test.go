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
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// migrateV9Page is the appendix page that shows the audit.db actions rows
// and what the migration does with them.
func migrateV9Page(t *testing.T) string {
	t.Helper()
	page := filepath.Join("..", "..", "docs-site", "content", "docs", "reference", "migrate-v9.mdx")
	data, err := os.ReadFile(page)
	if err != nil {
		t.Skipf("docs page not available: %v", err)
	}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	start := strings.Index(text, "### Operator block and allow entries from audit.db")
	if start < 0 {
		t.Fatalf("%s has no 'Operator block and allow entries from audit.db' section", page)
	}
	text = text[start:]
	if end := strings.Index(text[4:], "\n### "); end >= 0 {
		text = text[:end+4]
	}
	return text
}

var (
	docsActionRow   = regexp.MustCompile("(?m)^\\| `(r[0-9]+)` \\| (\\w+) \\| `([^`]+)`(?: \\(connector `([^`]+)`\\))? \\| (.+?) \\| (.+?) \\|$")
	docsActionState = regexp.MustCompile("`(\\w+): (\\w+)`")
	docsStaysRow    = regexp.MustCompile("Row `(r[0-9]+)` stays in `audit.db`")
)

// The page's sample actions table, run through the real migration, must give
// the page's config.yaml excerpt, and exactly the rows the page says stay
// must keep their install state in audit.db (GAP-0581: r4's reason
// "auto-block: HIGH findings" is not a scanner reason, so it moved although
// the page said it stays).
func TestMigrateV9DocsActionsExampleMatchesMigration(t *testing.T) {
	section := migrateV9Page(t)
	rows := docsActionRow.FindAllStringSubmatch(section, -1)
	if len(rows) == 0 {
		t.Fatal("the page's actions table has no rows")
	}
	fence := "```yaml title=\"config.yaml (v9, excerpt)\"\n"
	i := strings.Index(section, fence)
	if i < 0 {
		t.Fatal("the page has no config.yaml (v9, excerpt) block")
	}
	excerpt := section[i+len(fence):]
	excerpt = excerpt[:strings.Index(excerpt, "\n```")]
	var want map[string]any
	if err := yaml.Unmarshal([]byte(excerpt), &want); err != nil {
		t.Fatalf("the page's excerpt is not YAML: %v", err)
	}
	stays := map[string]bool{}
	for _, m := range docsStaysRow.FindAllStringSubmatch(section, -1) {
		stays[m[1]] = true
	}

	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	dir := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", dir)
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("config_version: 8\ndata_dir: "+dir+"\nobservability: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The allow entry's pin on the page is the path it was recorded for.
	allowedPaths := map[string]string{}
	if skill, ok := want["asset_policy"].(map[string]any)["skill"].(map[string]any); ok {
		for _, entry := range asList(skill["allowed"]) {
			e := entry.(map[string]any)
			if paths := asList(e["source_path_contains"]); len(paths) == 1 {
				allowedPaths[e["name"].(string)] = paths[0].(string)
			}
		}
	}
	auditDB := filepath.Join(dir, "audit.db")
	db, err := sql.Open("sqlite", auditDB)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE actions (id TEXT PRIMARY KEY, target_type TEXT NOT NULL, target_name TEXT NOT NULL,
	  source_path TEXT, actions_json TEXT NOT NULL DEFAULT '{}', reason TEXT, updated_at DATETIME NOT NULL,
	  connector TEXT NOT NULL DEFAULT '')`); err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		state := map[string]string{}
		for _, s := range docsActionState.FindAllStringSubmatch(row[5], -1) {
			state[s[1]] = s[2]
		}
		raw, _ := json.Marshal(state)
		reason := strings.Trim(row[6], "`")
		if _, err := db.Exec(`INSERT INTO actions VALUES (?,?,?,?,?,?,'now',?)`,
			row[1], row[2], row[3], allowedPaths[row[3]], string(raw), reason, row[4]); err != nil {
			t.Fatal(err)
		}
	}
	_ = db.Close()

	if _, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath, AuditDBPath: auditDB}); err != nil {
		t.Fatalf("MigrateV9: %v", err)
	}
	migrated, _ := os.ReadFile(configPath)
	var got map[string]any
	if err := yaml.Unmarshal(migrated, &got); err != nil {
		t.Fatal(err)
	}
	if g, w := mustJSON(t, got["asset_policy"]), mustJSON(t, want["asset_policy"]); g != w {
		t.Errorf("the page's actions table migrates to\n%s\nbut the page shows\n%s", g, w)
	}

	db, _ = sql.Open("sqlite", auditDB)
	defer db.Close()
	for _, row := range rows {
		var actions string
		err := db.QueryRow(`SELECT actions_json FROM actions WHERE id = ?`, row[1]).Scan(&actions)
		kept := err == nil && strings.Contains(actions, `"install"`)
		if kept != stays[row[1]] {
			t.Errorf("row %s (reason %s): install kept in audit.db = %v, the page says stays = %v",
				row[1], row[6], kept, stays[row[1]])
		}
	}
}

var docsScannerReason = regexp.MustCompile("`([^`]+)`")

// Every scanner reason form the page lists, with its placeholders filled,
// must be one the migration leaves in audit.db, and each form
// v9AutomaticInstallReason recognises must be listed.
func TestMigrateV9DocsScannerReasonsMatchMigration(t *testing.T) {
	// The list wraps across lines; read it as one line.
	section := strings.Join(strings.Fields(migrateV9Page(t)), " ")
	start := strings.Index(section, "The scanner reasons are ")
	if start < 0 {
		t.Fatal("the page does not list the scanner reasons the migration leaves in audit.db")
	}
	list := section[start:]
	list = list[:strings.Index(list, "Any other reason is moved")]
	fill := strings.NewReplacer("<SEV>", "HIGH", "<N>", "3", "<name>", "skill-scanner")
	var forms []string
	for _, m := range docsScannerReason.FindAllStringSubmatch(list, -1) {
		forms = append(forms, m[1])
	}
	for _, form := range forms {
		switch form {
		case " (scanner=<name>)", ": ", "; ":
			continue // the watcher reason's optional endings, checked below
		}
		reason := fill.Replace(form)
		if strings.HasSuffix(reason, " ") {
			reason += "detail" // a prefix form
		}
		if !v9AutomaticInstallReason(reason) {
			t.Errorf("the page lists %q as a scanner reason, but the migration moves %q", form, reason)
		}
	}
	for _, ending := range []string{" (scanner=skill-scanner)", ": detail", "; detail"} {
		if reason := "auto-block: watch detected HIGH findings" + ending; !v9AutomaticInstallReason(reason) {
			t.Errorf("the page lists the watcher ending of %q, but the migration moves it", reason)
		}
	}
	for _, known := range []string{
		"auto-block: watch detected <SEV> findings",
		"post-scan: <N> findings, max=<SEV>",
		"post-install scan: <N> findings, max=<SEV>",
		"scan: <N> findings, max=<SEV>",
		"scan clean or within policy",
		"scanner failure (fail-closed): ",
		"quarantine failed: ",
		"link removed: ",
	} {
		if !slices.Contains(forms, known) {
			t.Errorf("the page does not list the scanner reason %q", known)
		}
	}
}

func asList(v any) []any {
	list, _ := v.([]any)
	return list
}
