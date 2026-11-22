// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"github.com/defenseclaw/defenseclaw/internal/testenv/hlinkmatrix"
)

// globOracleBashReachesKeys runs the variant in real bash in a fresh tree of
// the same layout and reports whether the decoy keys inode changed.
func globOracleBashReachesKeys(t *testing.T, bash string, v hlinkmatrix.Variant) bool {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	project := filepath.Join(home, "project")
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	for _, dir := range []string{filepath.Dir(keys), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(keys, []byte("# decoy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	_ = os.Chtimes(keys, old, old)
	hlinkmatrix.Rev2Setup(t, project, keys, hlinkmatrix.DefaultNames(), v.Layout)
	before, _ := os.Stat(keys)
	beforeData, _ := os.ReadFile(keys)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bash, "-c", v.Command)
	cmd.Dir = project
	cmd.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin", "LANG=C", "TMPDIR=" + root}
	for name, value := range v.Env {
		cmd.Env = append(cmd.Env, name+"="+value)
	}
	cmd.Stdin = strings.NewReader("")
	_ = cmd.Run()
	after, err := os.Stat(keys)
	if err != nil {
		return true
	}
	afterData, _ := os.ReadFile(keys)
	return !bytes.Equal(beforeData, afterData) || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime())
}

// globOracleFourCell holds every class variant that keep selects, and that
// real bash runs into the keys inode, to a block in all four hook cells. The
// hook client sends the agent shell startup (its glob options included) to
// both gateways, as hookexec does; the per-user gateway itself runs without
// the agent environment. It returns the number of such variants.
func globOracleFourCell(t *testing.T, keep func(hlinkmatrix.Variant) bool) int {
	t.Helper()
	bash := "/usr/bin/bash"
	if _, err := os.Stat(bash); err != nil {
		t.Skip("bash not available")
	}
	groups := map[string][]hlinkmatrix.Variant{}
	for _, v := range hlinkmatrix.Rev2ClassVariants(hlinkmatrix.DefaultNames()) {
		if !keep(v) || !globOracleBashReachesKeys(t, bash, v) {
			continue
		}
		env, _ := json.Marshal(v.Env)
		key := v.Layout + " " + string(env)
		groups[key] = append(groups[key], v)
	}
	var keys []string
	total := 0
	for key, cases := range groups {
		keys = append(keys, key)
		total += len(cases)
	}
	sort.Strings(keys)
	missed := map[string][]string{}
	for _, key := range keys {
		cases := groups[key]
		t.Run(key, func(t *testing.T) {
			f := newB36ManagedHookFixture(t)
			hlinkmatrix.Rev2Setup(t, f.project, f.keys, hlinkmatrix.DefaultNames(), cases[0].Layout)
			for name, value := range cases[0].Env {
				t.Setenv(name, value)
			}
			var payloads [][]byte
			for _, c := range cases {
				payloads = append(payloads, f.payload(t, c.Command))
			}
			headers := f.clientHeaders(t, payloads)
			startup := hookpaths.CurrentShellStartup().Encode()
			for name := range cases[0].Env {
				os.Unsetenv(name)
			}
			var calls []*hookCall
			for i, c := range cases {
				for _, call := range everyMode(c.ID, payloads[i], headers[i]) {
					call.startup = startup
					calls = append(calls, call)
				}
			}
			f.answerAll(t, calls)
			for i, call := range calls {
				if call.verdict != "block" {
					cell := call.connector + "/managed=" + map[bool]string{true: "true", false: "false"}[call.managed]
					missed[cell] = append(missed[cell], cases[i/4].ID)
				}
			}
			if data, err := os.ReadFile(f.keys); err != nil || string(data) != "# decoy\n" {
				t.Fatalf("decoy keys file changed: %q %v", data, err)
			}
		})
	}
	var cells []string
	for cell := range missed {
		cells = append(cells, cell)
	}
	sort.Strings(cells)
	for _, cell := range cells {
		ids := missed[cell]
		sort.Strings(ids)
		t.Errorf("bash reaches the keys inode, %s does not block: %d rows: %s", cell, len(ids), strings.Join(ids, ", "))
	}
	return total
}

// GAP-0379: bash globs an attached option value (dd of=PATTERN) as one word,
// prefix included. When nothing matches the whole word, the program gets the
// pattern itself as the name to write, and that name can be a hard link of
// the keys: every cell blocks it (rel-1-0-10:GAP-0379).
func TestGAP0379AttachedValueIsGlobbedAsOneWordFourCell(t *testing.T) {
	n := globOracleFourCell(t, func(v hlinkmatrix.Variant) bool { return strings.HasSuffix(v.Base.ID, "-dd") })
	if n == 0 {
		t.Fatal("no dd variant reaches the keys in bash: the fixture changed")
	}
	t.Logf("variants reaching the keys: %d", n)
}

// GAP-0380: glob options the call itself sets (shopt -s, a GLOBIGNORE
// assignment) and the options bash imports from BASHOPTS or GLOBIGNORE in the
// agent environment change what a glob word names; every cell blocks a
// variant that bash runs into the keys under them (rel-1-0-10:GAP-0380).
func TestGAP0380GlobOptionsOfTheCallAndAgentFourCell(t *testing.T) {
	n := globOracleFourCell(t, func(v hlinkmatrix.Variant) bool { return !strings.HasSuffix(v.Transform, "+none") })
	if n == 0 {
		t.Fatal("no option variant reaches the keys in bash: the fixture changed")
	}
	t.Logf("variants reaching the keys: %d", n)
}
