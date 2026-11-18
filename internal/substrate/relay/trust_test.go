//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// GAP-0446: the copy of a git project (/work/<folder>/.git, the copy a
// macOS or Linux launcher makes) is where Claude Code starts, and Claude
// Code does not carry the image's trust on /work into a git repository: the
// first screen was "Is this a project you trust?" with "No, exit" selected.
// The relay records the folder it starts the agent in as trusted, keeping
// the rest of ~/.claude.json as it was.
func TestRelayTrustsTheAgentStartFolderGAP0446(t *testing.T) {
	s, _, ec := testServer(t, []string{"sh"})
	wd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	proj := filepath.Join(wd, "app")
	if err := os.MkdirAll(filepath.Join(proj, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(t.TempDir(), ".claude.json")
	seed := `{"hasCompletedOnboarding": true, "numStartups": 12345678901234567,
  "projects": {"` + wd + `": {"hasTrustDialogAccepted": true, "allowedTools": ["Read"]}}}`
	if err := os.WriteFile(state, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	s.opts.Config.Relay.Workdir = wd
	// Set through JSON so the test also builds on a relay without the field
	// (where it fails on the trust it does not find).
	raw, _ := json.Marshal(map[string]string{"claude_state_file": state})
	if err := json.Unmarshal(raw, &s.opts.Config.Relay); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	req, _ := http.NewRequest("POST", srv.URL+Path(RoutePoll)+"?cols=80&rows=24&dir="+url.QueryEscape(proj), nil)
	req.Header.Set("Authorization", "Bearer "+ec.token(t, claims(time.Now(), nil), TokenType))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("attach in %s answered %d", proj, resp.StatusCode)
	}

	b, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		HasCompletedOnboarding bool        `json:"hasCompletedOnboarding"`
		NumStartups            json.Number `json:"numStartups"`
		Projects               map[string]struct {
			HasTrustDialogAccepted bool     `json:"hasTrustDialogAccepted"`
			AllowedTools           []string `json:"allowedTools"`
		} `json:"projects"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("%s after the start: %v\n%s", state, err, b)
	}
	if !doc.Projects[proj].HasTrustDialogAccepted {
		t.Fatalf("the agent started in %s, which is not trusted in %s:\n%s", proj, state, b)
	}
	if !doc.HasCompletedOnboarding || doc.NumStartups != "12345678901234567" ||
		!doc.Projects[wd].HasTrustDialogAccepted || len(doc.Projects[wd].AllowedTools) != 1 {
		t.Fatalf("the rest of %s was not kept:\n%s", state, b)
	}
	if fi, err := os.Stat(state); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("%s mode %v %v, want 0600", state, fi, err)
	}
}

// A relay without a Claude Code state file writes none (codex and the other
// connectors, and every test that runs the relay as the developer).
func TestClaudeTrustOnlyWithAStateFileGAP0446(t *testing.T) {
	s, _, ec := testServer(t, []string{"sh"})
	home := t.TempDir()
	t.Setenv("HOME", home)
	wd, _ := filepath.EvalSymlinks(t.TempDir())
	s.opts.Config.Relay.Workdir = wd
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	req, _ := http.NewRequest("POST", srv.URL+Path(RoutePoll)+"?cols=80&rows=24", nil)
	req.Header.Set("Authorization", "Bearer "+ec.token(t, claims(time.Now(), nil), TokenType))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if _, err := os.Stat(filepath.Join(home, ".claude.json")); !os.IsNotExist(err) {
		t.Fatalf("a relay with no claude_state_file wrote ~/.claude.json: %v", err)
	}
}

// A link in place of the state file is left alone, and so is its target.
func TestClaudeTrustLeavesALinkAloneGAP0446(t *testing.T) {
	s, _, ec := testServer(t, []string{"sh"})
	wd, _ := filepath.EvalSymlinks(t.TempDir())
	s.opts.Config.Relay.Workdir = wd
	target := filepath.Join(t.TempDir(), "elsewhere.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), ".claude.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]string{"claude_state_file": link})
	if err := json.Unmarshal(raw, &s.opts.Config.Relay); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	req, _ := http.NewRequest("POST", srv.URL+Path(RoutePoll)+"?cols=80&rows=24", nil)
	req.Header.Set("Authorization", "Bearer "+ec.token(t, claims(time.Now(), nil), TokenType))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("attach answered %d: a state file the relay cannot record in must not stop the agent", resp.StatusCode)
	}
	if b, _ := os.ReadFile(target); string(b) != "{}" {
		t.Fatalf("the link's target changed: %s", b)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the link was replaced: %v %v", fi, err)
	}
}

// A relay that runs as root starts the agent as its own user (GAP-0116),
// and ~/.claude.json is in the agent's home: the separated relay records the
// start folder's trust through its claude-trust child (as the agent's user),
// never in its own process. Here the child is a wrapper of the test binary
// that notes each child command it runs, as the test's user.
func TestSeparatedRelayRecordsClaudeTrustAsTheAgentGAP0446(t *testing.T) {
	s, _, ec := testServer(t, []string{"sh"})
	wd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	marks := filepath.Join(bin, "children")
	wrapper := filepath.Join(bin, "relay")
	script := "#!/bin/sh\necho \"$1\" >> '" + marks + "'\nexec '" + os.Args[0] + "' \"$@\"\n"
	if err := os.WriteFile(wrapper, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	s.opts.sep = &separation{exe: wrapper}
	state := filepath.Join(t.TempDir(), ".claude.json")
	s.opts.Config.Relay.Workdir = wd
	raw, _ := json.Marshal(map[string]string{"claude_state_file": state})
	if err := json.Unmarshal(raw, &s.opts.Config.Relay); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	req, _ := http.NewRequest("POST", srv.URL+Path(RoutePoll)+"?cols=80&rows=24", nil)
	req.Header.Set("Authorization", "Bearer "+ec.token(t, claims(time.Now(), nil), TokenType))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("attach answered %d", resp.StatusCode)
	}
	b, err := os.ReadFile(state)
	if err != nil || !bytes.Contains(b, []byte(`"hasTrustDialogAccepted": true`)) {
		t.Fatalf("%s after the start: %v\n%s", state, err, b)
	}
	if m, _ := os.ReadFile(marks); !bytes.Contains(m, []byte(childClaudeTrust+"\n")) {
		t.Fatalf("the trust was not recorded through the agent's-user child (children run: %q)", m)
	}
	if fi, err := os.Stat(state); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("%s mode %v %v, want 0600", state, fi, err)
	}
}
