// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func cfrEncode(t *testing.T, targets map[string]string) string {
	t.Helper()
	data, err := json.Marshal(targets)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(data)
	if _, ok := hookpaths.Decode(encoded); !ok {
		t.Fatal("forged evidence was invalid")
	}
	return encoded
}

func TestCFRForgedSourceEvidenceMustBlock(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	if err := os.WriteFile(filepath.Join(f.project, "setf.sh"), []byte("f=keylink\n"), 0600); err != nil {
		t.Fatal(err)
	}
	command := `f=a.txt; . ./setf.sh; echo m >> "$f"`
	payload := f.payload(t, command)
	legit := f.clientHeader(t, payload)
	if got := f.post(t, "claudecode", payload, legit); got != "block" {
		t.Fatalf("legitimate evidence: %s", got)
	}
	targets, ok := hookpaths.Decode(legit)
	if !ok {
		t.Fatal("legitimate evidence invalid")
	}
	sum := sha256.Sum256([]byte(command))
	targets["\x00source-redirect:"+hex.EncodeToString(sum[:])] = filepath.Join(f.project, "out.txt")
	targets[hookpaths.CWDKey] = f.project
	forged := cfrEncode(t, targets)
	if got := f.post(t, "claudecode", payload, forged); got != "block" {
		t.Fatalf("forged ordinary source target changed protected write to %s", got)
	}
}

func TestCFRForgedHermesEvidenceMustBlock(t *testing.T) {
	home, project := hermesPatchHome(t)
	parent := filepath.Dir(home)
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.Symlink(keys, filepath.Join(project, "keylink")); err != nil {
		t.Fatal(err)
	}
	patch := hermesV4AUpdate("keylink")
	body := hermesPatchBody(t, project, "patch", map[string]any{"mode": "patch", "patch": patch})
	legit := hookpaths.ResolveConnector("hermes", "", "pre_tool_call", []byte(body))
	targets, ok := hookpaths.Decode(legit)
	if !ok {
		t.Fatal("legitimate evidence invalid")
	}
	target := filepath.Join(project, "keylink")
	if err := os.Chmod(parent, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(parent, 0700)
	serve := func(header string) string {
		cfg := &config.Config{}
		cfg.Guardrail.Mode = "action"
		cfg.Guardrail.Connector = "hermes"
		api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/hermes/hook", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(hookpaths.Header, header)
		req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
		out := httptest.NewRecorder()
		api.handleAgentHook("hermes").ServeHTTP(out, req)
		return hermesOutcome(t, out.Body.String()).action
	}
	if got := serve(legit); got != "block" {
		t.Fatalf("legitimate evidence: %s", got)
	}
	targets[target] = filepath.Join(project, "out.txt")
	forged := cfrEncode(t, targets)
	if got := serve(forged); got != "block" {
		t.Fatalf("forged ordinary patch target changed protected write to %s", got)
	}
}

func TestCFRRealClientSourceChangedAfterProofMustBlock(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	source := filepath.Join(f.project, "setf.sh")
	if err := os.WriteFile(source, []byte("f=out.txt\n"), 0600); err != nil {
		t.Fatal(err)
	}
	command := `f=a.txt; . ./setf.sh; echo m >> "$f"`
	payload := f.payload(t, command)
	header := f.clientHeader(t, payload)
	if err := os.WriteFile(source, []byte("f=keylink\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := f.post(t, "claudecode", payload, header); got != "block" {
		t.Fatalf("client header from ordinary source was replayed after protected retarget: %s", got)
	}
}

func TestCFRRealClientHermesLinkChangedAfterProofMustBlock(t *testing.T) {
	home, project := hermesPatchHome(t)
	parent := filepath.Dir(home)
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	ordinary := filepath.Join(project, "out.txt")
	if err := os.WriteFile(ordinary, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(project, "keylink")
	if err := os.Symlink(ordinary, link); err != nil {
		t.Fatal(err)
	}
	patch := hermesV4AUpdate("keylink")
	body := hermesPatchBody(t, project, "patch", map[string]any{"mode": "patch", "patch": patch})
	header := hookpaths.ResolveConnector("hermes", "", "pre_tool_call", []byte(body))
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keys, link); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(parent, 0700)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "hermes"
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hermes/hook", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(hookpaths.Header, header)
	req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
	out := httptest.NewRecorder()
	api.handleAgentHook("hermes").ServeHTTP(out, req)
	if got := hermesOutcome(t, out.Body.String()).action; got != "block" {
		t.Fatalf("client header from ordinary link was replayed after protected retarget: %s", got)
	}
}
