// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// gap0055ServePack answers call as serve does, with rulePack ("" is the
// default pack, "strict" the strict one).
func (f b36ManagedHookFixture) gap0055ServePack(call *hookCall, rulePack string) (string, string) {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = call.connector
	cfg.Guardrail.RulePack = rulePack
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(call.payload)))
	if call.managed && call.header != "" {
		req.Header.Set(hookpaths.Header, call.header)
	}
	if call.connector == "codex" {
		setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	}
	if call.managed {
		req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: f.home}))
	}
	recorder := httptest.NewRecorder()
	api.handleAgentHook(call.connector).ServeHTTP(recorder, req)
	body := recorder.Body.String()
	switch {
	case strings.HasPrefix(body, `{"action":"block"`):
		return "block", body
	case strings.HasPrefix(body, `{"action":"allow"`):
		return "allow", body
	}
	return fmt.Sprintf("status %d body %.200s", recorder.Code, body), body
}

// TestGAP0055SuppliedArchiveModeIsPossibleGrade is gas-ux-r1 GAP-0055 rounds
// 4 and 5 (ROOTCAUSE-CROSS-1 Rule G): an archive call whose arguments come
// from an argument supplier and that shows a list or test mode (xargs unzip
// -v, -lv, -Z1, tar -tf, 7z l, jar tf, also in a sh -c body) may
// still extract through the supplied words, so a later write it could
// redirect is a Possible hit. The default pack allows it with a visible
// alert-only finding; the strict pack blocks it. A later write whose target
// is Named (the project's link to authorized_keys) blocks in both packs, and
// a supplied call that shows no mode (xargs unzip) keeps its block. Both
// connectors, managed and per-user.
func TestGAP0055SuppliedArchiveModeIsPossibleGrade(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	if err := os.WriteFile(filepath.Join(f.project, "a.txt"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(f.project, "build"), 0o700); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		name, command    string
		balanced, strict string
		possible         bool
	}{
		{"possible", `ls *.zip | xargs unzip -v; cp a.txt build/`, "allow", "block", true},
		{"possible-n1-and", `ls *.zip | xargs -n1 unzip -v && cp a.txt build/`, "allow", "block", true},
		{"possible-replace", `ls *.zip | xargs -I{} unzip -v {}; cp a.txt build/`, "allow", "block", true},
		{"possible-sudo", `ls *.zip | xargs sudo unzip -v; cp a.txt build/`, "allow", "block", true},
		{"named-copy", `ls *.zip | xargs unzip -v; cp a.txt keylink`, "block", "block", false},
		{"named-redirect", `ls *.zip | xargs unzip -v; echo hi > keylink`, "block", "block", false},
		{"named-after-possible-and-unseen", `ls *.zip | xargs unzip -v; ls *.zip | xargs unzip; cp a.txt build/`, "block", "block", false},
		{"unseen", `ls *.zip | xargs unzip; cp a.txt build/`, "block", "block", false},
		{"unseen-overwrite", `ls *.zip | xargs unzip -o; cp a.txt build/`, "block", "block", false},
		{"direct-version", `unzip -v; cp a.txt build/`, "allow", "", false},
		// Round 5 M1: the unzip list and test mode family is one class.
		{"possible-cluster-vq", `ls *.zip | xargs unzip -vq; cp a.txt build/`, "allow", "block", true},
		{"possible-cluster-lv", `ls *.zip | xargs unzip -lv; cp a.txt build/`, "allow", "block", true},
		{"possible-cluster-tq", `ls *.zip | xargs unzip -tq; cp a.txt build/`, "allow", "block", true},
		{"possible-cluster-Z1", `ls *.zip | xargs unzip -Z1; cp a.txt build/`, "allow", "block", true},
		{"possible-cluster-n1-and", `ls *.zip | xargs -n1 unzip -lv && cp a.txt build/`, "allow", "block", true},
		{"possible-cluster-env-redirect", `ls *.zip | env xargs unzip -Z1; echo hi > build/x`, "allow", "block", true},
		// Round 5 M2: a literal sh -c / bash -c body is graded as at top level.
		{"possible-bash-c", `bash -c 'ls *.zip | xargs unzip -v; cp a.txt build/'`, "allow", "block", true},
		{"possible-sh-c-cluster", `sh -c 'ls *.zip | xargs unzip -lv; cp a.txt build/'`, "allow", "block", true},
		{"possible-sh-c-double", `sh -c "ls *.zip | xargs unzip -t; cp a.txt build/"`, "allow", "block", true},
		{"named-bash-c", `bash -c 'ls *.zip | xargs unzip -v; cp a.txt keylink'`, "block", "block", false},
		{"named-sh-c-redirect", `sh -c 'ls *.zip | xargs unzip -lv; echo hi > keylink'`, "block", "block", false},
		// Round 5 M3: -l, -t, -Z, tar -t, 7z l and jar t are the same Possible scope.
		{"possible-l", `ls *.zip | xargs unzip -l; cp a.txt build/`, "allow", "block", true},
		{"possible-t", `ls *.zip | xargs unzip -t; cp a.txt build/`, "allow", "block", true},
		{"possible-Z", `ls *.zip | xargs unzip -Z; cp a.txt build/`, "allow", "block", true},
		{"possible-tar-tf", `ls *.tar | xargs tar -tf; cp a.txt build/`, "allow", "block", true},
		{"possible-tar-tvf", `ls *.tar | xargs tar -tvf; cp a.txt build/`, "allow", "block", true},
		{"possible-bsdtar-tf", `ls *.tar | xargs bsdtar -tf; cp a.txt build/`, "allow", "block", true},
		{"possible-7z-l", `ls *.7z | xargs 7z l; cp a.txt build/`, "allow", "block", true},
		{"possible-jar-tf", `ls *.jar | xargs jar tf; cp a.txt build/`, "allow", "block", true},
		{"possible-busybox-xargs", `ls *.zip | busybox xargs unzip -l; cp a.txt build/`, "allow", "block", true},
		{"possible-xargs-a-procsubst", `ls *.zip | xargs -a <(ls *.zip) unzip -t; cp a.txt build/`, "allow", "block", true},
		{"possible-eval", `eval 'ls *.zip | xargs unzip -v'; cp a.txt build/`, "allow", "block", true},
		{"named-eval", `eval 'ls *.zip | xargs unzip -l'; cp a.txt keylink`, "block", "block", false},
		{"possible-supplied-sh-c-list", `ls *.zip | xargs -I{} sh -c 'unzip -l {}'; cp a.txt build/`, "allow", "block", true},
		{"possible-supplied-sh-c-v", `ls *.zip | xargs -I{} sh -c 'unzip -v {}'; cp a.txt build/`, "allow", "block", true},
		{"named-supplied-sh-c-list-redirect", `ls *.zip | xargs -I{} sh -c 'unzip -l {} > keylink'; cp a.txt build/`, "block", "block", false},
		// Round 6: one shell -c argument reader (MF-1 sh -c --, MF-2 launchers and
		// positional words, MF-3).
		{"named-mf1-0", `ls | xargs -I{} sh -c -- 'cp a.txt $HOME/.ssh/authorized_keys'`, "block", "block", false},
		{"named-mf1-1", `ls | xargs -I{} sh -c -- 'echo k >> $HOME/.ssh/authorized_keys'`, "block", "block", false},
		{"named-mf1-2", `ls | xargs sh -c -- 'cp a.txt $HOME/.ssh/authorized_keys' _`, "block", "block", false},
		{"named-mf1-3", `ls | xargs bash -c -- 'cp a.txt "$HOME"/.ssh/authorized_keys' _`, "block", "block", false},
		{"named-mf1-4", `ls | xargs -I{} sh -c -- 'tee -a ${HOME}/.ssh/authorized_keys < a.txt'`, "block", "block", false},
		{"named-mf1-5", `ls | xargs -I{} sh -ec -- 'cp a.txt keylink'`, "block", "block", false},
		{"named-mf1-6", `ls | xargs -I{} env sh -c -- 'cp a.txt $HOME/.ssh/authorized_keys'`, "block", "block", false},
		{"possible-mf2-0", `env sh -c 'ls *.zip | xargs unzip -l; cp a.txt build/'`, "allow", "block", true},
		{"possible-mf2-1", `env -i sh -c 'ls *.zip | xargs unzip -l; cp a.txt build/'`, "allow", "block", true},
		{"possible-mf2-2", `env -i PATH=/usr/bin sh -c 'ls *.zip | xargs unzip -l; cp a.txt build/'`, "allow", "block", true},
		{"possible-mf2-3", `/usr/bin/env bash -c 'ls *.zip | xargs unzip -l; cp a.txt build/'`, "allow", "block", true},
		{"possible-mf2-4", `sudo sh -c 'ls *.zip | xargs unzip -l; cp a.txt build/'`, "allow", "block", true},
		{"possible-mf2-5", `sudo -E bash -lc 'ls *.zip | xargs unzip -l; cp a.txt build/'`, "allow", "block", true},
		{"possible-mf2-6", `nice sh -c 'ls *.zip | xargs unzip -l; cp a.txt build/'`, "allow", "block", true},
		{"possible-mf2-7", `nice -n 5 sh -c 'ls *.zip | xargs unzip -l; cp a.txt build/'`, "allow", "block", true},
		{"possible-mf2-8", `command sh -c 'ls *.zip | xargs unzip -l; cp a.txt build/'`, "allow", "block", true},
		{"possible-mf2-9", `exec sh -c 'ls *.zip | xargs unzip -l; cp a.txt build/'`, "allow", "block", true},
		{"possible-mf2-10", `busybox sh -c 'ls *.zip | xargs unzip -l; cp a.txt build/'`, "allow", "block", true},
		{"possible-mf2-11", `timeout 60 sh -c 'ls *.zip | xargs unzip -l; cp a.txt build/'`, "allow", "block", true},
		{"possible-mf2-12", `nohup sh -c 'ls *.zip | xargs unzip -l; cp a.txt build/'`, "allow", "block", true},
		{"possible-mf2-13", `bash -o pipefail -c 'ls *.zip | xargs unzip -l; cp a.txt build/'`, "allow", "block", true},
		{"possible-mf2-14", `sh -e -c 'ls *.zip | xargs unzip -l; cp a.txt build/'`, "allow", "block", true},
		{"possible-mf2-pos-0", `sh -c 'ls *.zip | xargs unzip -l; cp a.txt build/' sh`, "allow", "block", true},
		{"possible-mf2-pos-1", `sh -c 'ls *.zip | xargs unzip -l; cp a.txt build/' _ a b`, "allow", "block", true},
		{"possible-mf2-pos-2", `sh -c 'ls *.zip | xargs unzip -lv; cp a.txt build/' sh`, "allow", "block", true},
		{"possible-mf2-env-outside", `env sh -c 'ls *.zip | xargs unzip -l'; cp a.txt build/`, "allow", "block", true},
		{"possible-mf2-env-v-outside", `env sh -c 'ls *.zip | xargs unzip -v'; cp a.txt build/`, "allow", "block", true},
		{"possible-mf2-env-tar", `env sh -c 'ls *.tar | xargs -n1 tar -tf; cp a.txt build/'`, "allow", "block", true},
		{"possible-mf3-0", `sh -c -- 'ls *.zip | xargs unzip -v; cp a.txt build/'`, "allow", "block", true},
		{"possible-mf3-1", `bash -c -- 'ls *.zip | xargs unzip -v; cp a.txt build/'`, "allow", "block", true},
		{"possible-mf3-2", `bash -ec -- 'ls *.zip | xargs unzip -v; cp a.txt build/'`, "allow", "block", true},
		{"possible-mf3-3", `env sh -c -- 'ls *.zip | xargs unzip -v; cp a.txt build/'`, "allow", "block", true},
		{"possible-mf3-l", `sh -c -- 'ls *.zip | xargs unzip -l; cp a.txt build/'`, "allow", "block", true},
		{"named-mf2-env", `env sh -c 'ls *.zip | xargs unzip -l; cp a.txt keylink'`, "block", "block", false},
		{"named-mf2-sudo", `sudo sh -c 'ls *.zip | xargs unzip -l; echo hi > keylink'`, "block", "block", false},
		{"named-mf2-pos", `sh -c -- 'ls *.zip | xargs unzip -v; cp a.txt keylink' sh`, "block", "block", false},
		{"named-mf2-nice-home", `nice sh -c 'ls *.zip | xargs unzip -l; cp a.txt $HOME/.ssh/authorized_keys'`, "block", "block", false},
		{"ordinary-env-sh-list", `env sh -c 'ls *.zip | xargs unzip -l'`, "allow", "", false},
		{"possible-l-link", `ls *.zip | xargs unzip -l; ln -s ../a.txt build/l`, "allow", "block", true},
		{"named-cluster", `ls *.zip | xargs unzip -vq; cp a.txt keylink`, "block", "block", false},
		{"named-tar", `ls *.tar | xargs tar -tf; cp a.txt keylink`, "block", "block", false},
		{"named-in-supplied-call", `ls *.zip | xargs unzip -l keylink; cp a.txt build/`, "block", "block", false},
		{"unseen-cluster-overwrite", `ls *.zip | xargs unzip -lo; cp a.txt build/`, "block", "block", false},
		{"unseen-exdir", `ls *.zip | xargs unzip -v -d build; cp a.txt build/`, "block", "block", false},
		{"unseen-tar-x", `ls *.tar | xargs tar -xf; cp a.txt build/`, "block", "block", false},
		{"unseen-7z-x", `ls *.7z | xargs 7z x; cp a.txt build/`, "block", "block", false},
		// Round 5 S3: a Named write inside a supplied shell body or argv
		// blocks in every cell, managed included.
		{"named-supplied-sh-c", `ls *.zip | xargs -I{} sh -c 'unzip -v {} && cp a.txt keylink'`, "block", "block", false},
		{"named-supplied-bash-c", `ls *.zip | xargs bash -c 'unzip -v "$@"; cat a.txt > keylink' _`, "block", "block", false},
		{"named-supplied-replace", `ls *.zip | xargs -I{} cp {} keylink`, "block", "block", false},
		{"ordinary-supplied-replace", `ls *.zip | xargs -I{} cp {} build/`, "allow", "", false},
	}
	if err := os.Chmod(f.homes, 0o700); err != nil {
		t.Fatal(err)
	}
	var calls []*hookCall
	for _, row := range rows {
		payload := f.payload(t, row.command)
		calls = append(calls, everyMode(row.name, payload, hookpaths.Resolve(payload))...)
	}
	defer os.Chmod(f.homes, 0o700)
	for _, pack := range []string{"", "strict"} {
		for _, managed := range []bool{false, true} {
			mode := os.FileMode(0o700)
			if managed {
				mode = 0
			}
			if err := os.Chmod(f.homes, mode); err != nil {
				t.Fatal(err)
			}
			for i, call := range calls {
				if call.managed != managed {
					continue
				}
				row := rows[i/4]
				want := row.balanced
				if pack == "strict" {
					want = row.strict
				}
				verdict, body := f.gap0055ServePack(call, pack)
				if strings.HasPrefix(body, `{"action":"alert"`) {
					verdict = "allow" // alert: allowed with a visible warning
				}
				if want != "" && verdict != want {
					t.Errorf("%s pack=%q: verdict %s, want %s; body %.400s", call.name, pack, verdict, want, body)
				}
				if row.possible && pack == "" && !strings.Contains(body, "supplied arguments") {
					t.Errorf("%s pack=%q: no visible Possible finding; body %.300s", call.name, pack, body)
				}
			}
		}
	}
}
