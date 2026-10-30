// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/contracttest"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// identityRefreshSeams replaces every seam of the command; a test that does
// not expect a step makes it fail the test.
type identityRefreshSeams struct {
	privileged bool
	resolved   []string
	flushed    []string
	posted     map[string]any
	answer     identityRefreshAnswer
	postErr    error
}

func installIdentityRefreshSeams(t *testing.T, s *identityRefreshSeams) {
	t.Helper()
	savedPriv, savedResolve, savedFlush, savedPost, savedSC := identityRefreshPrivileged, identityRefreshResolveUser, identityRefreshFlushOSCache, identityRefreshPost, identityRefreshSecureClient
	t.Cleanup(func() {
		identityRefreshPrivileged, identityRefreshResolveUser, identityRefreshFlushOSCache, identityRefreshPost, identityRefreshSecureClient = savedPriv, savedResolve, savedFlush, savedPost, savedSC
	})
	identityRefreshPrivileged = func() bool { return s.privileged }
	identityRefreshSecureClient = func() bool { return false }
	identityRefreshResolveUser = func(user string) (string, string, error) {
		s.resolved = append(s.resolved, user)
		if user == "nobody-here" {
			return "", "", errors.New("no account named \"nobody-here\" on this host")
		}
		return "1916801105", "eng2@corp.example.com", nil
	}
	identityRefreshFlushOSCache = func(name string) (identityRefreshFlush, *enterprisestatus.Message) {
		s.flushed = append(s.flushed, name)
		if name != "" {
			return identityRefreshFlush{Flushed: "user", Method: "sss_cache"}, nil
		}
		return identityRefreshFlush{Flushed: "all", Method: "sss_cache"}, nil
	}
	identityRefreshPost = func(path string, body []byte, out any) (string, error) {
		if path != identityRefreshGatewayPath {
			t.Fatalf("posted to %s", path)
		}
		if err := json.Unmarshal(body, &s.posted); err != nil {
			t.Fatal(err)
		}
		if s.postErr != nil {
			return "", s.postErr
		}
		*(out.(*identityRefreshAnswer)) = s.answer
		return "127.0.0.1:18970", nil
	}
}

func runIdentityRefreshCommand(t *testing.T, args ...string) (map[string]any, []byte, int) {
	t.Helper()
	cmd := newEnterpriseIdentityRefreshCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs(args)
	err := cmd.Execute()
	var doc map[string]any
	if strings.Contains(strings.Join(args, " "), "--json") {
		if jerr := json.Unmarshal(out.Bytes(), &doc); jerr != nil {
			t.Fatalf("output %q: %v", out.String(), jerr)
		}
	}
	return doc, out.Bytes(), runExit(err)
}

// The privilege check comes before any name resolution, flush or gateway
// call.
func TestIdentityRefreshRefusesNotAdminBeforeResolvingAnyName(t *testing.T) {
	seams := &identityRefreshSeams{privileged: false}
	installIdentityRefreshSeams(t, seams)
	doc, raw, exit := runIdentityRefreshCommand(t, "--user", "eng2@corp.example.com", "--flush-os-cache", "--json")
	contracttest.Compile(t).Validate(t, "identity-refresh.schema.json", raw)
	errs, _ := doc["errors"].([]any)
	if len(errs) != 1 || errs[0].(map[string]any)["code"] != "not_admin" {
		t.Fatalf("errors %v, want not_admin", doc["errors"])
	}
	if want := identityRefreshFailureExit(); exit != want {
		t.Fatalf("exit %d, want %d", exit, want)
	}
	if len(seams.resolved) != 0 || len(seams.flushed) != 0 || seams.posted != nil {
		t.Fatalf("a refused run resolved %v, flushed %v, posted %v", seams.resolved, seams.flushed, seams.posted)
	}
	if strings.Contains(string(raw), "eng2") {
		t.Fatalf("the refusal echoes the account: %s", raw)
	}
}

// With --user only that account is flushed and re-read; the result is
// schema valid and lists its change.
func TestIdentityRefreshOfOneAccountFlushesOnlyThatAccount(t *testing.T) {
	seams := &identityRefreshSeams{privileged: true, answer: identityRefreshAnswer{Scope: "user", ProfilesConfigured: true, Refreshed: 1, Changed: 1,
		Changes: []identityRefreshChangeView{{UserID: "1916801105", UserName: "eng2@corp.example.com", PreviousProfile: "engineering",
			PreviousMatch: "group", Profile: "contractors", Match: "group"}}, DurationMS: 30}}
	installIdentityRefreshSeams(t, seams)
	doc, raw, exit := runIdentityRefreshCommand(t, "--user", "eng2@corp.example.com", "--flush-os-cache", "--json")
	contracttest.Compile(t).Validate(t, "identity-refresh.schema.json", raw)
	if exit != 0 || doc["ok"] != true {
		t.Fatalf("exit %d doc %v", exit, doc)
	}
	if len(seams.flushed) != 1 || seams.flushed[0] != "eng2@corp.example.com" {
		t.Fatalf("flushed %v, want only the named account", seams.flushed)
	}
	if seams.posted["user"] != "1916801105" || seams.posted["os_cache_flushed"] != "user" {
		t.Fatalf("posted %v, want the uid and the user flush scope", seams.posted)
	}
	// Without --user the whole cache is flushed.
	seams.flushed, seams.answer = nil, identityRefreshAnswer{Scope: "all", Refreshed: 0}
	_, raw, exit = runIdentityRefreshCommand(t, "--flush-os-cache", "--json")
	contracttest.Compile(t).Validate(t, "identity-refresh.schema.json", raw)
	if exit != 0 || len(seams.flushed) != 1 || seams.flushed[0] != "" || seams.posted["user"] != "" || seams.posted["os_cache_flushed"] != "all" {
		t.Fatalf("exit %d flushed %v posted %v", exit, seams.flushed, seams.posted)
	}
	// Without --flush-os-cache nothing is flushed.
	seams.flushed = nil
	if _, _, exit = runIdentityRefreshCommand(t, "--json"); exit != 0 || len(seams.flushed) != 0 || seams.posted["os_cache_flushed"] != "none" {
		t.Fatalf("exit %d flushed %v posted %v", exit, seams.flushed, seams.posted)
	}
}

func TestIdentityRefreshFailureCodes(t *testing.T) {
	invalid := enterprisestatus.InvalidArgsExitCode(runtime.GOOS)
	for _, tc := range []struct {
		name    string
		args    []string
		postErr error
		answer  identityRefreshAnswer
		code    string
		exit    int
	}{
		{"unknown account", []string{"--user", "nobody-here"}, nil, identityRefreshAnswer{}, "account_unresolved", invalid},
		{"max users", []string{"--max-users", "0"}, nil, identityRefreshAnswer{}, "invalid_arguments", invalid},
		{"busy", nil, &enterpriseGatewayRefusal{status: http.StatusConflict, code: "refresh_busy", message: "another identity refresh is running"},
			identityRefreshAnswer{}, "refresh_busy", enterprisestatus.BusyExitCode(runtime.GOOS)},
		{"per-user gateway", nil, &enterpriseGatewayRefusal{status: http.StatusNotFound}, identityRefreshAnswer{}, "not_managed", identityRefreshFailureExit()},
		{"gateway down", nil, errors.New("the gateway did not answer"), identityRefreshAnswer{}, "gateway_unavailable", identityRefreshFailureExit()},
		{"lookup of the account failed", []string{"--user", "eng2@corp.example.com"}, nil,
			identityRefreshAnswer{Scope: "user", Failed: 1, Failures: []identityRefreshFailureView{{UserID: "1916801105", Code: "lookup_failed"}}},
			"lookup_failed", identityRefreshFailureExit()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			installIdentityRefreshSeams(t, &identityRefreshSeams{privileged: true, postErr: tc.postErr, answer: tc.answer})
			doc, raw, exit := runIdentityRefreshCommand(t, append(tc.args, "--json")...)
			contracttest.Compile(t).Validate(t, "identity-refresh.schema.json", raw)
			errs, _ := doc["errors"].([]any)
			if exit != tc.exit || len(errs) != 1 || errs[0].(map[string]any)["code"] != tc.code {
				t.Fatalf("exit %d errors %v, want %d %s", exit, doc["errors"], tc.exit, tc.code)
			}
		})
	}
}

// An all-account run with some failures and Windows pending accounts
// succeeds with warnings.
func TestIdentityRefreshWarnings(t *testing.T) {
	installIdentityRefreshSeams(t, &identityRefreshSeams{privileged: true, answer: identityRefreshAnswer{Scope: "all", Refreshed: 2, Failed: 1, Skipped: 3,
		Failures:                  []identityRefreshFailureView{{UserID: "1916801106", Code: "lookup_failed"}},
		WindowsTokenGroupsPending: []identityRefreshAccountView{{UserID: "S-1-5-21-1-2-3-1105"}}}})
	doc, raw, exit := runIdentityRefreshCommand(t, "--max-users", "2", "--json")
	contracttest.Compile(t).Validate(t, "identity-refresh.schema.json", raw)
	if exit != 0 {
		t.Fatalf("exit %d", exit)
	}
	var codes []string
	for _, w := range doc["warnings"].([]any) {
		codes = append(codes, w.(map[string]any)["code"].(string))
	}
	if strings.Join(codes, ",") != "windows_token_groups_pending,accounts_skipped,accounts_failed" {
		t.Fatalf("warnings %v", codes)
	}
	// The text form names the counts.
	_, text, _ := runIdentityRefreshCommand(t)
	if !strings.Contains(string(text), "Re-read 2 account(s): 0 changed, 1 failed, 3 skipped") {
		t.Fatalf("text %q", text)
	}
}

func TestVersionJSONReportsIdentityRefresh(t *testing.T) {
	saved := appVersion
	t.Cleanup(func() { appVersion = saved })
	appVersion = "1.0.6"
	var out bytes.Buffer
	if err := writeMachineVersion(&out); err != nil {
		t.Fatal(err)
	}
	doc := contracttest.Compile(t).Validate(t, "version.schema.json", out.Bytes())
	if doc["identity_refresh"] != true {
		t.Fatalf("--version-json %s: want identity_refresh", out.String())
	}
}

func TestEnterpriseIdentityRefreshIsWired(t *testing.T) {
	cmd, _, err := enterpriseCmd.Find([]string{"identity", "refresh"})
	if err != nil || cmd.Name() != "refresh" {
		t.Fatalf("enterprise identity refresh: %v %v", cmd, err)
	}
	for _, flag := range []string{"user", "flush-os-cache", "max-users", "json"} {
		if cmd.Flags().Lookup(flag) == nil {
			t.Fatalf("missing --%s", flag)
		}
	}
}
