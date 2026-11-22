//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// rel-1-0-10 GAP-0906, black box through the old entry point: the HIGH
// audit row --skip-profile posts to the managed gateway names who skipped
// in the actor-reference form the audit record keeps (an actor in another
// form is dropped from the record: internal/audit
// controlPlaneV8PrincipalPattern), and carries skipped_by in after_state.
func TestHookImageRetireSkipPostNamesTheSkippingAccountNatively(t *testing.T) {
	priorEndpoint, priorFactory := windowsManagedLaunchAuditEndpoint, managedGatewayClientFactory
	t.Cleanup(func() { windowsManagedLaunchAuditEndpoint, managedGatewayClientFactory = priorEndpoint, priorFactory })
	managedGatewayClientFactory = func(timeout time.Duration, _ string, _ string) (*http.Client, error) {
		return &http.Client{Timeout: timeout}, nil
	}
	bodies := make(chan []byte, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		bodies <- body
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	windowsManagedLaunchAuditEndpoint = func() (string, string, bool, error) { return server.URL, "managed-token", true, nil }
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	profile := windowsHookImageSkippedProfile{SID: "S-1-5-21-1-2-3-1018", Account: `HOST\dcw-std2`, Home: `C:\Users\dcw-std2`,
		SkippedBy: windowsHookImageRetireActor(), SkippedAt: "2026-11-15T16:20:44Z",
		Files: []windowsHookImageNamedFile{{File: `C:\Users\dcw-std2\.copilot\hooks\defenseclaw-vscode.json`, Folder: "f2e64f2160900a55", Account: true}}}
	if err := postWindowsHookImageRetireSkip(profile); err != nil {
		t.Fatal(err)
	}
	var row struct {
		Activity struct {
			Actor string         `json:"actor"`
			After map[string]any `json:"after"`
		} `json:"activity"`
	}
	body := <-bodies
	if err := json.Unmarshal(body, &row); err != nil {
		t.Fatalf("body %s: %v", body, err)
	}
	actorRef := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*$`)
	if !actorRef.MatchString(row.Activity.Actor) || !strings.Contains(row.Activity.Actor, sid) {
		t.Errorf("activity actor %q is not an audit actor naming %s; the audit record drops it", row.Activity.Actor, sid)
	}
	if row.Activity.After["skipped_by"] != profile.SkippedBy {
		t.Errorf("after_state = %v, want skipped_by %q", row.Activity.After, profile.SkippedBy)
	}
}
