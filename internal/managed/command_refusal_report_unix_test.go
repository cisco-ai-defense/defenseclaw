//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestReportCommandRefusalSendsTheCSRFHeaderAndFixedFields(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "dcm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "hook.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	type record struct {
		Action  string `json:"action"`
		Target  string `json:"target"`
		Details string `json:"details"`
		Reason  string `json:"reason"`
	}
	var got record
	var client, contentType string
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != CommandRefusalPath || r.Method != http.MethodPost {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		client, contentType = r.Header.Get("X-DefenseClaw-Client"), r.Header.Get("Content-Type")
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusNoContent)
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	status, err := ReportCommandRefusal(t.Context(), path, "enterprise linux ensure", "not_root")
	if err != nil || status != http.StatusNoContent {
		t.Fatalf("report: status %d err %v", status, err)
	}
	if client != CommandRefusalClient || contentType != "application/json" {
		t.Fatalf("headers: client %q content-type %q", client, contentType)
	}
	if got != (record{Action: "action", Target: "enterprise linux ensure", Details: "command=enterprise linux ensure", Reason: "not_root"}) {
		t.Fatalf("payload = %+v", got)
	}
	if _, err := ReportCommandRefusal(t.Context(), filepath.Join(dir, "absent.sock"), "uninstall", ""); err == nil {
		t.Fatal("a report to a missing socket did not return an error")
	}
}
