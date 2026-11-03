// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package contracttest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// errorRecorder is a testing.TB that records Errorf instead of failing.
type errorRecorder struct {
	testing.TB
	errors []string
}

func (r *errorRecorder) Helper() {}

func (r *errorRecorder) Errorf(format string, args ...any) {
	r.errors = append(r.errors, fmt.Sprintf(format, args...))
}

func decodeJSON(t *testing.T, data []byte) any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("%v\n%s", err, data)
	}
	return value
}

func canonical(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// A member of a real document that the forward schema neither lists nor
// keeps on the device on purpose fails CheckForward (sidecar-r107 GAP-0006:
// the guide said to forward what the forward schema dropped).
func TestCheckForwardFailsForAnUnlistedMember(t *testing.T) {
	s := Compile(t)
	document := decodeJSON(t, []byte(`{"schema_version":1,"command":"status","ok":true,
		"sessions_restart_required":{"state":"known","count":1,"entries":[{"pid":7,"user":"alice","agent":"codex","started_at":"2026-11-01T00:00:00Z"}]},
		"enforcement_pending":{"count":1,"connectors":["codex"]},"added_in_a_later_release":3}`))
	r := &errorRecorder{TB: t}
	projected := s.CheckForward(r, "bundle-status.schema.json", document)
	if len(r.errors) != 1 || !strings.Contains(r.errors[0], ".added_in_a_later_release") {
		t.Fatalf("CheckForward errors %q, want one for .added_in_a_later_release", r.errors)
	}
	if got := canonical(t, projected["enforcement_pending"]); got != `{"connectors":["codex"],"count":1}` {
		t.Errorf("enforcement_pending projects to %s", got)
	}
	if got := canonical(t, projected["sessions_restart_required"]); got != `{"count":1,"state":"known"}` {
		t.Errorf("sessions_restart_required projects to %s", got)
	}
}

// The Go projection CheckForward makes is forward/project.py's, on the
// fixtures and the contract schema examples. Runs where python3 is on PATH.
func TestForwardProjectionMatchesProjectPy(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not on PATH")
	}
	s := Compile(t)
	fixtures, err := filepath.Glob(filepath.Join(filepath.FromSlash(ForwardDir), "fixtures", "*.json"))
	if err != nil || len(fixtures) == 0 {
		t.Fatalf("fixtures %v (%v)", fixtures, err)
	}
	type sample struct {
		label   string
		forward string
		data    []byte
	}
	var samples []sample
	for _, path := range fixtures {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		prefix, _, _ := strings.Cut(filepath.Base(path), ".")
		samples = append(samples, sample{filepath.Base(path), prefix + "-forward.schema.json", data})
	}
	for source, forward := range forwardOf {
		data, err := os.ReadFile(filepath.Join(filepath.FromSlash(Dir), source))
		if err != nil {
			t.Fatal(err)
		}
		var schema struct {
			Examples []json.RawMessage `json:"examples"`
		}
		if err := json.Unmarshal(data, &schema); err != nil {
			t.Fatal(err)
		}
		for i, example := range schema.Examples {
			samples = append(samples, sample{fmt.Sprintf("%s example %d", source, i), forward, example})
		}
	}
	for _, sample := range samples {
		goProjection, _ := s.Project(t, sample.forward, decodeJSON(t, sample.data))
		cmd := exec.Command(python, "-I", filepath.Join(filepath.FromSlash(ForwardDir), "project.py"),
			filepath.Join(filepath.FromSlash(ForwardDir), sample.forward))
		cmd.Stdin = bytes.NewReader(sample.data)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%s: project.py: %v", sample.label, err)
		}
		if want, got := canonical(t, decodeJSON(t, out)), canonical(t, goProjection); want != got {
			t.Errorf("%s through %s:\nproject.py %s\nGo         %s", sample.label, sample.forward, want, got)
		}
	}
}

// management-agent.md, What to forward, names every member CheckForward
// lets a forward schema drop, so the guide and the schemas say the same.
func TestGuideNamesEveryMemberKeptOnTheDevice(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(filepath.FromSlash(Dir), "management-agent.md"))
	if err != nil {
		t.Fatal(err)
	}
	// A Windows checkout converts the guide to CRLF line endings.
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	_, section, found := strings.Cut(text, "### What to forward\n")
	if !found {
		t.Fatal("management-agent.md has no What to forward section")
	}
	section, _, _ = strings.Cut(section, "\n## ")
	section = strings.Join(strings.Fields(section), " ")
	for _, member := range KeepOnDevice {
		named, ok := forwardKeepGuideMembers[member]
		if !ok {
			named = "`" + member + "`"
		}
		if !strings.Contains(section, named) {
			t.Errorf("What to forward does not name %s, a member the forward schemas keep on the device", named)
		}
	}
}
