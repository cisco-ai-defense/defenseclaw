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

//go:build !windows

package sandboxauth

import (
	"errors"
	"slices"
	"testing"
	"time"
)

func mountSpec(name, connector string) Spec {
	return Spec{
		SandboxName:    name,
		Connector:      connector,
		AgentVersion:   "2.1.156",
		HookContractID: "claudecode-hooks-v1",
		Workdir: Workdir{
			Mode:   WorkdirMount,
			Mounts: []Mount{{SandboxPath: "/work/app", HostPath: "/home/dev/code/app"}},
			Masks:  []string{"/work/app/.env"},
		},
		HostUser: HostUser{UID: "1000", Name: "dev"},
	}
}

func TestSpecNormalizeCanonicalises(t *testing.T) {
	spec := mountSpec("dc-claude-app-7f3a", " Claude-Code ")
	spec.Routes = []Route{RouteOTLP, RouteHook, RouteHook}
	spec.PolicyProfile = "Open"
	spec.Workdir.Masks = []string{"/work/app/.env", "/work/app/.env"}
	spec.TTL = 90*time.Second + 400*time.Millisecond
	got, err := spec.normalize()
	if err != nil || got.Connector != "claudecode" || !slices.Equal(got.Routes, []Route{RouteHook, RouteOTLP}) ||
		got.PolicyProfile != "open" || !slices.Equal(got.Workdir.Masks, []string{"/work/app/.env"}) || got.TTL != 90*time.Second {
		t.Fatalf("normalize = %+v, %v", got, err)
	}
	for connector, want := range map[string][]Route{
		"claudecode": {RouteHook, RouteOTLP},
		"codex":      {RouteHook, RouteNotify, RouteOTLP},
		"cursor":     {RouteHook, RouteOTLP},
	} {
		if got, err := mountSpec("dc-"+connector, connector).normalize(); err != nil || !slices.Equal(got.Routes, want) {
			t.Errorf("%s default routes = %v, %v; want %v", connector, got.Routes, err, want)
		}
	}
	// Copy mode may record the context mounts, or none.
	spec = mountSpec("dc-app", "codex")
	spec.Workdir.Mode = WorkdirCopy
	if _, err := spec.normalize(); err != nil {
		t.Fatalf("copy mode with context mounts: %v", err)
	}
	spec.Workdir.Mounts = nil
	if _, err := spec.normalize(); err != nil {
		t.Fatalf("copy mode without mounts: %v", err)
	}
}

func TestSpecNormalizeRejects(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Spec)
	}{
		{"empty connector", func(s *Spec) { s.Connector = "" }},
		{"connector with path", func(s *Spec) { s.Connector = "../codex" }},
		{"empty sandbox name", func(s *Spec) { s.SandboxName = "" }},
		{"sandbox name with slash", func(s *Spec) { s.SandboxName = "a/b" }},
		{"sandbox name leading dash", func(s *Spec) { s.SandboxName = "-x" }},
		{"sandbox id with space", func(s *Spec) { s.SandboxID = "a b" }},
		{"agent version control char", func(s *Spec) { s.AgentVersion = "1.0\x1b[31m" }},
		{"contract id with space", func(s *Spec) { s.HookContractID = "codex hooks" }},
		{"unknown profile", func(s *Spec) { s.PolicyProfile = "yolo" }},
		{"unknown route", func(s *Spec) { s.Routes = []Route{"admin"} }},
		{"unknown workdir mode", func(s *Spec) { s.Workdir.Mode = "rsync" }},
		{"mount mode without mounts", func(s *Spec) { s.Workdir.Mounts = nil }},
		{"relative sandbox path", func(s *Spec) { s.Workdir.Mounts[0].SandboxPath = "work/app" }},
		{"unclean sandbox path", func(s *Spec) { s.Workdir.Mounts[0].SandboxPath = "/work/../app" }},
		{"root sandbox path", func(s *Spec) { s.Workdir.Mounts[0].SandboxPath = "/" }},
		{"relative host path", func(s *Spec) { s.Workdir.Mounts[0].HostPath = "code/app" }},
		{"host filesystem root", func(s *Spec) { s.Workdir.Mounts[0].HostPath = "/" }},
		{"unclean host path", func(s *Spec) { s.Workdir.Mounts[0].HostPath = "/home/dev//app" }},
		{"duplicate mount", func(s *Spec) {
			s.Workdir.Mounts = append(s.Workdir.Mounts, Mount{SandboxPath: "/work/app", HostPath: "/tmp/x"})
		}},
		{"relative mask", func(s *Spec) { s.Workdir.Masks = []string{".env"} }},
		{"non-numeric uid", func(s *Spec) { s.HostUser.UID = "dev" }},
		{"user name with shell chars", func(s *Spec) { s.HostUser.Name = "dev;rm" }},
		{"negative rps", func(s *Spec) { s.RateLimit.RequestsPerSecond = -1 }},
		{"huge burst", func(s *Spec) { s.RateLimit.Burst = maxBurst + 1 }},
		{"negative ttl", func(s *Spec) { s.TTL = -time.Second }},
		{"sub-second ttl", func(s *Spec) { s.TTL = time.Millisecond }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := mountSpec("dc-app", "claudecode")
			tc.mutate(&spec)
			if _, err := spec.normalize(); !errors.Is(err, ErrInvalidSpec) {
				t.Fatalf("normalize error = %v, want ErrInvalidSpec", err)
			}
		})
	}
}

func TestBindingAuthorize(t *testing.T) {
	b := Binding{Connector: "claudecode", Routes: []Route{RouteHook, RouteOTLP}}
	for _, tc := range []struct {
		route     Route
		connector string
		want      error
	}{
		{RouteHook, "claudecode", nil},
		{RouteHook, "claude-code", nil},
		{RouteOTLP, "CLAUDECODE", nil},
		{RouteHook, "codex", ErrConnectorMismatch},
		{RouteOTLP, "", ErrConnectorMismatch},
		{RouteNotify, "claudecode", ErrRouteNotAllowed},
		{RouteInspect, "claudecode", ErrRouteNotAllowed},
	} {
		if err := b.Authorize(tc.route, tc.connector); !errors.Is(err, tc.want) {
			t.Errorf("Authorize(%s, %q) = %v, want %v", tc.route, tc.connector, err, tc.want)
		}
	}
}

func TestBindingExpired(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	b := Binding{ExpiresAt: now}
	if (Binding{}).Expired(now) || !b.Expired(now) || b.Expired(now.Add(-time.Nanosecond)) {
		t.Fatal("a zero expiry never expires; a binding expires at its expiry instant, not before")
	}
}

func TestBindingSpecRoundTrip(t *testing.T) {
	spec, err := mountSpec("dc-app", "codex").normalize()
	if err != nil {
		t.Fatal(err)
	}
	spec.TTL = time.Hour
	b := bindingFromSpec("sb_00000000000000000000000000000000", spec)
	back := b.Spec()
	back.Workdir.Mounts[0].HostPath = "/elsewhere"
	if b.Workdir.Mounts[0].HostPath == "/elsewhere" {
		t.Fatal("Spec must not alias the binding's mounts")
	}
	if back.TTL != time.Hour {
		t.Fatalf("ttl = %v", back.TTL)
	}
}

func TestCanonicalConnector(t *testing.T) {
	for in, want := range map[string]string{
		"claude": "claudecode", "Claude_Code": "claudecode", "claude-code": "claudecode",
		" codex ": "codex", "cursor": "cursor",
	} {
		if got := CanonicalConnector(in); got != want {
			t.Errorf("CanonicalConnector(%q) = %q, want %q", in, got, want)
		}
	}
}
