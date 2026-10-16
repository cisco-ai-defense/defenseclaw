// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package openshell

import (
	"regexp"
	"slices"
	"testing"

	toml "github.com/pelletier/go-toml/v2"
)

// dockerSweepContainer is a container as OpenShell's docker driver labels it.
type dockerSweepContainer struct {
	name, namespace, role string
}

// startupSweep is what OpenShell's docker driver (0.1.1 to 0.1.3,
// reconcile_runtime_resources_at_startup) force-removes when its gateway
// starts: every managed supervisor, staging and identity container whose
// openshell.ai/sandbox-namespace is the gateway's sandbox_label, whoever
// made it.
func startupSweep(namespace string, containers []dockerSweepContainer) []string {
	var removed []string
	for _, c := range containers {
		if c.namespace == namespace && slices.Contains([]string{"supervisor", "staging", "identity"}, c.role) {
			removed = append(removed, c.name)
		}
	}
	return removed
}

// renderedSandboxLabel is the [openshell.drivers.docker] sandbox_label of a
// rendered gateway.toml ("" when it has none, which OpenShell reads as
// DefaultDockerNamespace).
func renderedSandboxLabel(t *testing.T, r RenderedGateway) (string, bool) {
	t.Helper()
	data, err := r.TOML()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		OpenShell struct {
			Drivers struct {
				Docker *struct {
					SandboxLabel *string `toml:"sandbox_label"`
				} `toml:"docker"`
			} `toml:"drivers"`
		} `toml:"openshell"`
	}
	if err := toml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse %s: %v", data, err)
	}
	if doc.OpenShell.Drivers.Docker == nil {
		return "", false
	}
	if doc.OpenShell.Drivers.Docker.SandboxLabel == nil {
		return "", true
	}
	return *doc.OpenShell.Drivers.Docker.SandboxLabel, true
}

// A managed docker gateway's start must not remove what another account's
// gateway runs: the render gives the managed gateways a sandbox namespace of
// their own, so the gateways DefenseClaw does not render (a per-user gateway
// an account started before the host was managed, NVIDIA's own unit) keep
// OpenShell's default one to themselves (GAP-0566).
func TestRenderedDockerGatewayKeepsItsObjectsInTheManagedNamespace(t *testing.T) {
	label, docker := renderedSandboxLabel(t, RenderedGateway{BindAddress: "127.0.0.1:17671", ComputeDriver: DriverDocker})
	if !docker || label != ManagedDockerNamespace {
		t.Fatalf("docker render sandbox_label = %q (docker table %t), want %q", label, docker, ManagedDockerNamespace)
	}
	if ManagedDockerNamespace == DefaultDockerNamespace {
		t.Fatal("the managed namespace is OpenShell's default one")
	}
	// The label names a directory under the gateway's state
	// (docker-sandbox-tokens/<namespace>) and is hashed into volume names:
	// one plain path element.
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,62}$`).MatchString(ManagedDockerNamespace) {
		t.Fatalf("namespace %q is not a plain label", ManagedDockerNamespace)
	}

	// The supervisors of two sandboxes another account's own gateway runs
	// on 17670 (OpenShell's default namespace), and those of a managed
	// sandbox.
	host := []dockerSweepContainer{
		{"openshell-default--sbx-one-0001-supervisor", DefaultDockerNamespace, "supervisor"},
		{"openshell-default--sbx-two-0002-supervisor", DefaultDockerNamespace, "supervisor"},
		{"openshell-default--sbx-one-0001", DefaultDockerNamespace, "sandbox"},
		{"openshell-default--sbx-three-0003-supervisor", ManagedDockerNamespace, "supervisor"},
	}
	removed := startupSweep(label, host)
	for _, name := range removed {
		for _, c := range host {
			if c.name == name && c.namespace != ManagedDockerNamespace {
				t.Errorf("a managed gateway start removes %s of namespace %q", name, c.namespace)
			}
		}
	}
	if len(removed) != 1 {
		t.Errorf("a managed gateway start removes %v, want only the managed namespace's supervisor", removed)
	}
	// Before the fix the render named no namespace: the start swept the
	// other account's supervisors.
	if before := startupSweep(DefaultDockerNamespace, host); len(before) != 2 {
		t.Errorf("default-namespace sweep = %v", before)
	}

	// The MicroVM driver keeps its state per account and makes no Docker
	// objects: its render has no docker table.
	if _, docker := renderedSandboxLabel(t, RenderedGateway{BindAddress: "127.0.0.1:17670", ComputeDriver: DriverVM}); docker {
		t.Error("the vm render has a docker driver table")
	}
}
