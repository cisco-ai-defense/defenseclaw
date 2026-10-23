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
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Per-account docker sandbox namespaces (GAP-0579). Every account's
// OpenShell gateway on a Linux host drives the host's one Docker engine, and
// a docker gateway's start force-removes the supervisors of its sandbox
// namespace, whoever made them (see ManagedDockerNamespace). A per-user
// gateway that names no sandbox_label shares OpenShell's default namespace
// with every other such gateway on the host: one account's gateway start
// ended the sandboxes another account ran. `defenseclaw sandbox setup` gives
// the account's gateway a namespace of its own, AccountDockerNamespace. The
// gateway lists only its namespace's sandboxes, so setup does it only while
// the account has no sandbox in the default one; until then the doctor says
// the account still shares it.

// accountDockerNamespacePrefix starts every per-account namespace; it is
// never ManagedDockerNamespace.
const accountDockerNamespacePrefix = "defenseclaw-u"

// AccountDockerNamespace is the docker sandbox namespace of the per-user
// gateway of the account uid.
func AccountDockerNamespace(uid int) string {
	return accountDockerNamespacePrefix + strconv.Itoa(uid)
}

// dockerNamespacePattern is a sandbox_label DefenseClaw writes: one plain
// path element (the driver names a state folder after it and hashes it into
// volume names).
var dockerNamespacePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,62}$`)

func validDockerNamespace(ns string) bool { return dockerNamespacePattern.MatchString(ns) }

// SharesDefaultDockerNamespace reports whether a gateway configuration keeps
// its docker sandboxes in OpenShell's default namespace.
func (s *GatewayConfigState) SharesDefaultDockerNamespace() bool {
	return s.DockerNamespace == "" || s.DockerNamespace == DefaultDockerNamespace
}

// UserStateHome is the state folder the account's gateway keeps its state
// in: $XDG_STATE_HOME, else ~/.local/state (DefaultStateHome).
func UserStateHome(getenv func(string) string, home string) string {
	if dir := strings.TrimSpace(getenv("XDG_STATE_HOME")); filepath.IsAbs(dir) {
		return dir
	}
	return DefaultStateHome(home)
}

// DefaultStateHome is ~/.local/state of home: the state folder of a gateway
// started with no XDG_STATE_HOME, as the exec shim of a managed computer
// starts every account's gateway (HOME, no XDG_STATE_HOME), whatever
// $XDG_STATE_HOME the account's other processes have.
func DefaultStateHome(home string) string {
	return filepath.Join(home, ".local", "state")
}

// DockerNamespaceInUse reports whether the account's gateway keeps a docker
// sandbox in namespace: OpenShell's docker driver (0.1.0 to 0.1.5) keeps a
// folder per sandbox of a namespace, from its create to its delete, in
// <state>/openshell/docker-sandbox-tokens/<namespace>. A folder that cannot
// be read counts as in use, so the namespace is kept.
func DockerNamespaceInUse(stateHome, namespace string) bool {
	entries, err := os.ReadDir(filepath.Join(stateHome, "openshell", "docker-sandbox-tokens", namespace))
	if errors.Is(err, fs.ErrNotExist) {
		return false
	}
	return err != nil || len(entries) > 0
}

// checkDockerNamespace names a Linux per-user docker gateway that still
// shares OpenShell's default sandbox namespace with every other account's
// gateway on the host. Its fix gives it the account's own namespace where
// the account has no sandbox in the default one; otherwise the account
// moves its sandboxes' work out first. Nothing is said on a managed host
// (the administrator's render names the managed namespace), for another
// driver, or where the gateway on the port is another account's.
func (r *doctorRun) checkDockerNamespace(ctx context.Context) {
	if r.GOOS != "linux" || r.Gateway == nil || r.Gateway.managedHost() || r.config == nil || r.portOther ||
		r.driver() != DriverDocker || !r.config.SharesDefaultDockerNamespace() {
		return
	}
	c := Check{ID: CheckIDDockerNamespace, Title: "Docker sandbox namespace", Status: StatusWarn,
		Detail: "your OpenShell gateway keeps its sandboxes in OpenShell's default Docker sandbox namespace, which the gateways of the other accounts " +
			"on this computer share: when one of them starts, it removes the supervisors of your running sandboxes, and they stop"}
	uid := r.Geteuid()
	if r.sandboxesInDefaultNamespace(ctx) {
		c.Fix = &Fix{Summary: "once no sandbox is left on your gateway (bring back their work with `defenseclaw sandbox pull NAME`, then " +
			"`defenseclaw sandbox delete NAME`), run `" + setupCommand + "`: it gives your gateway a namespace of its own"}
	} else {
		c.Fix = r.gatewayChangeFix("give your gateway a sandbox namespace of its own (sandbox_label = \""+AccountDockerNamespace(uid)+"\" in gateway.toml, with a backup)", "",
			r.applyGateway(GatewayChanges{DockerNamespace: AccountDockerNamespace(uid)}))
	}
	r.add(c)
}

// sandboxesInDefaultNamespace reports whether the account's gateway keeps a
// sandbox in the default namespace: one its gateway lists, or a sandbox
// folder of the docker driver's. Not knowing counts as yes.
func (r *doctorRun) sandboxesInDefaultNamespace(ctx context.Context) bool {
	if r.client != nil {
		lctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		list, err := r.client.ListSandboxes(lctx, nil)
		cancel()
		if err == nil && len(list) > 0 {
			return true
		}
	}
	home, err := r.HomeDir()
	if err != nil || home == "" {
		return true
	}
	return DockerNamespaceInUse(UserStateHome(r.Getenv, home), DefaultDockerNamespace)
}
