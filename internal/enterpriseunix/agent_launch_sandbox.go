// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
)

// cgroupDockerContainerRE finds a Docker container in a cgroup path, as the
// host reads /proc/<pid>/cgroup: docker-<id>.scope (the systemd cgroup
// driver) or docker/<id> (cgroupfs).
var cgroupDockerContainerRE = lazyregexp.New(`(?:^|/)docker[-/]([0-9a-f]{64})(?:\.scope)?(?:/|$)`)

// sandboxLaunchInspectTimeout bounds the Docker label read of one container
// during status and verify.
const sandboxLaunchInspectTimeout = 10 * time.Second

// linuxCgroupContainer is the Docker container of a process from its
// /proc/<pid>/cgroup lines ("hierarchy:controllers:path"), or "" when it
// runs in none, or the lines name more than one.
func linuxCgroupContainer(raw []byte) string {
	id := ""
	for _, line := range strings.Split(string(raw), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), ":", 3)
		if len(parts) != 3 {
			continue
		}
		match := cgroupDockerContainerRE.FindStringSubmatch(parts[2])
		if match == nil {
			continue
		}
		if id != "" && id != match[1] {
			return ""
		}
		id = match[1]
	}
	return id
}

// registeredSandboxLaunch reports an agent process that runs inside a
// DefenseClaw sandbox the managed gateway registered for the same account
// (GAP-0194): a Docker container with OpenShell's labels and the labels of
// the account's DefenseClaw sandbox image, whose sandbox id names a live
// registration of that uid in the gateway's registration store. Such a
// session runs under the sandbox policy and the hooks of the sandbox image,
// not under the host's managed hook files, so the host's launch check does
// not apply to it. The process name and arguments decide nothing here: a
// process outside a container, in another container, or in a sandbox whose
// registration is not live is checked as usual. The answer per container
// and uid is kept in seen for one scan.
func (e *Env) registeredSandboxLaunch(ctx context.Context, session agentSession, seen map[string]bool) bool {
	if e.GOOS != "linux" || session.ContainerID == "" || session.UID <= 0 {
		return false
	}
	key := session.ContainerID + "|" + strconv.Itoa(session.UID)
	if known, ok := seen[key]; ok {
		return known
	}
	registered := e.sandboxContainerRegistered(ctx, session.ContainerID, session.UID)
	if seen != nil {
		seen[key] = registered
	}
	return registered
}

func (e *Env) sandboxContainerRegistered(ctx context.Context, containerID string, uid int) bool {
	if !sandboxContainerIDRE.MatchString(containerID) {
		return false
	}
	docker := e.firstExisting(e.binCandidates("docker"))
	if docker == "" {
		return false
	}
	inspectCtx, cancel := context.WithTimeout(ctx, sandboxLaunchInspectTimeout)
	defer cancel()
	labels, err := e.sandboxDockerLabels(inspectCtx, docker, "container", containerID)
	sandboxID := labels[openshellLabelSandboxID]
	if err != nil || labels[openshellLabelManagedBy] != openshellManagedBy || labels[image.LabelSandboxImage] != "1" ||
		labels[image.LabelUID] != strconv.Itoa(uid) || !openshellSandboxIDRE.MatchString(sandboxID) {
		return false
	}
	registrations, err := sandboxreg.NewFileStore(e.P(sandboxreg.RegistrationsDir(e.Layout.DataDir))).List(uid)
	if err != nil {
		return false
	}
	now := time.Now()
	if e.Now != nil {
		now = e.Now()
	}
	for _, registration := range registrations {
		if registration.UID == uid && registration.SandboxID == sandboxID &&
			sandboxreg.EffectiveState(registration, now) == sandboxreg.StateLive {
			return true
		}
	}
	return false
}
