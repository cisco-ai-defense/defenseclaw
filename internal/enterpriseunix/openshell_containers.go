// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
)

// Labels OpenShell's docker driver puts on every container and volume of a
// sandbox (the sandbox feed reads the same ones). The workload container
// also carries the labels of the DefenseClaw image it runs: the account's
// uid and the owner of the image store that built it (image.LabelUID,
// image.LabelOwner).
const (
	openshellLabelManagedBy   = "openshell.ai/managed-by"
	openshellLabelSandboxID   = "openshell.ai/sandbox-id"
	openshellLabelSandboxName = "openshell.ai/sandbox-name"
	openshellLabelNamespace   = "openshell.ai/sandbox-namespace"
	openshellManagedBy        = "openshell"
)

var (
	sandboxContainerIDRE = lazyregexp.New(`^[0-9a-f]{64}$`)
	openshellSandboxIDRE = lazyregexp.New(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	sandboxVolumeNameRE  = lazyregexp.New(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$`)
)

// purgeDockerNamespaces are the sandbox namespaces the managed gateways keep
// an account's docker sandboxes in: OpenShell's default one, where 1.0.1 and
// the 1.0.1 upgrade bridge keep them, and the managed one. An account that
// moved between them can have sandboxes in both, and its gateway lists only
// one namespace's, so the account-run teardown cannot delete the others
// (GAP-0026). A per-user gateway's own namespace (AccountDockerNamespace)
// is not the deployment's and stays.
var purgeDockerNamespaces = []string{openshell.DefaultDockerNamespace, openshell.ManagedDockerNamespace}

type openshellDockerSandbox struct{ namespace, id, name string }

func sandboxContainerListCommand(a SandboxAccount, owner string) string {
	return "docker container ls --all --filter label=" + openshellLabelManagedBy + "=" + openshellManagedBy +
		" --filter label=" + image.LabelOwner + "=" + owner + " --filter label=" + image.LabelUID + "=" + strconv.Itoa(a.UID)
}

// listSandboxDocker lists the containers (kind "container") or volumes
// (kind "volume") OpenShell made in namespace that carry every label in
// labels ("key=value").
func (e *Env) listSandboxDocker(ctx context.Context, docker, kind, namespace string, labels ...string) ([]string, CommandResult, error) {
	args := []string{kind, "ls"}
	format, row := "{{.Name}}", sandboxVolumeNameRE
	if kind == "container" {
		args = append(args, "--all", "--no-trunc")
		format, row = "{{.ID}}", sandboxContainerIDRE
	}
	for _, label := range append([]string{openshellLabelManagedBy + "=" + openshellManagedBy, openshellLabelNamespace + "=" + namespace}, labels...) {
		args = append(args, "--filter", "label="+label)
	}
	out, err := e.runSandboxDocker(ctx, docker, append(args, "--format", format)...)
	if err != nil {
		return nil, out, err
	}
	var refs []string
	for _, line := range strings.Split(strings.TrimSpace(string(out.Stdout)), "\n") {
		if line == "" {
			continue
		}
		if !row.MatchString(line) {
			return nil, out, errors.New("Docker listed a " + kind + " row that is not a " + kind + " name")
		}
		refs = append(refs, line)
	}
	return refs, out, nil
}

// sandboxDockerLabels reads the labels of one container or volume.
func (e *Env) sandboxDockerLabels(ctx context.Context, docker, kind, ref string) (map[string]string, error) {
	format := "{{json .Labels}}"
	if kind == "container" {
		format = "{{json .Config.Labels}}"
	}
	out, err := e.runSandboxDocker(ctx, docker, kind, "inspect", "--format", format, ref)
	if err != nil {
		return nil, errors.New(sandboxDockerReason(out, err))
	}
	var labels map[string]string
	if err := json.Unmarshal(out.Stdout, &labels); err != nil {
		return nil, errors.New("docker inspect did not report its labels")
	}
	return labels, nil
}

// purgeSandboxOwnerContainers removes, as root, the Docker containers and
// volumes of the account's sandboxes in purgeDockerNamespaces, whichever
// namespace the account's gateway lists, before the images, which a
// container using one keeps. A sandbox is the account's by its workload
// container: OpenShell's namespace and sandbox id labels, and the image
// labels of a DefenseClaw sandbox image with this account's uid and the
// owner of its own image store. The other containers of that sandbox (its
// supervisor) and its volumes go by OpenShell's labels; one that names
// another account or image owner stays. Nothing else is touched, and every
// failure is a warning: the purge still finishes.
func (l *lifecycle) purgeSandboxOwnerContainers(ctx context.Context, a SandboxAccount, owner string) {
	e, r := l.env, l.result
	docker := e.firstExisting(e.binCandidates("docker"))
	if docker == "" {
		return // purgeSandboxOwnerImages reports the missing Docker CLI
	}
	uid := strconv.Itoa(a.UID)
	listCommand := sandboxContainerListCommand(a, owner)
	var sandboxes []openshellDockerSandbox
	seen := map[openshellDockerSandbox]bool{}
	for _, ns := range purgeDockerNamespaces {
		ids, out, err := e.listSandboxDocker(ctx, docker, "container", ns, image.LabelSandboxImage+"=1", image.LabelOwner+"="+owner, image.LabelUID+"="+uid)
		if err != nil {
			r.AddWarning(codeSandboxUserState, fmt.Sprintf("could not list the Docker containers of the DefenseClaw sandboxes of user %s in namespace %s: %s; as root run `%s`, "+
				"then remove each listed container with `docker container rm --force <id>` and the volumes of its sandbox with `docker volume rm`", a.Name, ns, sandboxDockerReason(out, err), listCommand))
			continue
		}
		for _, id := range ids {
			labels, err := e.sandboxDockerLabels(ctx, docker, "container", id)
			if err == nil && (labels[openshellLabelManagedBy] != openshellManagedBy || labels[openshellLabelNamespace] != ns || labels[image.LabelSandboxImage] != "1" ||
				labels[image.LabelOwner] != owner || labels[image.LabelUID] != uid || !openshellSandboxIDRE.MatchString(labels[openshellLabelSandboxID])) {
				err = errors.New("its OpenShell namespace, sandbox id, image owner or account uid label did not match")
			}
			if err != nil {
				r.AddWarning(codeSandboxUserState, fmt.Sprintf("left candidate sandbox container %s of user %s: %v; check `%s` before removing it", id[:12], a.Name, err, listCommand))
				continue
			}
			sb := openshellDockerSandbox{namespace: ns, id: labels[openshellLabelSandboxID], name: labels[openshellLabelSandboxName]}
			if !openshellSandboxIDRE.MatchString(sb.name) {
				sb.name = sb.id
			}
			if !seen[sb] {
				seen[sb] = true
				sandboxes = append(sandboxes, sb)
			}
		}
	}
	var containers, volumes int
	var names []string
	for _, sb := range sandboxes {
		of := fmt.Sprintf("sandbox %s (namespace %s) of user %s", sb.name, sb.namespace, a.Name)
		ids, out, err := e.listSandboxDocker(ctx, docker, "container", sb.namespace, openshellLabelSandboxID+"="+sb.id)
		if err != nil {
			r.AddWarning(codeSandboxUserState, fmt.Sprintf("could not list the Docker containers of %s: %s; as root run `%s`", of, sandboxDockerReason(out, err), listCommand))
			continue
		}
		all := true
		for _, id := range ids {
			labels, err := e.sandboxDockerLabels(ctx, docker, "container", id)
			if err == nil && (labels[openshellLabelManagedBy] != openshellManagedBy || labels[openshellLabelNamespace] != sb.namespace || labels[openshellLabelSandboxID] != sb.id ||
				(labels[image.LabelUID] != "" && labels[image.LabelUID] != uid) || (labels[image.LabelOwner] != "" && labels[image.LabelOwner] != owner)) {
				err = errors.New("its labels name another sandbox, account or image owner")
			}
			if err == nil {
				out, rmErr := e.runSandboxDocker(ctx, docker, "container", "rm", "--force", id)
				if rmErr != nil {
					err = errors.New(sandboxDockerReason(out, rmErr))
				}
			}
			if err != nil {
				all = false
				r.AddWarning(codeSandboxUserState, fmt.Sprintf("left Docker container %s of %s: %v; as root check `docker container inspect %s`, then run `docker container rm --force %s`", id[:12], of, err, id[:12], id[:12]))
				continue
			}
			containers++
		}
		if !all {
			continue // its volumes are still in use
		}
		vols, out, err := e.listSandboxDocker(ctx, docker, "volume", sb.namespace, openshellLabelSandboxID+"="+sb.id)
		if err != nil {
			r.AddWarning(codeSandboxUserState, fmt.Sprintf("could not list the Docker volumes of %s: %s; as root run `docker volume ls --filter label=%s=%s`, then `docker volume rm` each", of, sandboxDockerReason(out, err), openshellLabelSandboxID, sb.id))
			continue
		}
		for _, vol := range vols {
			labels, err := e.sandboxDockerLabels(ctx, docker, "volume", vol)
			if err == nil && (labels[openshellLabelManagedBy] != openshellManagedBy || labels[openshellLabelNamespace] != sb.namespace || labels[openshellLabelSandboxID] != sb.id) {
				err = errors.New("its labels name another sandbox")
			}
			if err == nil {
				out, rmErr := e.runSandboxDocker(ctx, docker, "volume", "rm", vol)
				if rmErr != nil {
					err = errors.New(sandboxDockerReason(out, rmErr))
				}
			}
			if err != nil {
				r.AddWarning(codeSandboxUserState, fmt.Sprintf("left Docker volume %s of %s: %v; as root run `docker volume rm %s`", vol, of, err, vol))
				continue
			}
			volumes++
		}
		names = append(names, sb.name+" in "+sb.namespace)
	}
	if containers+volumes > 0 {
		shown := names
		if len(shown) > imageNameLimit {
			shown = shown[:imageNameLimit]
		}
		line := fmt.Sprintf("removed %d Docker containers and %d volumes of the DefenseClaw sandboxes of user %s (%s", containers, volumes, a.Name, strings.Join(shown, ", "))
		if len(names) > len(shown) {
			line += fmt.Sprintf(", and %d more", len(names)-len(shown))
		}
		r.Changes = append(r.Changes, line+")")
	}
}
