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
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
)

type testDockerContainer struct {
	image   string
	running bool
	labels  map[string]string
}

// sandboxDockerRunner answers the purge's container and volume commands and
// hands image commands to the image fake. Like Docker it applies every label
// filter, lists a stopped container only with --all, and refuses to remove
// an image or a volume a container still uses.
type sandboxDockerRunner struct {
	*imageDockerRunner
	containers map[string]*testDockerContainer
	volumes    map[string]map[string]string
	objCalls   [][]string
	listErr    string
}

func (d *sandboxDockerRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	if filepath.Base(name) != "docker" || len(args) < 2 || (args[0] != "container" && args[0] != "volume") {
		if filepath.Base(name) == "docker" && len(args) == 3 && args[0] == "image" && args[1] == "rm" {
			for id, c := range d.containers {
				if c.image == args[2] {
					return CommandResult{Stderr: []byte("Error response from daemon: conflict: unable to delete " + args[2] + " (must be forced) - container " + id[:12] + " is using its referenced image"), ExitCode: 1}, errors.New("image in use")
				}
			}
		}
		return d.imageDockerRunner.Run(ctx, name, args...)
	}
	d.objCalls = append(d.objCalls, append([]string(nil), args...))
	kind := args[0]
	switch args[1] {
	case "ls":
		if d.listErr != "" {
			return CommandResult{Stderr: []byte(d.listErr), ExitCode: 1}, errors.New("Docker list failed")
		}
		filters, all, format := map[string]string{}, false, ""
		for i := 2; i < len(args); i++ {
			switch args[i] {
			case "--all":
				all = true
			case "--filter":
				key, value, _ := strings.Cut(strings.TrimPrefix(args[i+1], "label="), "=")
				filters[key] = value
				i++
			case "--format":
				format = args[i+1]
				i++
			}
		}
		matches := func(labels map[string]string) bool {
			for key, value := range filters {
				if labels[key] != value {
					return false
				}
			}
			return true
		}
		var out []string
		if kind == "container" {
			if format != "{{.ID}}" {
				return CommandResult{ExitCode: 1}, errors.New("wrong Docker container list command")
			}
			for id, c := range d.containers {
				if (all || c.running) && matches(c.labels) {
					out = append(out, id)
				}
			}
		} else {
			if format != "{{.Name}}" {
				return CommandResult{ExitCode: 1}, errors.New("wrong Docker volume list command")
			}
			for vol, labels := range d.volumes {
				if matches(labels) {
					out = append(out, vol)
				}
			}
		}
		sort.Strings(out)
		return CommandResult{Stdout: []byte(strings.Join(out, "\n") + "\n")}, nil
	case "inspect":
		ref := args[len(args)-1]
		var labels map[string]string
		if c := d.containers[ref]; kind == "container" && c != nil && containsSequence(args, "--format", "{{json .Config.Labels}}") {
			labels = c.labels
		} else if v, ok := d.volumes[ref]; kind == "volume" && ok && containsSequence(args, "--format", "{{json .Labels}}") {
			labels = v
		} else {
			return CommandResult{Stderr: []byte("No such object"), ExitCode: 1}, errors.New("missing object")
		}
		data, _ := json.Marshal(labels)
		return CommandResult{Stdout: data}, nil
	case "rm":
		ref := args[len(args)-1]
		if kind == "container" {
			if !reflect.DeepEqual(args, []string{"container", "rm", "--force", ref}) || d.containers[ref] == nil {
				return CommandResult{ExitCode: 1}, errors.New("unexpected container rm")
			}
			delete(d.containers, ref)
			return CommandResult{}, nil
		}
		labels, ok := d.volumes[ref]
		if len(args) != 3 || !ok {
			return CommandResult{ExitCode: 1}, errors.New("unexpected volume rm")
		}
		for id, c := range d.containers {
			if c.labels[openshellLabelSandboxID] == labels[openshellLabelSandboxID] && c.labels[openshellLabelNamespace] == labels[openshellLabelNamespace] {
				return CommandResult{Stderr: []byte("Error response from daemon: remove " + ref + ": volume is in use - [" + id + "]"), ExitCode: 1}, errors.New("volume in use")
			}
		}
		delete(d.volumes, ref)
		return CommandResult{}, nil
	}
	return CommandResult{ExitCode: 1}, errors.New("unexpected Docker command")
}

// sandbox adds what OpenShell's docker driver leaves of a stopped sandbox,
// labelled as on the rc.5 and rc.6 hosts (TST-6733, TST-6879): the workload
// container, which carries the labels of the DefenseClaw image it runs, its
// supervisor container, and its channel and supervisor volumes.
func (d *sandboxDockerRunner) sandbox(namespace, name, digit string, uid int, owner, tag string) {
	id := strings.Repeat(digit, 8) + "-08e1-4f75-9a9c-f94442e0230b"
	base := func(role string) map[string]string {
		return map[string]string{openshellLabelManagedBy: "openshell", openshellLabelNamespace: namespace, openshellLabelSandboxID: id, "openshell.ai/isolation-role": role}
	}
	workload := base("sandbox")
	workload[openshellLabelSandboxName] = name
	workload[image.LabelSandboxImage], workload[image.LabelOwner], workload[image.LabelUID] = "1", owner, strconv.Itoa(uid)
	d.containers[strings.Repeat(digit, 64)] = &testDockerContainer{image: tag, labels: workload}
	d.containers[strings.Repeat(digit, 63)+"0"] = &testDockerContainer{image: "ghcr.io/nvidia/openshell/supervisor:0.1.1", labels: base("supervisor")}
	for _, kind := range []string{"channel", "supervisor"} {
		labels := base("")
		delete(labels, "openshell.ai/isolation-role")
		d.volumes["openshell-"+kind+"-"+strings.Repeat(digit, 32)] = labels
	}
}

func (d *sandboxDockerRunner) left() (containers, volumes []string) {
	for id := range d.containers {
		containers = append(containers, id[:1]+":"+d.containers[id].labels["openshell.ai/isolation-role"])
	}
	for vol := range d.volumes {
		volumes = append(volumes, vol[:len(vol)-31])
	}
	sort.Strings(containers)
	sort.Strings(volumes)
	return containers, volumes
}

const (
	bridgedImageTag = "defenseclaw/sandbox:claudecode-aaaaaaaaaaaaaaaa-u1000"
	otherImageTag   = "defenseclaw/sandbox:claudecode-bbbbbbbbbbbbbbbb-u1001"
)

// bridgedDockerHost is a managed Linux docker host upgraded from 1.0.1 with
// the 1.0.1 upgrade bridge (DELTA-42). alice kept a stopped 1.0.1 sandbox in
// OpenShell's default namespace and made one since in the managed one;
// her gateway lists one namespace's, so her teardown deletes at most those
// (the fake teardown deletes none). Beside them: alice's per-user gateway's
// own namespace, another account's 1.0.1 sandbox, and a container no
// sandbox made.
func bridgedDockerHost(t *testing.T) (*osHost, *sandboxDockerRunner) {
	t.Helper()
	h := packagedDockerHost(t)
	requireOK(t, h.ensure(sandboxConfig(t, "linux", true, map[string]any{"install": "prerequisite", "driver": "docker", "gateway_port": 17671})))
	state := h.env.loadOpenShellState()
	state.Applied.DefaultNamespaceBridge = true
	if err := h.env.saveOpenShellState(state); err != nil {
		t.Fatal(err)
	}
	d := &sandboxDockerRunner{imageDockerRunner: &imageDockerRunner{other: h.env.Runner, images: map[string]*testDockerImage{}},
		containers: map[string]*testDockerContainer{}, volumes: map[string]map[string]string{}}
	h.env.Runner = d
	writeImageStore(t, h, h.alice, sampleImageOwner, bridgedImageTag, "", "")
	d.add(bridgedImageTag, sampleImageOwner, h.alice.UID, "a", false)
	d.add(otherImageTag, otherImageOwner, h.alice.UID+1, "b", false)
	d.sandbox(openshell.DefaultDockerNamespace, "fcs-eng-101", "1", h.alice.UID, sampleImageOwner, bridgedImageTag)
	d.sandbox(openshell.ManagedDockerNamespace, "eng-rc5", "2", h.alice.UID, sampleImageOwner, bridgedImageTag)
	d.sandbox(openshell.AccountDockerNamespace(h.alice.UID), "own-gateway", "3", h.alice.UID, sampleImageOwner, "defenseclaw/sandbox:own-u1000")
	d.sandbox(openshell.DefaultDockerNamespace, "fcs-ctr-101", "4", h.alice.UID+1, otherImageOwner, otherImageTag)
	d.containers[strings.Repeat("6", 64)] = &testDockerContainer{image: "grafana/grafana:11.3.0", running: true, labels: map[string]string{}}
	return h, d
}

// GAP-0026: a managed purge left the stopped 1.0.1 default-namespace
// containers of eng1 and ctr1, their images (in use by them) and their
// volumes (TST-6733 on rc.5, TST-6879). The purge removes, as root, every
// container and volume of the account's sandboxes in both namespaces of the
// managed gateways, then its images; another account's sandboxes, the
// account's per-user gateway's namespace and unlabelled containers stay.
func TestSandboxPurgeRemovesBridgedAccountSandboxesInBothNamespaces(t *testing.T) {
	h, d := bridgedDockerHost(t)
	r := h.run(Options{Action: ActionUninstall, Purge: true})
	requireOK(t, r)
	containers, volumes := d.left()
	if want := []string{"3:sandbox", "3:supervisor", "4:sandbox", "4:supervisor", "6:"}; !reflect.DeepEqual(containers, want) {
		t.Errorf("containers left = %v, want %v", containers, want)
	}
	if want := []string{"openshell-channel-3", "openshell-channel-4", "openshell-supervisor-3", "openshell-supervisor-4"}; !reflect.DeepEqual(volumes, want) {
		t.Errorf("volumes left = %v, want %v", volumes, want)
	}
	if d.images[bridgedImageTag] != nil || d.images[otherImageTag] == nil {
		t.Errorf("images left = %v, want only the other account's", d.images)
	}
	if !containsLine(r.Changes, "removed 4 Docker containers and 4 volumes of the DefenseClaw sandboxes of user alice (fcs-eng-101 in default, eng-rc5 in defenseclaw-managed)") ||
		!containsLine(r.Changes, "removed 1 DefenseClaw sandbox images of user alice") {
		t.Errorf("changes = %v", r.Changes)
	}
	if warnings := messagesOf(r.Warnings, codeSandboxUserState); warnings != "" {
		t.Errorf("warnings = %s", warnings)
	}
}

// A plain uninstall keeps every sandbox of the account in both namespaces,
// with its containers, volumes and images, and asks Docker nothing.
func TestSandboxUninstallKeepsBridgedAccountSandboxes(t *testing.T) {
	h, d := bridgedDockerHost(t)
	beforeContainers, beforeVolumes := d.left()
	requireOK(t, h.run(Options{Action: ActionUninstall}))
	containers, volumes := d.left()
	if len(d.objCalls) != 0 || len(d.calls) != 0 || !reflect.DeepEqual(containers, beforeContainers) || !reflect.DeepEqual(volumes, beforeVolumes) ||
		d.images[bridgedImageTag] == nil {
		t.Errorf("a plain uninstall changed Docker: calls %v %v, containers %v, volumes %v", d.objCalls, d.calls, containers, volumes)
	}
}

// A container of the account's sandbox whose labels name another account
// stays with the sandbox's volumes, and the purge says so; one Docker cannot
// list is reported with the root command, and the purge still finishes.
func TestSandboxPurgeKeepsWhatItCannotTieToTheAccount(t *testing.T) {
	t.Run("foreign label", func(t *testing.T) {
		h, d := bridgedDockerHost(t)
		forged := strings.Repeat("5", 64)
		labels := map[string]string{}
		for key, value := range d.containers[strings.Repeat("1", 64)].labels {
			labels[key] = value
		}
		labels[image.LabelUID] = strconv.Itoa(h.alice.UID + 1)
		d.containers[forged] = &testDockerContainer{image: "other/forged:latest", labels: labels}
		r := h.run(Options{Action: ActionUninstall, Purge: true})
		requireOK(t, r)
		containers, volumes := d.left()
		if want := []string{"3:sandbox", "3:supervisor", "4:sandbox", "4:supervisor", "5:sandbox", "6:"}; !reflect.DeepEqual(containers, want) {
			t.Errorf("containers left = %v, want %v", containers, want)
		}
		if want := []string{"openshell-channel-1", "openshell-channel-3", "openshell-channel-4", "openshell-supervisor-1", "openshell-supervisor-3", "openshell-supervisor-4"}; !reflect.DeepEqual(volumes, want) {
			t.Errorf("volumes left = %v, want %v", volumes, want)
		}
		if warning := messagesOf(r.Warnings, codeSandboxUserState); !strings.Contains(warning, "left Docker container 555555555555 of sandbox fcs-eng-101 (namespace default) of user alice: its labels name another sandbox, account or image owner") {
			t.Errorf("warnings = %s", warning)
		}
	})
	t.Run("Docker cannot list", func(t *testing.T) {
		h, d := bridgedDockerHost(t)
		d.listErr = "Cannot connect to the Docker daemon"
		store := filepath.Join(h.alice.Home, h.env.daemonStateRel(), "sandboxes", "images.json")
		r := h.run(Options{Action: ActionUninstall, Purge: true})
		requireOK(t, r)
		warning := messagesOf(r.Warnings, codeSandboxUserState)
		for _, ns := range []string{"default", "defenseclaw-managed"} {
			if !strings.Contains(warning, "could not list the Docker containers of the DefenseClaw sandboxes of user alice in namespace "+ns+": Cannot connect to the Docker daemon; as root run `"+sandboxContainerListCommand(h.alice, sampleImageOwner)+"`") {
				t.Errorf("namespace %s: warnings = %s", ns, warning)
			}
		}
		if h.exists(store) || len(d.containers) != 9 {
			t.Errorf("purge did not finish or removed a container: store %t, containers %d", h.exists(store), len(d.containers))
		}
	})
}
