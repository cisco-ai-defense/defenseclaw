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

package feed

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
	"github.com/defenseclaw/defenseclaw/internal/sensor/sandboxfeed"
)

// fakeInspector is docker with a few containers.
type fakeInspector struct {
	containers map[string]ContainerLabels
	inspects   map[string]int
	listings   int
	err        error
}

func (f *fakeInspector) Inspect(_ context.Context, id string) (ContainerLabels, error) {
	f.inspects[id]++
	if f.err != nil {
		return ContainerLabels{}, f.err
	}
	for full, c := range f.containers {
		if len(full) >= len(id) && full[:len(id)] == id {
			return c, nil
		}
	}
	return ContainerLabels{}, ErrNoSuchContainer
}

func (f *fakeInspector) Sandbox(_ context.Context, sandboxID string) ([]ContainerLabels, error) {
	f.listings++
	var out []ContainerLabels
	for _, c := range f.containers {
		if c.Labels[LabelSandboxID] == sandboxID {
			out = append(out, c)
		}
	}
	return out, nil
}

func sandboxLabels(id, role, uid string) map[string]string {
	labels := map[string]string{LabelManagedBy: "openshell", LabelSandboxID: id, LabelSandboxName: "box-" + id, LabelIsolationRole: role}
	if uid != "" {
		labels[LabelOwnerUID] = uid
	}
	return labels
}

func newFakeInspector() *fakeInspector {
	return &fakeInspector{inspects: map[string]int{}, containers: map[string]ContainerLabels{
		"e323c06c37041c0c6e72d9d8d0d87866eb7689e9010509de4ac2615626b197a2": {ID: "e323c06c37041c0c6e72d9d8d0d87866eb7689e9010509de4ac2615626b197a2",
			Labels: sandboxLabels("sb-1", sandboxfeed.RoleSandbox, "1000")},
		"23f7ebb0e93ee786a75d0c26267e46513a6d5def7817acab08dfdb4c1e94dcb1": {ID: "23f7ebb0e93ee786a75d0c26267e46513a6d5def7817acab08dfdb4c1e94dcb1",
			Labels: sandboxLabels("sb-1", sandboxfeed.RoleSupervisor, "")},
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef": {ID: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Labels: map[string]string{"com.example.app": "web"}},
		"1111111111111111111111111111111111111111111111111111111111111111": {ID: "1111111111111111111111111111111111111111111111111111111111111111",
			Labels: sandboxLabels("sb-root", sandboxfeed.RoleSandbox, "0")},
	}}
}

func TestContainersResolveSandboxContainers(t *testing.T) {
	inspector := newFakeInspector()
	now := time.Unix(1_800_000_000, 0)
	c := NewContainers(inspector, func() time.Time { return now })
	ctx := context.Background()

	got, ok := c.Resolve(ctx, "e323c06c37041c0c6e72d9d8d0d8786")
	if !ok || got.SandboxID != "sb-1" || got.SandboxName != "box-sb-1" || got.Role != sandboxfeed.RoleSandbox || got.Owner != 1000 {
		t.Fatalf("workload = %+v, %v", got, ok)
	}
	// The supervisor container carries no uid: it is the workload's.
	got, ok = c.Resolve(ctx, "23f7ebb0e93ee786a75d0c26267e465")
	if !ok || got.Role != sandboxfeed.RoleSupervisor || got.Owner != 1000 {
		t.Fatalf("supervisor = %+v, %v", got, ok)
	}
	if inspector.listings != 0 {
		t.Fatalf("the owner was listed although the workload already named it (%d)", inspector.listings)
	}
	for _, id := range []string{"0123456789abcdef0123456789abcde", "1111111111111111111111111111111", "ffffffffffffffffffffffffffffff0"} {
		if got, ok := c.Resolve(ctx, id); ok && got.Owner >= 0 {
			t.Fatalf("%s resolved to an owned sandbox: %+v", id, got)
		}
	}
	// A uid label of 0 names no owner: sandboxes never run as root.
	if got, _ := c.Resolve(ctx, "1111111111111111111111111111111"); got.Owner != -1 {
		t.Fatalf("root sandbox owner = %d", got.Owner)
	}
	// Answers are cached: every exec names its container.
	for range 10 {
		c.Resolve(ctx, "e323c06c37041c0c6e72d9d8d0d8786")
		c.Resolve(ctx, "0123456789abcdef0123456789abcde")
	}
	if inspector.inspects["e323c06c37041c0c6e72d9d8d0d8786"] != 1 || inspector.inspects["0123456789abcdef0123456789abcde"] != 1 {
		t.Fatalf("inspects = %v", inspector.inspects)
	}
	// Anything but a hex id is never sent to docker.
	if _, ok := c.Resolve(ctx, "../containers/x"); ok || len(inspector.inspects) != 5 {
		t.Fatalf("a malformed id was looked up: %v", inspector.inspects)
	}
}

// The supervisor seen first: its owner comes from listing the sandbox.
func TestContainersFindTheSupervisorsOwner(t *testing.T) {
	inspector := newFakeInspector()
	c := NewContainers(inspector, nil)
	got, ok := c.Resolve(context.Background(), "23f7ebb0e93ee786a75d0c26267e465")
	if !ok || got.Owner != 1000 || inspector.listings != 1 {
		t.Fatalf("supervisor first = %+v, %v (listings %d)", got, ok, inspector.listings)
	}
}

// A failure is asked again soon; a gone container later.
func TestContainersRetryAfterAFailure(t *testing.T) {
	inspector := newFakeInspector()
	inspector.err = errors.New("docker is restarting")
	now := time.Unix(1_800_000_000, 0)
	c := NewContainers(inspector, func() time.Time { return now })
	ctx := context.Background()
	if _, ok := c.Resolve(ctx, "e323c06c37041c0c6e72d9d8d0d8786"); ok {
		t.Fatal("resolved while docker failed")
	}
	inspector.err = nil
	if _, ok := c.Resolve(ctx, "e323c06c37041c0c6e72d9d8d0d8786"); ok {
		t.Fatal("the failure was not kept for a moment")
	}
	now = now.Add(keepFailure + time.Second)
	if _, ok := c.Resolve(ctx, "e323c06c37041c0c6e72d9d8d0d8786"); !ok {
		t.Fatal("not asked again after the failure")
	}
}

// The uid label the feed filters on is the one DefenseClaw's sandbox image
// carries.
func TestOwnerLabelIsTheImagesUIDLabel(t *testing.T) {
	if LabelOwnerUID != image.LabelUID {
		t.Fatalf("LabelOwnerUID = %q, image.LabelUID = %q", LabelOwnerUID, image.LabelUID)
	}
}
