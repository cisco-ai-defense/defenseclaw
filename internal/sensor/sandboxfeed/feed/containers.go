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
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/defenseclaw/defenseclaw/internal/sensor/sandboxfeed"
)

// Container labels the feed reads. OpenShell's docker driver labels both of
// a sandbox's containers; DefenseClaw's sandbox image carries the uid it was
// built for (image.LabelUID), which docker copies onto the workload
// container. The test pins LabelOwnerUID to the image package's constant.
const (
	LabelManagedBy     = "openshell.ai/managed-by"
	LabelSandboxID     = "openshell.ai/sandbox-id"
	LabelSandboxName   = "openshell.ai/sandbox-name"
	LabelIsolationRole = "openshell.ai/isolation-role"
	LabelOwnerUID      = "io.defenseclaw.uid"

	managedByOpenShell = "openshell"
)

// Container is the OpenShell sandbox container a process runs in.
type Container struct {
	ID          string
	SandboxID   string
	SandboxName string
	// Role is sandboxfeed.RoleSandbox (the workload) or RoleSupervisor.
	Role string
	// Owner is the sandbox's io.defenseclaw.uid (the supervisor container
	// takes it from its workload container), -1 when none says.
	Owner int
}

// ContainerLabels is one container as the Docker Engine reports it.
type ContainerLabels struct {
	ID     string
	Labels map[string]string
}

// Inspector reads containers' labels (DockerInspector).
type Inspector interface {
	// Inspect reads one container by id or unique id prefix;
	// ErrNoSuchContainer when docker has none.
	Inspect(ctx context.Context, id string) (ContainerLabels, error)
	// Sandbox lists the containers of one OpenShell sandbox.
	Sandbox(ctx context.Context, sandboxID string) ([]ContainerLabels, error)
}

// ErrNoSuchContainer is a container docker does not know (any more).
var ErrNoSuchContainer = errors.New("sandbox feed: no such container")

// How long an answer is kept. A sandbox container's labels never change, so
// a known one is kept while it is in use; other containers and failures are
// asked again after a while.
const (
	keepKnown    = 10 * time.Minute
	keepOther    = 10 * time.Minute
	keepGone     = 5 * time.Minute
	keepFailure  = 30 * time.Second
	inspectLimit = 2 * time.Second
	maxCached    = 4096
)

var (
	containerIDPattern = regexp.MustCompile(`^[0-9a-f]{12,64}$`)
	sandboxIDPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

// Containers resolves Tetragon's container ids through an Inspector, with a
// cache, because every exec names its container.
type Containers struct {
	inspector Inspector
	now       func() time.Time

	mu     sync.Mutex
	byID   map[string]cachedContainer
	owners map[string]cachedOwner
}

type cachedContainer struct {
	container Container
	known     bool
	until     time.Time
}

type cachedOwner struct {
	uid   int
	until time.Time
}

// NewContainers returns a resolver.
func NewContainers(inspector Inspector, now func() time.Time) *Containers {
	if now == nil {
		now = time.Now
	}
	return &Containers{inspector: inspector, now: now, byID: map[string]cachedContainer{}, owners: map[string]cachedOwner{}}
}

// Resolve names the sandbox container id belongs to, false for any other
// container (or none docker could answer for).
func (c *Containers) Resolve(ctx context.Context, id string) (Container, bool) {
	if !containerIDPattern.MatchString(id) {
		return Container{}, false
	}
	now := c.now()
	c.mu.Lock()
	if hit, ok := c.byID[id]; ok && now.Before(hit.until) {
		if hit.known {
			hit.until = now.Add(keepKnown)
			c.byID[id] = hit
		}
		c.mu.Unlock()
		return hit.container, hit.known
	}
	c.mu.Unlock()

	inspectCtx, cancel := context.WithTimeout(ctx, inspectLimit)
	defer cancel()
	labels, err := c.inspector.Inspect(inspectCtx, id)
	entry := cachedContainer{until: now.Add(keepFailure)}
	switch {
	case errors.Is(err, ErrNoSuchContainer):
		entry.until = now.Add(keepGone)
	case err != nil:
	default:
		entry.container, entry.known = containerOf(labels)
		entry.until = now.Add(keepOther)
		if entry.known {
			entry.until = now.Add(keepKnown)
			entry.container.Owner = c.owner(inspectCtx, entry.container, now)
		}
	}
	c.mu.Lock()
	c.prune(now)
	c.byID[id] = entry
	c.mu.Unlock()
	return entry.container, entry.known
}

// containerOf reads an OpenShell sandbox container's labels.
func containerOf(labels ContainerLabels) (Container, bool) {
	l := labels.Labels
	if l[LabelManagedBy] != managedByOpenShell || !sandboxIDPattern.MatchString(l[LabelSandboxID]) {
		return Container{}, false
	}
	role := l[LabelIsolationRole]
	if role != sandboxfeed.RoleSandbox && role != sandboxfeed.RoleSupervisor {
		return Container{}, false
	}
	return Container{
		ID: redaction.TruncateUTF8(labels.ID, sandboxfeed.MaxIDBytes), SandboxID: l[LabelSandboxID],
		SandboxName: redaction.TruncateUTF8(l[LabelSandboxName], sandboxfeed.MaxIDBytes), Role: role, Owner: ownerUID(l[LabelOwnerUID]),
	}, true
}

// ownerUID parses the uid label; sandboxes never run as root, so 0 is no
// owner too.
func ownerUID(value string) int {
	uid, err := strconv.Atoi(value)
	if err != nil || uid <= 0 || uid > 1<<31-2 {
		return -1
	}
	return uid
}

// owner is the uid a sandbox belongs to: the workload container's label. The
// supervisor container has none, so it is read from the workload's.
func (c *Containers) owner(ctx context.Context, container Container, now time.Time) int {
	c.mu.Lock()
	if container.Owner >= 0 {
		c.owners[container.SandboxID] = cachedOwner{uid: container.Owner, until: now.Add(keepKnown)}
		c.mu.Unlock()
		return container.Owner
	}
	if hit, ok := c.owners[container.SandboxID]; ok && now.Before(hit.until) {
		c.mu.Unlock()
		return hit.uid
	}
	c.mu.Unlock()
	listed, err := c.inspector.Sandbox(ctx, container.SandboxID)
	if err != nil {
		return -1
	}
	for _, other := range listed {
		peer, ok := containerOf(other)
		if ok && peer.SandboxID == container.SandboxID && peer.Role == sandboxfeed.RoleSandbox && peer.Owner >= 0 {
			c.mu.Lock()
			c.owners[container.SandboxID] = cachedOwner{uid: peer.Owner, until: now.Add(keepKnown)}
			c.mu.Unlock()
			return peer.Owner
		}
	}
	return -1
}

// prune drops expired answers once the cache is full. Callers hold c.mu.
func (c *Containers) prune(now time.Time) {
	if len(c.byID) >= maxCached {
		for id, entry := range c.byID {
			if !now.Before(entry.until) {
				delete(c.byID, id)
			}
		}
		// Still full: every entry is live, so forget an arbitrary quarter
		// (asked again on its next exec) rather than grow.
		for id := range c.byID {
			if len(c.byID) < maxCached*3/4 {
				break
			}
			delete(c.byID, id)
		}
	}
	if len(c.owners) >= maxCached {
		for id, entry := range c.owners {
			if !now.Before(entry.until) {
				delete(c.owners, id)
			}
		}
	}
}
