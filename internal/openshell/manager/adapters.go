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

package manager

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
	"github.com/defenseclaw/defenseclaw/internal/openshell/stream"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// Bindings is the ingress binding store the manager drives.
// *sandboxauth.FileStore satisfies it.
type Bindings interface {
	Mint(spec sandboxauth.Spec) (sandboxauth.Binding, string, error)
	Rotate(id string) (sandboxauth.Binding, string, error)
	Revoke(id string) error
	Update(id string, fn func(*sandboxauth.Spec) error) (sandboxauth.Binding, error)
	Get(id string) (sandboxauth.Binding, error)
	Lookup(sandboxName string) (sandboxauth.Binding, error)
	List() []sandboxauth.Binding
}

// ErrImageMissing reports that no hook-verified overlay image exists for a
// sandbox and building one was not allowed.
var ErrImageMissing = errors.New("no hook-verified overlay image is built for this harness")

// Images resolves the verified overlay image a sandbox runs.
type Images interface {
	// Resolve returns the hook-verified image for spec. When none is
	// recorded it builds one if build is set (Build runs the hook-fire
	// verification) and otherwise returns ErrImageMissing. An unverified
	// image is never returned.
	Resolve(ctx context.Context, spec image.BuildSpec, build bool) (image.Record, error)
}

// BuilderImages implements Images with the overlay image builder.
type BuilderImages struct {
	Builder *image.Builder
	// Options tune builds started by Resolve.
	Options image.BuildOptions
}

// Resolve implements Images.
func (b BuilderImages) Resolve(ctx context.Context, spec image.BuildSpec, build bool) (image.Record, error) {
	if b.Builder == nil {
		return image.Record{}, errors.New("no image builder configured")
	}
	if rec, ok, err := b.Builder.Current(spec); err != nil {
		return image.Record{}, err
	} else if ok && rec.HookFireVerified {
		return rec, nil
	}
	if !build {
		return image.Record{}, ErrImageMissing
	}
	opts := b.Options
	opts.SkipHookFire = false
	rec, err := b.Builder.Build(ctx, spec, opts)
	if err != nil {
		return image.Record{}, err
	}
	if !rec.HookFireVerified {
		return image.Record{}, fmt.Errorf("overlay image %s was built but its hooks are not verified", rec.Tag)
	}
	return rec, nil
}

// Workspace is the project-folder surface the manager uses. It is a thin
// seam over package workspace so the workspace API can evolve behind it.
type Workspace interface {
	PlanMount(ctx context.Context, opts workspace.MountOptions) (*workspace.MountPlan, error)
	ReleaseMount(dataDir, name string) error
	Snapshot(ctx context.Context, opts workspace.SnapshotOptions) (*workspace.SnapshotRecord, error)
	LoadSnapshot(dataDir, name string) (*workspace.SnapshotRecord, error)
	DeleteSnapshot(ctx context.Context, dataDir, name string) error
	Undo(ctx context.Context, opts workspace.UndoOptions) (*workspace.UndoResult, error)
	Review(ctx context.Context, opts workspace.ReviewOptions) (*workspace.ReviewReport, error)
	ReviewDiff(ctx context.Context, dataDir, name string) ([]byte, error)
	DeleteCopy(dataDir, name string) error
}

// DefaultWorkspace implements Workspace with package workspace.
type DefaultWorkspace struct{}

func (DefaultWorkspace) PlanMount(ctx context.Context, opts workspace.MountOptions) (*workspace.MountPlan, error) {
	return workspace.PlanMount(ctx, opts)
}

func (DefaultWorkspace) ReleaseMount(dataDir, name string) error {
	return workspace.ReleaseMount(dataDir, name)
}

func (DefaultWorkspace) Snapshot(ctx context.Context, opts workspace.SnapshotOptions) (*workspace.SnapshotRecord, error) {
	return workspace.Snapshot(ctx, opts)
}

func (DefaultWorkspace) LoadSnapshot(dataDir, name string) (*workspace.SnapshotRecord, error) {
	return workspace.LoadSnapshot(dataDir, name)
}

func (DefaultWorkspace) DeleteSnapshot(ctx context.Context, dataDir, name string) error {
	return workspace.DeleteSnapshot(ctx, dataDir, name)
}

func (DefaultWorkspace) Undo(ctx context.Context, opts workspace.UndoOptions) (*workspace.UndoResult, error) {
	return workspace.Undo(ctx, opts)
}

func (DefaultWorkspace) Review(ctx context.Context, opts workspace.ReviewOptions) (*workspace.ReviewReport, error) {
	return workspace.Review(ctx, opts)
}

func (DefaultWorkspace) ReviewDiff(ctx context.Context, dataDir, name string) ([]byte, error) {
	return workspace.ReviewDiff(ctx, dataDir, name)
}

func (DefaultWorkspace) DeleteCopy(dataDir, name string) error {
	return workspace.DeleteCopy(dataDir, name)
}

// ProfileImporter imports platform-scoped provider profiles in their YAML
// form. The SDK's typed profile drops endpoint access and enforcement, so
// profiles go through the upstream CLI, which the spike validated.
type ProfileImporter interface {
	// Import creates the profile on the named gateway registration when
	// resourceVersion is 0. Otherwise it replaces the existing profile of
	// the same id, which must still be at resourceVersion: a concurrent
	// update (another DefenseClaw daemon on the gateway) makes it fail
	// instead of being overwritten.
	Import(ctx context.Context, gateway string, p profiles.Profile, resourceVersion uint64) error
}

// CLIProfileImporter imports profiles with `openshell profile import|update
// --global`.
type CLIProfileImporter struct {
	Binary string
	Runner openshell.Runner
	// TempDir holds the short-lived profile files (default os.TempDir()).
	TempDir string
}

// Import implements ProfileImporter. An update's file carries the
// resource_version it replaces, which `openshell profile update` requires
// (as `openshell profile export` prints it).
func (c CLIProfileImporter) Import(ctx context.Context, gateway string, p profiles.Profile, resourceVersion uint64) error {
	if !openshell.ValidGatewayName(gateway) {
		return fmt.Errorf("profile import needs a gateway name, got %q", gateway)
	}
	if p.ID == "" || len(p.YAML) == 0 {
		return errors.New("profile import needs a rendered profile")
	}
	data := p.YAML
	if resourceVersion != 0 {
		data = append([]byte("resource_version: "+strconv.FormatUint(resourceVersion, 10)+"\n"), p.YAML...)
	}
	dir := c.TempDir
	if dir == "" {
		dir = os.TempDir()
	}
	f, err := os.CreateTemp(dir, "dc-profile-*.yaml")
	if err != nil {
		return fmt.Errorf("profile import: %w", err)
	}
	name := f.Name()
	defer os.Remove(name)
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return fmt.Errorf("profile import: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("profile import: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("profile import: %w", err)
	}
	bin := c.Binary
	if bin == "" {
		bin = openshell.DefaultBinary
	}
	args := []string{"profile", "import", "-f", filepath.Clean(name), "--global", "-g", gateway}
	if resourceVersion != 0 {
		args = []string{"profile", "update", "-f", filepath.Clean(name), "--global", "-g", gateway, p.ID}
	}
	runner := c.Runner
	if runner == nil {
		runner = openshell.ExecRunner{}
	}
	out, err := runner.Output(ctx, openshell.Command{Name: bin, Args: args, Timeout: time.Minute})
	if err != nil {
		return fmt.Errorf("openshell profile %s %s: %w: %s", args[1], p.ID, err, lastLine(out))
	}
	return nil
}

func lastLine(out []byte) string {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

// Gateway is a live connection to the local OpenShell gateway.
type Gateway struct {
	Client openshell.Client
	// Conn serves the WatchSandbox streams; nil disables watchers.
	Conn grpc.ClientConnInterface
	// Name is the registration name (the CLI's -g).
	Name     string
	Endpoint string
	// Port is the gateway's own port, which sandboxes must never reach.
	Port    int
	Version string
	// Close releases the connection.
	Close func() error
}

// Connector opens the gateway connection. It is retried until it succeeds.
type Connector func(ctx context.Context) (*Gateway, error)

// DiscoverConnector connects to the registration Discover selects, refusing
// gateways outside the supported version window.
func DiscoverConnector(discover openshell.DiscoverOptions, client openshell.ClientOptions) Connector {
	return func(ctx context.Context) (*Gateway, error) {
		reg, err := openshell.Discover(discover)
		if err != nil {
			return nil, err
		}
		c, err := openshell.Dial(reg, client)
		if err != nil {
			return nil, err
		}
		health, err := c.Health(ctx)
		if err != nil {
			_ = c.Close()
			return nil, err
		}
		if err := health.CheckVersion(); err != nil {
			_ = c.Close()
			return nil, err
		}
		conn, err := reg.DialGRPC()
		if err != nil {
			_ = c.Close()
			return nil, err
		}
		return &Gateway{
			Client: c, Conn: conn, Name: reg.Name, Endpoint: reg.Endpoint, Port: registrationPort(reg),
			Version: health.RawVersion,
			Close: func() error {
				return errors.Join(c.Close(), conn.Close())
			},
		}, nil
	}
}

func registrationPort(reg *openshell.Registration) int {
	target := reg.Target()
	if i := strings.LastIndexByte(target, ':'); i >= 0 {
		var port int
		if _, err := fmt.Sscanf(target[i+1:], "%d", &port); err == nil && port > 0 && port < 65536 {
			return port
		}
	}
	return 0
}

// WatchFunc follows one sandbox until ctx ends or the watch fails for good,
// delivering events to handle and persisting the resume cursor with save.
type WatchFunc func(ctx context.Context, gw *Gateway, sandbox, cursor string, save func(string) error, handle func(stream.Event)) error

// StreamWatch is the default WatchFunc, over the gateway's raw
// WatchSandbox stream.
func StreamWatch(ctx context.Context, gw *Gateway, sandbox, cursor string, save func(string) error, handle func(stream.Event)) error {
	if gw == nil || gw.Conn == nil {
		return errors.New("no gateway stream connection")
	}
	w, err := stream.New(stream.Config{
		Conn: gw.Conn, Workspace: gw.Client.Workspace(), Sandbox: sandbox, Cursor: cursor, SaveCursor: save,
	})
	if err != nil {
		return err
	}
	return w.Run(ctx, handle)
}
