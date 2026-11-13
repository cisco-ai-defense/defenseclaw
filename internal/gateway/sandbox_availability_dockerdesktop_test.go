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

package gateway

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0007: on a managed Mac with enterprise.openshell.driver docker, the
// gateway's service account cannot enter the 0700 ~/.docker that
// /var/run/docker.sock leads into. It no longer answers "the Docker socket
// isn't read-write for your account": the caller's own Docker Desktop is
// named as the reason (no Landlock; MicroVMs are the Mac's driver),
// another account's as not running in the caller's account, and any other
// socket is judged by its modes as before. The MicroVM driver asks nothing
// of Docker at the gateway.
func TestSandboxAvailabilityDockerDesktopOnAMac(t *testing.T) {
	docker := &config.Config{}
	docker.OpenShell.Enabled = true
	docker.Enterprise.OpenShell.Driver = config.EnterpriseOpenShellDriverDocker
	vm := &config.Config{}
	vm.OpenShell.Enabled = true
	probe := func(link sandboxDockerDesktopLink, state sandboxDeviceState) *sandboxAvailabilityProbe {
		p := newSandboxAvailabilityProbe()
		p.goos, p.goarch, p.prerequisite = "darwin", "arm64", nil
		p.access = func(string, int) sandboxDeviceAccess { return sandboxDeviceAccess{State: state} }
		p.dockerDesktop = func(path string, uid int) sandboxDockerDesktopLink {
			if path != sandboxDockerSocketPath || uid != 503 {
				t.Errorf("dockerDesktop(%s, %d)", path, uid)
			}
			return link
		}
		return p
	}
	for name, tc := range map[string]struct {
		p    *sandboxAvailabilityProbe
		cfg  *config.Config
		want sandboxAvailability
	}{
		"own docker desktop": {probe(sandboxDockerDesktopOwn, sandboxDeviceDenied), docker,
			sandboxAvailability{Why: sandboxUnavailableDockerDesktop, Code: "driver_unsupported"}},
		"another account's": {probe(sandboxDockerDesktopOther, sandboxDeviceDenied), docker,
			sandboxAvailability{Why: sandboxUnavailableDockerElsewhere, Code: "no_docker"}},
		"colima socket": {probe(sandboxDockerDesktopNone, sandboxDeviceUsable), docker,
			sandboxAvailability{Available: true, Driver: "docker", DriverReason: "configured"}},
		"unexaminable socket": {probe(sandboxDockerDesktopNone, sandboxDeviceDenied), docker,
			sandboxUnavailable(sandboxUnavailableDockerAccess)},
		"microvm": {probe(sandboxDockerDesktopOwn, sandboxDeviceDenied), vm,
			sandboxAvailability{Available: true, Driver: "vm", DriverReason: "configured"}},
	} {
		if got := tc.p.check(tc.cfg, 503, true, config.OpenShellAdminConfig{}); got != tc.want {
			t.Errorf("%s: %+v, want %+v", name, got, tc.want)
		}
	}
	// Linux has no Docker Desktop link to judge.
	p := probe(sandboxDockerDesktopOwn, sandboxDeviceUsable)
	p.goos, p.goarch = "linux", "amd64"
	if got := p.check(docker, 503, true, config.OpenShellAdminConfig{}); !got.Available {
		t.Fatalf("linux: %+v", got)
	}
}

// sandboxDockerDesktopLinkOf reads only the link and the owner of the home
// folder it leads into, never anything under it.
func TestSandboxDockerDesktopLinkOf(t *testing.T) {
	root := t.TempDir()
	own, other := filepath.Join(root, "Users", "dcm-std2"), filepath.Join(root, "Users", "dcm-std1")
	for _, home := range []string{own, other} {
		if err := os.MkdirAll(home, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	owners := map[string]int{own: 503, other: 502}
	linkOwner := 0
	restore := sandboxOwnerOf
	t.Cleanup(func() { sandboxOwnerOf = restore })
	sandboxOwnerOf = func(info fs.FileInfo) (int, bool) {
		if info.Mode()&fs.ModeSymlink != 0 {
			return linkOwner, true
		}
		for path, uid := range owners {
			if filepath.Base(path) == info.Name() {
				return uid, true
			}
		}
		return 0, false
	}
	link := func(target string) string {
		path := filepath.Join(t.TempDir(), "docker.sock")
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		return path
	}
	plain := filepath.Join(t.TempDir(), "docker.sock")
	if err := os.WriteFile(plain, nil, 0o660); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		path      string
		linkOwner int
		want      sandboxDockerDesktopLink
	}{
		"own home":         {link(own + sandboxDockerDesktopSocket), 0, sandboxDockerDesktopOwn},
		"another home":     {link(other + sandboxDockerDesktopSocket), 0, sandboxDockerDesktopOther},
		"not a link":       {plain, 0, sandboxDockerDesktopNone},
		"a link of a user": {link(own + sandboxDockerDesktopSocket), 503, sandboxDockerDesktopNone},
		"relative target":  {link("dcm-std2" + sandboxDockerDesktopSocket), 0, sandboxDockerDesktopNone},
		"unclean target":   {link(own + "/../dcm-std2" + sandboxDockerDesktopSocket), 0, sandboxDockerDesktopNone},
		"colima":           {link(own + "/.colima/default/docker.sock"), 0, sandboxDockerDesktopNone},
		"missing home":     {link(filepath.Join(root, "Users", "gone") + sandboxDockerDesktopSocket), 0, sandboxDockerDesktopNone},
		"missing link":     {filepath.Join(root, "absent.sock"), 0, sandboxDockerDesktopNone},
		"root as the home": {link(sandboxDockerDesktopSocket), 0, sandboxDockerDesktopNone},
	} {
		linkOwner = tc.linkOwner
		if got := sandboxDockerDesktopLinkOf(tc.path, 503); got != tc.want {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
}
