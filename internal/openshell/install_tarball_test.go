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

package openshell

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/netguard"
)

// release is a fake NVIDIA release server: the tarballs of one version for
// linux/amd64 and the two checksum files.
type release struct {
	t        *testing.T
	version  string
	archives map[string][]byte // asset name -> tar.gz
	listed   map[string]string // asset name -> digest NVIDIA lists
	pins     map[string]string
	server   *httptest.Server
	mu       sync.Mutex
	requests []string
	redirect string
}

func tarball(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		header := &tar.Header{Name: e.name, Mode: 0o755, Typeflag: e.kind, Linkname: e.link, Size: int64(len(e.body))}
		if e.kind != tar.TypeReg {
			header.Size = 0
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if e.kind == tar.TypeReg {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type tarEntry struct {
	name string
	body []byte
	kind byte
	link string
}

func reg(name, body string) tarEntry {
	return tarEntry{name: name, body: []byte(body), kind: tar.TypeReg}
}

func digestOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func newRelease(t *testing.T, version string) *release {
	t.Helper()
	r := &release{t: t, version: version, archives: map[string][]byte{}, listed: map[string]string{}, pins: map[string]string{}}
	cli, gnu, err := tarballTriples("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range tarballComponents {
		asset := c.assetName(cli, gnu)
		data := tarball(t, reg(c.Name, "#!/bin/sh\necho "+c.Name+" "+version+"\n"))
		r.archives[asset] = data
		r.listed[asset] = digestOf(data)
		r.pins[asset] = digestOf(data)
	}
	r.server = httptest.NewTLSServer(http.HandlerFunc(r.serve))
	t.Cleanup(r.server.Close)
	return r
}

func (r *release) serve(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	r.requests = append(r.requests, req.URL.Path)
	redirect := r.redirect
	r.mu.Unlock()
	prefix := "/v" + r.version + "/"
	if !strings.HasPrefix(req.URL.Path, prefix) {
		http.NotFound(w, req)
		return
	}
	name := strings.TrimPrefix(req.URL.Path, prefix)
	if redirect != "" {
		http.Redirect(w, req, redirect+name, http.StatusFound)
		return
	}
	switch name {
	case "openshell-checksums-sha256.txt", "openshell-gateway-checksums-sha256.txt":
		var b strings.Builder
		for asset, sum := range r.listed {
			isGateway := strings.HasPrefix(asset, "openshell-gateway-")
			if isGateway == (name == "openshell-gateway-checksums-sha256.txt") {
				fmt.Fprintf(&b, "%s  %s\n", sum, asset)
			}
		}
		w.Write([]byte(b.String()))
	default:
		data, ok := r.archives[name]
		if !ok {
			http.NotFound(w, req)
			return
		}
		w.Write(data)
	}
}

func (r *release) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.requests)
}

// fakeRunner answers the installed CLI's --version and records every call.
type fakeRunner struct {
	version string
	calls   []string
}

func (f *fakeRunner) Output(_ context.Context, cmd Command) ([]byte, error) {
	line := cmd.Name + " " + strings.Join(cmd.Args, " ")
	f.calls = append(f.calls, line)
	if len(cmd.Args) == 1 && cmd.Args[0] == "--version" {
		return []byte("openshell " + f.version + "\n"), nil
	}
	return nil, fmt.Errorf("unexpected command %s", line)
}

func (f *fakeRunner) Run(ctx context.Context, cmd Command) error {
	_, err := f.Output(ctx, cmd)
	return err
}

func (r *release) installer(home string, runner Runner) *TarballInstaller {
	return &TarballInstaller{
		Version: r.version, Home: home, GOOS: "linux", GOARCH: "amd64",
		BaseURL: r.server.URL, Pins: r.pins, HTTPClient: r.server.Client(), Runner: runner,
	}
}

func TestTarballInstallPlacesVerifiedBinaries(t *testing.T) {
	rel := newRelease(t, "0.1.5")
	home := t.TempDir()
	inst := rel.installer(home, &fakeRunner{version: "0.1.5"})
	res, err := inst.Install(context.Background())
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.Already || len(res.Files) != 3 {
		t.Fatalf("result = %+v", res)
	}
	for _, want := range []string{".local/bin/openshell", ".local/bin/openshell-gateway", ".local/libexec/openshell/openshell-driver-vm"} {
		info, err := os.Stat(filepath.Join(home, want))
		// Windows has no POSIX mode bits to check.
		if err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0o755 {
			t.Errorf("%s: %v %v", want, info, err)
		}
	}
	// Nothing but the manifest is left of the downloads.
	entries, _ := os.ReadDir(filepath.Join(home, TarballStateDir))
	if len(entries) != 1 || entries[0].Name() != TarballManifestName {
		t.Errorf("state dir = %v", entries)
	}
	release, intact, err := inst.Installed()
	if err != nil || !intact || release.Version != "0.1.5" || len(release.Files) != 3 {
		t.Fatalf("Installed = %+v %v %v", release, intact, err)
	}

	// A second run with the files intact downloads nothing.
	before := rel.count()
	again, err := inst.Install(context.Background())
	if err != nil || !again.Already || rel.count() != before {
		t.Fatalf("second Install: %+v %v, requests %d -> %d", again, err, before, rel.count())
	}

	// A changed binary is replaced by the next install.
	if err := os.WriteFile(filepath.Join(home, ".local/bin/openshell"), []byte("tampered"), 0o755); err != nil {
		t.Fatal(err)
	}
	if res, err := inst.Install(context.Background()); err != nil || res.Already {
		t.Fatalf("reinstall after tamper: %+v %v", res, err)
	}
}

func TestTarballInstallRefusesAnUnverifiedTarball(t *testing.T) {
	cases := map[string]func(*release){
		"NVIDIA's list disagrees with the pin": func(r *release) {
			for asset := range r.listed {
				r.listed[asset] = strings.Repeat("0", 64)
				break
			}
		},
		"the pin disagrees with the file": func(r *release) {
			for asset := range r.pins {
				r.pins[asset] = strings.Repeat("1", 64)
				break
			}
		},
		"the file is not what NVIDIA listed and pinned": func(r *release) {
			for asset := range r.archives {
				r.archives[asset] = append([]byte(nil), r.archives[asset]...)
				r.archives[asset][len(r.archives[asset])-1] ^= 0xff
				break
			}
		},
		"NVIDIA's list does not name a tarball": func(r *release) {
			for asset := range r.listed {
				delete(r.listed, asset)
				break
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			rel := newRelease(t, "0.1.5")
			mutate(rel)
			home := t.TempDir()
			_, err := rel.installer(home, &fakeRunner{version: "0.1.5"}).Install(context.Background())
			if !errors.Is(err, ErrTarballChecksum) {
				t.Fatalf("err = %v, want ErrTarballChecksum", err)
			}
			if _, statErr := os.Stat(filepath.Join(home, ".local", "bin")); !os.IsNotExist(statErr) {
				t.Errorf("a refused install created %s", filepath.Join(home, ".local", "bin"))
			}
		})
	}
}

func TestTarballInstallRefusesUnexpectedArchiveContent(t *testing.T) {
	cli, gnu, _ := tarballTriples("linux", "amd64")
	cases := map[string][]tarEntry{
		"an extra file":     {reg("openshell", "ok"), reg("extra", "x")},
		"a symlink":         {{name: "openshell", kind: tar.TypeSymlink, link: "/etc/passwd"}},
		"a path traversal":  {reg("../openshell", "x")},
		"another name":      {reg("not-openshell", "x")},
		"an empty archive":  {},
		"a nested path":     {reg("bin/openshell", "x")},
		"the file twice":    {reg("openshell", "a"), reg("openshell", "b")},
		"a zero-byte file":  {reg("openshell", "")},
		"an absolute path":  {reg("/tmp/openshell", "x")},
		"a hard link entry": {{name: "openshell", kind: tar.TypeLink, link: "x"}},
	}
	for name, entries := range cases {
		t.Run(name, func(t *testing.T) {
			rel := newRelease(t, "0.1.5")
			asset := tarballComponents[0].assetName(cli, gnu)
			bad := tarball(t, entries...)
			rel.archives[asset], rel.listed[asset], rel.pins[asset] = bad, digestOf(bad), digestOf(bad)
			home := t.TempDir()
			_, err := rel.installer(home, &fakeRunner{version: "0.1.5"}).Install(context.Background())
			if !errors.Is(err, ErrTarballContent) {
				t.Fatalf("err = %v, want ErrTarballContent", err)
			}
			if _, statErr := os.Stat(filepath.Join(home, ".local", "bin", "openshell")); statErr == nil {
				t.Error("a refused archive left a binary behind")
			}
		})
	}
}

func TestTarballInstallRefusesAWrongVersionBinary(t *testing.T) {
	rel := newRelease(t, "0.1.5")
	_, err := rel.installer(t.TempDir(), &fakeRunner{version: "0.1.1"}).Install(context.Background())
	if err == nil || !strings.Contains(err.Error(), "reports 0.1.1, want 0.1.5") {
		t.Fatalf("err = %v", err)
	}
}

func TestTarballInstallOfflineIsNamed(t *testing.T) {
	rel := newRelease(t, "0.1.5")
	inst := rel.installer(t.TempDir(), &fakeRunner{version: "0.1.5"})
	rel.server.Close()
	_, err := inst.Install(context.Background())
	if !errors.Is(err, ErrTarballOffline) {
		t.Fatalf("err = %v, want ErrTarballOffline", err)
	}
	for _, want := range []string{"enterprise.network", "install: prerequisite"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
}

func TestTarballInstallNeedsAPinnedExactVersion(t *testing.T) {
	home := t.TempDir()
	for _, version := range []string{"", ">=0.1.1 <0.2.0", "0.1", "latest"} {
		_, err := (&TarballInstaller{Version: version, Home: home}).Install(context.Background())
		if err == nil || !strings.Contains(err.Error(), "exact OpenShell version") {
			t.Errorf("version %q: err = %v", version, err)
		}
	}
	_, err := (&TarballInstaller{Version: "9.9.9", Home: home}).Install(context.Background())
	if !errors.Is(err, ErrTarballNotPinned) || !strings.Contains(err.Error(), "0.1.5") {
		t.Errorf("unpinned release: err = %v", err)
	}
	_, err = (&TarballInstaller{Version: "0.1.5", Home: "relative/home"}).Install(context.Background())
	if err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Errorf("relative home: err = %v", err)
	}
	_, err = (&TarballInstaller{Version: "0.1.5", Home: home, GOOS: "darwin", GOARCH: "amd64"}).Install(context.Background())
	if !errors.Is(err, ErrTarballPlatform) {
		t.Errorf("Intel macOS: err = %v", err)
	}
}

func TestTarballPinsCoverEveryPlatform(t *testing.T) {
	for release, pins := range TarballPins {
		for _, platform := range [][2]string{{"linux", "amd64"}, {"linux", "arm64"}, {"darwin", "arm64"}} {
			cli, gnu, err := tarballTriples(platform[0], platform[1])
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range tarballComponents {
				asset := c.assetName(cli, gnu)
				if len(pins[asset]) != 64 {
					t.Errorf("release %s pins no digest for %s", release, asset)
				}
			}
		}
	}
	if _, ok := TarballPins[InstallerVersion]; !ok {
		t.Errorf("InstallerVersion %s has no tarball pins", InstallerVersion)
	}
}

func TestTarballInstallRefusesRedirectsOffGitHub(t *testing.T) {
	rel := newRelease(t, "0.1.5")
	rel.redirect = "https://evil.example.test/"
	inst := rel.installer(t.TempDir(), &fakeRunner{version: "0.1.5"})
	inst.HTTPClient = nil
	// Trust the test server's certificate in the default client.
	inst.Proxy = netguard.EgressProxy{}
	client, cerr := inst.client()
	if cerr != nil {
		t.Fatal(cerr)
	}
	client.Transport.(*http.Transport).TLSClientConfig = rel.server.Client().Transport.(*http.Transport).TLSClientConfig
	inst.HTTPClient = client
	_, err := inst.Install(context.Background())
	if err == nil || !strings.Contains(err.Error(), "refusing a redirect to evil.example.test") {
		t.Fatalf("err = %v, want the redirect refused", err)
	}
}

func TestTarballInstallUsesTheAdministratorsProxy(t *testing.T) {
	var mu sync.Mutex
	var connects []string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		connects = append(connects, r.Method+" "+r.Host)
		mu.Unlock()
		http.Error(w, "denied", http.StatusForbidden)
	}))
	defer proxy.Close()
	inst := &TarballInstaller{
		Version: "0.1.5", Home: t.TempDir(), GOOS: "linux", GOARCH: "amd64",
		Proxy:  netguard.EgressProxy{HTTPSProxy: proxy.URL},
		Runner: &fakeRunner{version: "0.1.5"},
	}
	_, err := inst.Install(context.Background())
	if !errors.Is(err, ErrTarballOffline) {
		t.Fatalf("err = %v, want ErrTarballOffline", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(connects) == 0 || connects[0] != "CONNECT github.com:443" {
		t.Fatalf("the proxy saw %v, want a CONNECT to github.com:443", connects)
	}
}

func TestTarballInstallKeepsTheShippedDriverSignature(t *testing.T) {
	// Every pinned release ships its macOS MicroVM driver signed for Apple's
	// Hypervisor, so a Mac install runs nothing but the CLI's --version.
	rel := &release{t: t, version: "0.1.5", archives: map[string][]byte{}, listed: map[string]string{}, pins: map[string]string{}}
	cli, gnu, _ := tarballTriples("darwin", "arm64")
	for _, c := range tarballComponents {
		asset := c.assetName(cli, gnu)
		data := tarball(t, reg(c.Name, "binary "+c.Name))
		rel.archives[asset], rel.listed[asset], rel.pins[asset] = data, digestOf(data), digestOf(data)
	}
	rel.server = httptest.NewTLSServer(http.HandlerFunc(rel.serve))
	defer rel.server.Close()
	runner := &fakeRunner{version: "0.1.5"}
	inst := rel.installer(t.TempDir(), runner)
	inst.GOOS, inst.GOARCH = "darwin", "arm64"
	if _, err := inst.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 1 || !strings.HasSuffix(runner.calls[0], " --version") {
		t.Errorf("calls = %q, want only the installed CLI's --version", runner.calls)
	}
}
