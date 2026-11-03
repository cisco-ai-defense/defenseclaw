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

package image

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
)

func TestR108OSMINMicroVMCustomBaseHostsAndBenignTwin(t *testing.T) {
	spec := testSpec(harness.Codex)
	spec.MicroVM = true
	c := mustContext(t, spec)
	if contextSchema < 2 {
		t.Fatal("the MicroVM image schema does not invalidate older records")
	}
	file := microVMResolverStep(openshell.DefaultBaseImage)
	for _, part := range []string{
		"FROM dc-complete AS dc-resolver-check\n",
		"--network=none --mount=type=bind,from=dc-complete,source=/,target=/tmp/dc-root,ro",
		"/usr/sbin/chroot \"$root\" " + microVMResolverPath + " hosts localhost",
		"USER sandbox\n",
	} {
		if !strings.Contains(file, part) {
			t.Fatalf("MicroVM image lacks completed-image resolver step %q", part)
		}
	}
	if strings.Contains(string(c.Dockerfile), "dc-resolver-check") {
		t.Fatal("the completed image is checked before its exported hosts file is known")
	}
	if !strings.Contains(string(c.Dockerfile), microVMResolverCopyStep()) {
		t.Fatal("the completed VM image lacks the pinned resolver caller")
	}
	dockerSpec := testSpec(harness.Codex)
	if strings.Contains(string(mustContext(t, dockerSpec).Dockerfile), "dc-resolver-check") ||
		strings.Contains(string(mustContext(t, dockerSpec).Dockerfile), microVMResolverPath) {
		t.Fatal("Docker-driver image has the VM-only check")
	}
	localDocker(t)

	for _, tc := range []struct {
		name      string
		hosts     []byte
		copyHosts bool
		want      bool
	}{
		{"stock empty file", nil, false, true},
		{"empty regular file", nil, true, true},
		{"canonical mapping", []byte("127.0.0.1 localhost\n"), true, true},
		{"dual stack mapping", []byte("::1 localhost\n127.0.0.1 localhost\n"), true, true},
		{"IPv6 answer ahead of usable IPv4", []byte("::2 localhost\n127.0.0.1 localhost\n"), true, true},
		{"alias after another name", []byte("127.0.0.1 localname localhost\n"), true, true},
		{"upper ASCII alias", []byte("127.0.0.1 LOCALHOST\n"), true, true},
		{"mixed ASCII alias", []byte("127.0.0.1 LocalHost\n"), true, true},
		{"tabs without final newline", []byte("127.0.0.1\tlocalhost"), true, true},
		{"CRLF mapping", []byte("127.0.0.1 localhost\r\n"), true, true},
		{"non ASCII full line comment", []byte("# caf\xc3\xa9\n127.0.0.1 localhost\n"), true, true},
		{"non ASCII inline comment", []byte("127.0.0.1 localhost # caf\xc3\xa9\n"), true, true},
		{"unrelated record", []byte("not a record\n127.0.0.1 localhost\n"), true, true},
		{"NUL after mapping", []byte("127.0.0.1 localhost\n\x00unrelated\n"), true, true},
		{"long canonical alias", []byte("127.0.0.1 " + strings.Repeat(strings.Repeat("a", 60)+".", 3) + strings.Repeat("a", 60) + " localhost\n"), true, true},
		{"unmapped name", []byte("127.0.0.1 custom\n"), true, false},
		{"comment only", []byte("# 127.0.0.1 localhost\n"), true, false},
		{"long s lookalike", []byte("127.0.0.1 localho\xc5\xbft\n"), true, false},
		{"Cyrillic alias", []byte("127.0.0.1 localh\xd0\xbest\n"), true, false},
		{"NUL before first mapping", []byte("\x00127.0.0.1 localhost\n"), true, false},
		{"NUL before later mapping", []byte("127.0.0.1 custom\n\x00127.0.0.1 localhost\n"), true, false},
		{"NUL inside alias", []byte("127.0.0.1 localho\x00st\n"), true, false},
		{"other address", []byte("203.0.113.10 localhost\n"), true, false},
		{"mixed addresses", []byte("127.0.0.1 localhost\n203.0.113.10 localhost\n"), true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			layout := "FROM " + openshell.DefaultBaseImage + " AS dc-complete\n"
			if tc.copyHosts {
				if err := os.WriteFile(filepath.Join(dir, "hosts"), tc.hosts, 0o600); err != nil {
					t.Fatal(err)
				}
				layout += "COPY hosts /etc/hosts\n"
			}
			layout += microVMResolverCopyStep() + microVMResolverStep(openshell.DefaultBaseImage)
			if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(layout), 0o600); err != nil {
				t.Fatal(err)
			}
			tag := testImageTag(dir)
			t.Cleanup(func() { exec.Command("docker", "image", "rm", "-f", tag).Run() })
			out, err := dockerCommand(t, "build", "--pull=false", "--progress=plain", "-t", tag, dir).CombinedOutput()
			if (err == nil) != tc.want {
				t.Fatalf("build success = %t, want %t: %v\n%s", err == nil, tc.want, err, out)
			}
			if err != nil && !bytes.Contains(out, []byte("MicroVM image localhost check failed")) {
				t.Fatalf("build did not name the localhost repair: %s", out)
			}
		})
	}
}

// A custom base may supply localhost through a local NSS module even when
// its nonempty hosts file names only other hosts. The completed-image check
// uses that resolver instead of requiring a particular hosts-file layout.
func TestMicroVMResolverCustomLocalNSSSource(t *testing.T) {
	localDocker(t)
	const source = `#include <nss.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
enum nss_status _nss_localtest_gethostbyname2_r(const char *name, int af, struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop) {
    if (strcasecmp(name, "localhost") != 0 || af != AF_INET) {
        *h_errnop = HOST_NOT_FOUND;
        return NSS_STATUS_NOTFOUND;
    }
    uintptr_t p = ((uintptr_t)buffer + sizeof(char *) - 1) & ~(sizeof(char *) - 1);
    char **aliases = (char **)p;
    p += sizeof(char *);
    char **addresses = (char **)p;
    p += 2 * sizeof(char *);
    if (p + 4 + 10 > (uintptr_t)buffer + buflen) {
        *errnop = ERANGE;
        *h_errnop = NETDB_INTERNAL;
        return NSS_STATUS_TRYAGAIN;
    }
    char *address = (char *)p;
    address[0] = 127; address[1] = 0; address[2] = 0; address[3] = 1;
    char *canonical = address + 4;
    memcpy(canonical, "localhost", 10);
    aliases[0] = NULL;
    addresses[0] = address;
    addresses[1] = NULL;
    result->h_name = canonical;
    result->h_aliases = aliases;
    result->h_addrtype = AF_INET;
    result->h_length = 4;
    result->h_addr_list = addresses;
    return NSS_STATUS_SUCCESS;
}
`
	for _, tc := range []struct {
		name, nss string
		want      bool
	}{
		{"custom file without local source", "", false},
		{"custom file with local source", "localtest", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "hosts"), []byte("127.0.0.1 custom\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			layout := "FROM " + openshell.DefaultBaseImage + " AS dc-complete\nUSER root\nCOPY hosts /etc/hosts\n"
			if tc.nss != "" {
				if err := os.WriteFile(filepath.Join(dir, "localtest.c"), []byte(source), 0o600); err != nil {
					t.Fatal(err)
				}
				layout += "COPY localtest.c /tmp/localtest.c\nRUN gcc -shared -fPIC -o /usr/lib/$(gcc -dumpmachine)/libnss_localtest.so.2 /tmp/localtest.c && sed -i 's/^hosts:.*/hosts: files localtest/' /etc/nsswitch.conf\n"
			}
			layout += microVMResolverCopyStep() + microVMResolverStep(openshell.DefaultBaseImage)
			if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(layout), 0o600); err != nil {
				t.Fatal(err)
			}
			tag := testImageTag(dir)
			t.Cleanup(func() { exec.Command("docker", "image", "rm", "-f", tag).Run() })
			out, err := dockerCommand(t, "build", "--pull=false", "--progress=plain", "-t", tag, dir).CombinedOutput()
			if (err == nil) != tc.want {
				t.Fatalf("build success = %t, want %t: %v\n%s", err == nil, tc.want, err, out)
			}
		})
	}
}

func TestMicroVMResolverUsesLibcWithImagePythonCustomization(t *testing.T) {
	localDocker(t)
	for _, tc := range []struct {
		name, hosts, replacement string
		want                     bool
	}{
		{"usable localhost", "127.0.0.1 localhost\n", "203.0.113.10", true},
		{"unusable localhost", "203.0.113.10 localhost\n", "127.0.0.1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "hosts"), []byte(tc.hosts), 0o600); err != nil {
				t.Fatal(err)
			}
			site := `import socket
def resolved(host, port, family=0, type=0, proto=0, flags=0):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("` + tc.replacement + `", 0))]
socket.getaddrinfo = resolved
`
			if err := os.WriteFile(filepath.Join(dir, "sitecustomize.py"), []byte(site), 0o600); err != nil {
				t.Fatal(err)
			}
			layout := "FROM " + openshell.DefaultBaseImage + " AS dc-complete\nUSER root\n" +
				"COPY hosts /etc/hosts\nCOPY sitecustomize.py /usr/lib/python3.12/sitecustomize.py\n" +
				microVMResolverCopyStep() + microVMResolverStep(openshell.DefaultBaseImage)
			if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(layout), 0o600); err != nil {
				t.Fatal(err)
			}
			tag := testImageTag(dir)
			t.Cleanup(func() { exec.Command("docker", "image", "rm", "-f", tag).Run() })
			out, err := dockerCommand(t, "build", "--pull=false", "--progress=plain", "-t", tag, dir).CombinedOutput()
			if (err == nil) != tc.want {
				t.Fatalf("build success = %t, want %t: %v\n%s", err == nil, tc.want, err, out)
			}
		})
	}
}

func TestMicroVMResolverUsesPinnedCallerWithCustomGetent(t *testing.T) {
	localDocker(t)
	for _, tc := range []struct {
		name, hosts, customAnswer string
		want                      bool
	}{
		{"usable localhost", "127.0.0.1 localhost\n", "203.0.113.10 localhost", true},
		{"unusable localhost", "203.0.113.10 localhost\n", "127.0.0.1 localhost", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "hosts"), []byte(tc.hosts), 0o600); err != nil {
				t.Fatal(err)
			}
			custom := "#!/bin/sh\nprintf '%s\\n' '" + tc.customAnswer + "'\n"
			if err := os.WriteFile(filepath.Join(dir, "custom-getent"), []byte(custom), 0o755); err != nil {
				t.Fatal(err)
			}
			layout := "FROM " + openshell.DefaultBaseImage + " AS dc-complete\nUSER root\n" +
				"COPY hosts /etc/hosts\nCOPY --chmod=0755 custom-getent /usr/bin/getent\n" +
				microVMResolverCopyStep() + microVMResolverStep(openshell.DefaultBaseImage)
			if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(layout), 0o600); err != nil {
				t.Fatal(err)
			}
			tag := testImageTag(dir)
			t.Cleanup(func() { exec.Command("docker", "image", "rm", "-f", tag).Run() })
			out, err := dockerCommand(t, "build", "--pull=false", "--progress=plain", "-t", tag, dir).CombinedOutput()
			if (err == nil) != tc.want {
				t.Fatalf("build success = %t, want %t: %v\n%s", err == nil, tc.want, err, out)
			}
		})
	}
}

func TestMicroVMResolverSymlinks(t *testing.T) {
	localDocker(t)
	for _, tc := range []struct {
		name, link   string
		target, want bool
	}{
		{"in-image target", "target", true, true},
		{"missing target", "target", false, false},
		{"out-of-image target", "../../outside", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			var data bytes.Buffer
			tw := tar.NewWriter(&data)
			if tc.target {
				body := []byte("127.0.0.1 localhost\n")
				if err := tw.WriteHeader(&tar.Header{Name: "etc/target", Mode: 0o644, Size: int64(len(body))}); err != nil {
					t.Fatal(err)
				}
				if _, err := tw.Write(body); err != nil {
					t.Fatal(err)
				}
			}
			if err := tw.WriteHeader(&tar.Header{Name: "etc/hosts", Typeflag: tar.TypeSymlink, Linkname: tc.link, Mode: 0o777}); err != nil {
				t.Fatal(err)
			}
			if err := tw.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "hosts.tar"), data.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			layout := "FROM " + openshell.DefaultBaseImage + " AS dc-complete\nADD hosts.tar /\n" +
				microVMResolverCopyStep() + microVMResolverStep(openshell.DefaultBaseImage)
			if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(layout), 0o600); err != nil {
				t.Fatal(err)
			}
			tag := testImageTag(dir)
			t.Cleanup(func() { exec.Command("docker", "image", "rm", "-f", tag).Run() })
			out, err := dockerCommand(t, "build", "--pull=false", "--progress=plain", "-t", tag, dir).CombinedOutput()
			if (err == nil) != tc.want {
				t.Fatalf("build success = %t, want %t: %v\n%s", err == nil, tc.want, err, out)
			}
		})
	}
}

func TestMicroVMResolverUnprobeableImage(t *testing.T) {
	localDocker(t)
	for _, tc := range []struct {
		name, change string
		file         bool
	}{
		{"missing resolver", "RUN rm -f " + microVMResolverPath + "\n", false},
		{"missing NSS source", "RUN sed -i 's/^hosts:.*/hosts: unavailable/' /etc/nsswitch.conf\n", false},
		{"resolver timeout", "COPY --chmod=0755 stalled-getent " + microVMResolverPath + "\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "hosts"), []byte("127.0.0.1 localhost\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.file {
				if err := os.WriteFile(filepath.Join(dir, "stalled-getent"), []byte("#!/bin/sh\nsleep 9\n"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			layout := "FROM " + openshell.DefaultBaseImage + " AS dc-complete\nCOPY hosts /etc/hosts\n" +
				microVMResolverCopyStep() + tc.change +
				microVMResolverStep(openshell.DefaultBaseImage)
			if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(layout), 0o600); err != nil {
				t.Fatal(err)
			}
			tag := testImageTag(dir)
			t.Cleanup(func() { exec.Command("docker", "image", "rm", "-f", tag).Run() })
			if out, err := dockerCommand(t, "build", "--pull=false", "--progress=plain", "-t", tag, dir).CombinedOutput(); err == nil ||
				!bytes.Contains(out, []byte("MicroVM image localhost check failed")) {
				t.Fatalf("unprobeable image result = %v\n%s", err, out)
			}
		})
	}
}

// The BuildKit bind source and the Docker export can differ. This measures
// both and confirms that the image check reads the exported entry. Docker's
// runtime hosts file is a third, independently supplied file.
func TestMicroVMResolverUsesExportedHosts(t *testing.T) {
	localDocker(t)
	dir := t.TempDir()
	const authored = "127.0.0.1 localhost\n# image-authored marker\n"
	if err := os.WriteFile(filepath.Join(dir, "hosts"), []byte(authored), 0o600); err != nil {
		t.Fatal(err)
	}
	file := "FROM " + openshell.DefaultBaseImage + " AS dc-complete\nCOPY hosts /etc/hosts\n" +
		"FROM dc-complete AS dc-mounted\nRUN --network=none --mount=type=bind,from=dc-complete,source=/,target=/tmp/dc-root,ro cp /tmp/dc-root/etc/hosts /tmp/mounted-hosts\n"
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	tag := testImageTag(dir)
	t.Cleanup(func() { exec.Command("docker", "image", "rm", "-f", tag).Run() })
	if out, err := dockerCommand(t, "build", "--pull=false", "--progress=plain", "-t", tag, dir).CombinedOutput(); err != nil {
		t.Fatalf("build mounted snapshot: %v\n%s", err, out)
	}
	b := &Builder{Docker: CLI{}}
	exported, err := b.exportHosts(t.Context(), tag)
	if err != nil || !exported.present || exported.typeflag != tar.TypeReg {
		t.Fatalf("exported hosts = %+v, %v", exported, err)
	}
	if exported.initializedByGuest() {
		if len(exported.data) != 0 {
			t.Fatalf("guest-initialized exported hosts was nonempty: %q", exported.data)
		}
	} else if string(exported.data) != authored {
		t.Fatalf("exported hosts = %q, want image entry", exported.data)
	}
	mounted, err := dockerCommand(t, "run", "--rm", "--user", "root", "--entrypoint", "/bin/cat", tag, "/tmp/mounted-hosts").Output()
	if err != nil || string(mounted) != authored {
		t.Fatalf("BuildKit source = %q, %v", mounted, err)
	}
	runtime, err := dockerCommand(t, "run", "--rm", "--user", "root", "--entrypoint", "/bin/cat", tag, "/etc/hosts").Output()
	if err != nil || bytes.Contains(runtime, []byte("image-authored marker")) {
		t.Fatalf("runtime hosts file was not independent: %v %q", err, runtime)
	}
}

func localDocker(t *testing.T) {
	t.Helper()
	for _, args := range [][]string{{"info", "--format", "{{.ServerVersion}}"}, {"buildx", "version"}, {"image", "inspect", openshell.DefaultBaseImage}} {
		if err := dockerCommand(t, args...).Run(); err != nil {
			t.Skipf("local Docker/BuildKit and the pinned base are needed: %v", err)
		}
	}
}

func dockerCommand(t *testing.T, args ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "docker", args...)
	cmd.Env = append(os.Environ(), "DOCKER_BUILDKIT=1")
	return cmd
}

func testImageTag(dir string) string {
	sum := sha256.Sum256([]byte(dir))
	return fmt.Sprintf("r108-osmin23-test:%s", hex.EncodeToString(sum[:8]))
}

func TestMicroVMExportedHostsClassification(t *testing.T) {
	for _, tc := range []struct {
		name      string
		typeflag  byte
		data      string
		link      string
		wantInit  bool
		wantError bool
	}{
		{"missing", 0, "", "", true, false},
		{"empty", tar.TypeReg, "", "", true, false},
		{"mapping", tar.TypeReg, "127.0.0.1 localhost\n", "", false, false},
		{"symlink", tar.TypeSymlink, "", "target", false, false},
		{"directory", tar.TypeDir, "", "", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var data bytes.Buffer
			tw := tar.NewWriter(&data)
			if tc.typeflag != 0 {
				h := &tar.Header{Name: "etc/hosts", Typeflag: tc.typeflag, Linkname: tc.link, Mode: 0o644,
					Size: int64(len(tc.data))}
				if err := tw.WriteHeader(h); err != nil {
					t.Fatal(err)
				}
				if _, err := tw.Write([]byte(tc.data)); err != nil {
					t.Fatal(err)
				}
			}
			if err := tw.Close(); err != nil {
				t.Fatal(err)
			}
			hosts, err := parseExportedHosts(&data)
			if (err != nil) != tc.wantError || (err == nil && hosts.initializedByGuest() != tc.wantInit) {
				t.Fatalf("hosts = %+v, error = %v", hosts, err)
			}
		})
	}
}

func TestBuildRejectsUnresolvedMicroVMBeforeRecord(t *testing.T) {
	spec := testSpec(harness.Codex)
	spec.MicroVM = true
	builds := 0
	docker := &fakeDocker{handler: func(args []string, input []byte) (string, int) {
		if args[0] == "image" && args[1] == "inspect" {
			return "", 1
		}
		if args[0] == "build" {
			builds++
			if builds == 1 {
				return "", 0
			}
			if !bytes.Contains(input, []byte("dc-resolver-check")) || !bytes.Contains(input, []byte("203.0.113.10 localhost")) {
				t.Fatal("the resolver build did not receive the exported hosts file")
			}
			return "MicroVM image localhost check failed", 1
		}
		if args[0] == "image" && args[1] == "rm" {
			return "", 0
		}
		t.Fatalf("unexpected docker call: %q", args)
		return "", 1
	}, exportedHosts: exportedHosts{present: true, typeflag: tar.TypeReg, data: []byte("203.0.113.10 localhost\n")}}
	store := testStore(t)
	b := &Builder{Docker: docker, Store: store}
	if _, err := b.Build(context.Background(), spec, BuildOptions{SkipHookFire: true}); err == nil {
		t.Fatal("build succeeded")
	}
	items, err := store.List()
	if err != nil || len(items) != 0 {
		t.Fatalf("failed build recorded an image: %+v, %v", items, err)
	}
	if builds != 2 || docker.count("image", "rm") == 0 {
		t.Fatalf("resolver build or cleanup did not run: builds %d, docker calls %v", builds, docker.calls)
	}
}
