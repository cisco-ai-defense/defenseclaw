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
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
		"FROM dc-localhost-tool AS dc-resolver-check\n",
		"--network=none --mount=type=bind,from=dc-complete,source=/,target=/tmp/dc-root,ro",
		"/usr/sbin/chroot \"$root\" " + microVMResolverPath,
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
		{"dual stack with another IPv4 address", []byte("::1 localhost\n198.51.100.10 localhost\n"), true, false},
		{"IPv6-only mapping", []byte("::1 localhost\n"), true, true},
		{"IPv6-only other address", []byte("::2 localhost\n"), true, false},
		// Every family is judged: programs ask for both (round-3 review item 1).
		{"other IPv6 answer ahead of IPv4 loopback", []byte("::2 localhost\n127.0.0.1 localhost\n"), true, false},
		{"IPv4 loopback with other IPv6 address", []byte("127.0.0.1 localhost\n2001:db8::10 localhost\n"), true, false},
		{"alias after another name", []byte("127.0.0.1 localname localhost\n"), true, true},
		{"upper ASCII alias", []byte("127.0.0.1 LOCALHOST\n"), true, true},
		{"mixed ASCII alias", []byte("127.0.0.1 LocalHost\n"), true, true},
		{"tabs without final newline", []byte("127.0.0.1\tlocalhost"), true, true},
		{"CRLF mapping", []byte("127.0.0.1 localhost\r\n"), true, true},
		{"non ASCII full line comment", []byte("# caf\xc3\xa9\n127.0.0.1 localhost\n"), true, true},
		{"non ASCII inline comment", []byte("127.0.0.1 localhost # caf\xc3\xa9\n"), true, true},
		{"unrelated record", []byte("not a record\n127.0.0.1 localhost\n"), true, true},
		{"NUL after mapping", []byte("127.0.0.1 localhost\n\x00unrelated\n"), true, true},
		{"non ASCII unrelated alias", []byte("127.0.0.2 caf\xc3\xa9\n127.0.0.1 localhost\n"), true, true},
		{"long canonical alias", []byte("127.0.0.1 " + strings.Repeat(strings.Repeat("a", 60)+".", 3) + strings.Repeat("a", 60) + " localhost\n"), true, true},
		{"unmapped name", []byte("127.0.0.1 custom\n# reserved name absent\n"), true, false},
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
			layout := microVMResolverFixtureStage(t, dir) + "FROM " + openshell.DefaultBaseImage + " AS dc-complete\n"
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

func TestMicroVMResolverCallerLocation(t *testing.T) {
	localDocker(t)
	for _, tc := range []struct {
		name, change string
		want         bool
	}{
		{"ordinary directory", "", true},
		{"existing caller link", "RUN mkdir -p /usr/local/lib/defenseclaw && ln -s /sandbox/locator " + microVMResolverPath + "\n", false},
		{"linked parent", "RUN ln -s /sandbox/callers /usr/local/lib/defenseclaw\n", false},
		{"writable parent", "RUN mkdir -p /usr/local/lib/defenseclaw && chmod 0777 /usr/local/lib/defenseclaw\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			layout := microVMResolverFixtureStage(t, dir) + "FROM " + openshell.DefaultBaseImage + "\nUSER root\n" +
				tc.change + microVMResolverCopyStep() + "USER sandbox\n"
			if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(layout), 0o600); err != nil {
				t.Fatal(err)
			}
			tag := testImageTag(dir)
			t.Cleanup(func() { exec.Command("docker", "image", "rm", "-f", tag).Run() })
			out, err := dockerCommand(t, "build", "--pull=false", "--progress=plain", "-t", tag, dir).CombinedOutput()
			if (err == nil) != tc.want {
				t.Fatalf("build success = %t, want %t: %v\n%s", err == nil, tc.want, err, out)
			}
			if err != nil && !bytes.Contains(out, []byte("resolver caller location")) {
				t.Fatalf("build did not identify the caller location: %s", out)
			}
		})
	}
}

// An NSS module is image code that can answer DefenseClaw's caller unlike
// every other program (osmin23c review 1), so a MicroVM image may resolve
// hosts only with libc's files and dns sources: a local NSS source is
// refused even when it answers loopback, and the IPv4-only loopback mapping
// with the stock NSS configuration passes.
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
		name, hosts, nss string
		want             bool
	}{
		{"custom file without local source", "127.0.0.1 custom\n", "", false},
		{"IPv4-only loopback with the stock NSS configuration", "127.0.0.1 localhost\n", "", true},
		{"custom file with local source", "127.0.0.1 custom\n", "localtest", false},
		{"IPv6 hosts with local source", "::1 localhost\n", "localtest", false},
		{"IPv6 hosts and other IPv4 with local source", "::1 localhost\n203.0.113.10 localhost\n", "localtest", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "hosts"), []byte(tc.hosts), 0o600); err != nil {
				t.Fatal(err)
			}
			layout := microVMResolverFixtureStage(t, dir) + "FROM " + openshell.DefaultBaseImage + " AS dc-complete\nUSER root\nCOPY hosts /etc/hosts\n"
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
			if err != nil && !bytes.Contains(out, []byte("MicroVM image localhost check failed")) {
				t.Fatalf("build failed before the localhost check: %s", out)
			}
		})
	}
}

// nssFamilySource is an NSS module that answers localhost per query kind:
// gethostbyname4_r (what getaddrinfo uses for AF_UNSPEC) with UNSPEC_ADDR
// and gethostbyname2_r for AF_INET with 127.0.0.1.
const nssFamilySource = `#include <nss.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
enum nss_status _nss_familytest_gethostbyname4_r(const char *name, struct gaih_addrtuple **pat, char *buffer, size_t buflen, int *errnop, int *herrnop, int32_t *ttlp) {
    (void)ttlp;
    if (strcasecmp(name, "localhost") != 0) {
        *herrnop = HOST_NOT_FOUND;
        return NSS_STATUS_NOTFOUND;
    }
    uintptr_t p = ((uintptr_t)buffer + sizeof(void *) - 1) & ~(sizeof(void *) - 1);
    if (p + sizeof(struct gaih_addrtuple) + 10 > (uintptr_t)buffer + buflen) {
        *errnop = ERANGE;
        *herrnop = NETDB_INTERNAL;
        return NSS_STATUS_TRYAGAIN;
    }
    struct gaih_addrtuple *t = *pat;
    if (t == NULL) {
        t = (struct gaih_addrtuple *)p;
        p += sizeof(struct gaih_addrtuple);
        *pat = t;
    }
    char *canonical = (char *)p;
    memcpy(canonical, "localhost", 10);
    memset(t, 0, sizeof *t);
    t->name = canonical;
    t->family = AF_INET;
    inet_pton(AF_INET, "UNSPEC_ADDR", t->addr);
    return NSS_STATUS_SUCCESS;
}
enum nss_status _nss_familytest_gethostbyname2_r(const char *name, int af, struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop) {
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

// An image resolver that answers the IPv4 query with loopback and the
// unspec query (what programs ask by default) with another address is
// refused (round-3 review item 2, family-dependent resolver), and so is the
// same module answering loopback to both: no NSS module answers a MicroVM's
// host lookups (osmin23c review 1).
func TestMicroVMResolverFamilyDependentNSSSource(t *testing.T) {
	localDocker(t)
	for _, tc := range []struct {
		name, unspec string
		want         bool
	}{
		{"unspec query gets another address", "203.0.113.10", false},
		{"unspec query gets loopback", "127.0.0.1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "hosts"), []byte("127.0.0.1 custom\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "familytest.c"), []byte(strings.Replace(nssFamilySource, "UNSPEC_ADDR", tc.unspec, 1)), 0o600); err != nil {
				t.Fatal(err)
			}
			layout := microVMResolverFixtureStage(t, dir) + "FROM " + openshell.DefaultBaseImage + " AS dc-complete\nUSER root\nCOPY hosts /etc/hosts\n" +
				"COPY familytest.c /tmp/familytest.c\nRUN gcc -shared -fPIC -o /usr/lib/$(gcc -dumpmachine)/libnss_familytest.so.2 /tmp/familytest.c && sed -i 's/^hosts:.*/hosts: files familytest/' /etc/nsswitch.conf\n" +
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
			if err != nil && !bytes.Contains(out, []byte("MicroVM image localhost check failed")) {
				t.Fatalf("build failed before the localhost check: %s", out)
			}
		})
	}
}

// reviewerNSSSource is the osmin23c review-1 reproduction: an NSS module
// that answers the program named localhost-resolver with 127.0.0.1 and every
// other program with 203.0.113.10, for both lookup kinds.
const reviewerNSSSource = `#include <nss.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
extern char *program_invocation_short_name;
enum nss_status _nss_familytest_gethostbyname4_r(const char *name, struct gaih_addrtuple **pat, char *buffer, size_t buflen, int *errnop, int *herrnop, int32_t *ttlp) {
    (void)ttlp;
    if (strcasecmp(name, "localhost") != 0) {
        *herrnop = HOST_NOT_FOUND;
        return NSS_STATUS_NOTFOUND;
    }
    uintptr_t p = ((uintptr_t)buffer + sizeof(void *) - 1) & ~(sizeof(void *) - 1);
    if (p + sizeof(struct gaih_addrtuple) + 10 > (uintptr_t)buffer + buflen) {
        *errnop = ERANGE;
        *herrnop = NETDB_INTERNAL;
        return NSS_STATUS_TRYAGAIN;
    }
    struct gaih_addrtuple *t = *pat;
    if (t == NULL) {
        t = (struct gaih_addrtuple *)p;
        p += sizeof(struct gaih_addrtuple);
        *pat = t;
    }
    char *canonical = (char *)p;
    memcpy(canonical, "localhost", 10);
    memset(t, 0, sizeof *t);
    t->name = canonical;
    t->family = AF_INET;
    inet_pton(AF_INET, program_invocation_short_name && strstr(program_invocation_short_name, "localhost-resolver") ? "127.0.0.1" : "203.0.113.10", t->addr);
    return NSS_STATUS_SUCCESS;
}
enum nss_status _nss_familytest_gethostbyname2_r(const char *name, int af, struct hostent *result, char *buffer, size_t buflen, int *errnop, int *h_errnop) {
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
    address[0] = program_invocation_short_name && strstr(program_invocation_short_name, "localhost-resolver") ? 127 : 203; address[1] = 0; address[2] = program_invocation_short_name && strstr(program_invocation_short_name, "localhost-resolver") ? 0 : 113; address[3] = program_invocation_short_name && strstr(program_invocation_short_name, "localhost-resolver") ? 1 : 10;
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

// The osmin23c review-1 reproduction: an image with an empty hosts file (the
// guest fills it), no preload, and hosts answered only by a module that
// gives the caller loopback and applications another address. The export
// check names the source, and the caller in the completed image refuses it
// while an application there gets the other address. Its twin with the
// stock NSS configuration passes both.
func TestMicroVMResolverReviewerNSSReproduction(t *testing.T) {
	localDocker(t)
	for _, tc := range []struct {
		name   string
		module bool
	}{
		{"module answers the caller alone with loopback", true},
		{"stock NSS configuration", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "hosts"), nil, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "familytest.c"), []byte(reviewerNSSSource), 0o644); err != nil {
				t.Fatal(err)
			}
			layout := microVMResolverFixtureStage(t, dir) + "FROM " + openshell.DefaultBaseImage + " AS dc-complete\nUSER root\nCOPY hosts /etc/hosts\n" +
				"COPY familytest.c /tmp/familytest.c\nRUN gcc -shared -fPIC -o /usr/lib/$(gcc -dumpmachine)/libnss_familytest.so.2 /tmp/familytest.c\n"
			if tc.module {
				layout += "RUN sed -i 's/^hosts:.*/hosts: familytest/' /etc/nsswitch.conf\n"
			}
			layout += microVMResolverCopyStep() + "USER sandbox\n"
			if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(layout), 0o600); err != nil {
				t.Fatal(err)
			}
			tag := testImageTag(dir)
			t.Cleanup(func() { exec.Command("docker", "image", "rm", "-f", tag).Run() })
			if out, err := dockerCommand(t, "build", "--pull=false", "--progress=plain", "-t", tag, dir).CombinedOutput(); err != nil {
				t.Fatalf("build the completed image: %v\n%s", err, out)
			}
			exported, err := (&Builder{Docker: CLI{}}).exportHosts(t.Context(), tag)
			if err != nil || !exported.initializedByGuest() || exported.preload != "" {
				t.Fatalf("export = %+v, %v", exported, err)
			}
			if want := map[bool]string{true: `names the hosts source "familytest"`, false: ""}[tc.module]; exported.nss != want {
				t.Fatalf("export nss = %q, want %q", exported.nss, want)
			}
			caller, err := dockerCommand(t, "run", "--rm", "--network=none", "--entrypoint", microVMResolverPath, tag).Output()
			app, appErr := dockerCommand(t, "run", "--rm", "--network=none", "--entrypoint", "/usr/bin/python3", tag, "-c",
				`import socket; print(socket.getaddrinfo("localhost", None, family=socket.AF_INET, type=socket.SOCK_STREAM)[0][4][0])`).Output()
			if appErr != nil {
				t.Fatalf("application lookup: %v", appErr)
			}
			if tc.module {
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 || string(caller) != "refused nss\n" {
					t.Fatalf("caller = %q, %v; want \"refused nss\"", caller, err)
				}
				if strings.TrimSpace(string(app)) != "203.0.113.10" {
					t.Fatalf("the reproduction's application got %q, not the module's other address", app)
				}
				return
			}
			if err != nil || !strings.HasSuffix(string(caller), "loopback-only\n") || strings.TrimSpace(string(app)) != "127.0.0.1" {
				t.Fatalf("stock twin: caller %q (%v), application %q", caller, err, app)
			}
		})
	}
}

// preloadSource interposes getaddrinfo for localhost: FAKE_CONDITION picks
// the queries that get 203.0.113.10, every other one gets loopback.
const preloadSource = `#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
extern char *program_invocation_short_name;
int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
    if (node && strcmp(node, "localhost") == 0) {
        struct addrinfo *ai = calloc(1, sizeof *ai);
        struct sockaddr_in *addr = calloc(1, sizeof *addr);
        if (!ai || !addr) { free(ai); free(addr); return EAI_MEMORY; }
        addr->sin_family = AF_INET;
        inet_pton(AF_INET, (FAKE_CONDITION) ? "203.0.113.10" : "127.0.0.1", &addr->sin_addr);
        ai->ai_family = AF_INET;
        ai->ai_socktype = SOCK_STREAM;
        ai->ai_addrlen = sizeof *addr;
        ai->ai_addr = (struct sockaddr *)addr;
        *res = ai;
        return 0;
    }
    int (*real)(const char *, const char *, const struct addrinfo *, struct addrinfo **) = dlsym(RTLD_NEXT, "getaddrinfo");
    return real(node, service, hints, res);
}
`

// Code an image preloads into every program (/etc/ld.so.preload) can answer
// DefenseClaw's caller unlike every other program: by the caller's name or
// by the query's family (round-3 review item 2). No probe can show what the
// harness gets, so such an image is refused, also when its preload answers
// loopback to everyone; the same image without the preload is accepted.
func TestMicroVMResolverRefusesPreloadedCode(t *testing.T) {
	localDocker(t)
	for _, tc := range []struct {
		name, condition string
		preload, want   bool
	}{
		{"preload answers only the caller with loopback", `strstr(program_invocation_short_name, "localhost-resolver") == NULL`, true, false},
		{"preload answers only the IPv4 query with loopback", `!hints || hints->ai_family != AF_INET`, true, false},
		{"preload answers loopback to everyone", "0", true, false},
		{"same image without the preload", "0", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "hosts"), []byte("127.0.0.1 localhost\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "libfake.c"), []byte(strings.Replace(preloadSource, "FAKE_CONDITION", tc.condition, 1)), 0o600); err != nil {
				t.Fatal(err)
			}
			layout := microVMResolverFixtureStage(t, dir) + "FROM " + openshell.DefaultBaseImage + " AS dc-complete\nUSER root\nCOPY hosts /etc/hosts\n" +
				"COPY libfake.c /tmp/libfake.c\nRUN gcc -shared -fPIC -o /usr/local/lib/libfake.so /tmp/libfake.c -ldl\n"
			if tc.preload {
				layout += "RUN printf '/usr/local/lib/libfake.so\\n' > /etc/ld.so.preload\n"
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
				t.Fatalf("build failed before the localhost check: %s", out)
			}
		})
	}
}

// The caller itself refuses to report while anything but the program, the
// vDSO, libc and the loader is mapped into it: a preload that answers only
// the caller with loopback cannot make it pass. Runs without Docker where a
// C compiler is on PATH (Linux).
func TestLocalhostResolverRefusesPreloadedCode(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the caller is a Linux program")
	}
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("no C compiler")
	}
	dir := t.TempDir()
	caller, lib := filepath.Join(dir, "localhost-resolver"), filepath.Join(dir, "libfake.so")
	if err := os.WriteFile(filepath.Join(dir, "resolver.c"), microVMResolverSource, 0o600); err != nil {
		t.Fatal(err)
	}
	fake := strings.Replace(preloadSource, "FAKE_CONDITION", `strstr(program_invocation_short_name, "localhost-resolver") == NULL`, 1)
	if err := os.WriteFile(filepath.Join(dir, "libfake.c"), []byte(fake), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"-O2", "-Wall", "-Wextra", "-Werror", "-o", caller, filepath.Join(dir, "resolver.c")},
		{"-shared", "-fPIC", "-o", lib, filepath.Join(dir, "libfake.c"), "-ldl"},
	} {
		if out, err := exec.CommandContext(t.Context(), cc, args...).CombinedOutput(); err != nil {
			t.Fatalf("cc %q: %v\n%s", args, err, out)
		}
	}
	plain := exec.CommandContext(t.Context(), caller)
	plain.Env = []string{}
	out, _ := plain.Output()
	if strings.Contains(string(out), "refused preload") {
		t.Fatalf("the caller refused a process without preloaded code: %q", out)
	}
	preloaded := exec.CommandContext(t.Context(), caller)
	preloaded.Env = []string{"LD_PRELOAD=" + lib}
	out, err = preloaded.Output()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 || string(out) != "refused preload\n" {
		t.Fatalf("preloaded caller = %q, %v; want \"refused preload\" and exit status 1", out, err)
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
			layout := microVMResolverFixtureStage(t, dir) + "FROM " + openshell.DefaultBaseImage + " AS dc-complete\nUSER root\n" +
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
			layout := microVMResolverFixtureStage(t, dir) + "FROM " + openshell.DefaultBaseImage + " AS dc-complete\nUSER root\n" +
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

func TestMicroVMResolverUsesPinnedCheckTools(t *testing.T) {
	localDocker(t)
	for _, tc := range []struct {
		name, toolPath, toolBody, hosts string
		want                            bool
	}{
		{"timeout with other address", "/usr/bin/timeout", "#!/bin/sh\nprintf '127.0.0.1 STREAM\\n'\n", "203.0.113.10 localhost\n", false},
		{"timeout with loopback", "/usr/bin/timeout", "#!/bin/sh\nprintf '203.0.113.10 STREAM\\n'\n", "127.0.0.1 localhost\n", true},
		{"chroot with other address", "/usr/sbin/chroot", "#!/bin/sh\nprintf '127.0.0.1 STREAM\\n'\n", "203.0.113.10 localhost\n", false},
		{"chroot with loopback", "/usr/sbin/chroot", "#!/bin/sh\nprintf '203.0.113.10 STREAM\\n'\n", "127.0.0.1 localhost\n", true},
		{"awk with other address", "/usr/bin/awk", "#!/bin/sh\nexit 0\n", "203.0.113.10 localhost\n", false},
		{"awk with loopback", "/usr/bin/awk", "#!/bin/sh\nexit 1\n", "127.0.0.1 localhost\n", true},
		{"NUL in alias", "/usr/bin/timeout", "#!/bin/sh\nprintf '127.0.0.1 STREAM\\n'\n", "127.0.0.1 localho\x00st\n", false},
		{"non ASCII alias", "/usr/bin/timeout", "#!/bin/sh\nprintf '127.0.0.1 STREAM\\n'\n", "127.0.0.1 localh\u043est\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "hosts"), []byte(tc.hosts), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "custom-tool"), []byte(tc.toolBody), 0o755); err != nil {
				t.Fatal(err)
			}
			layout := microVMResolverFixtureStage(t, dir) + "FROM " + openshell.DefaultBaseImage + " AS dc-complete\nUSER root\n" +
				"COPY hosts /etc/hosts\n" + microVMResolverCopyStep() +
				"COPY --chmod=0755 custom-tool " + tc.toolPath + "\n" + microVMResolverStep(openshell.DefaultBaseImage)
			if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(layout), 0o600); err != nil {
				t.Fatal(err)
			}
			tag := testImageTag(dir)
			t.Cleanup(func() { exec.Command("docker", "image", "rm", "-f", tag).Run() })
			out, err := dockerCommand(t, "build", "--pull=false", "--progress=plain", "-t", tag, dir).CombinedOutput()
			if (err == nil) != tc.want {
				t.Fatalf("image check success = %t, want %t: %v\n%s", err == nil, tc.want, err, out)
			}
			if err != nil && !bytes.Contains(out, []byte("MicroVM image localhost check failed")) {
				t.Fatalf("image check did not name the resolver: %s", out)
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
			layout := microVMResolverFixtureStage(t, dir) + "FROM " + openshell.DefaultBaseImage + " AS dc-complete\nADD hosts.tar /\n" +
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
			layout := microVMResolverFixtureStage(t, dir) + "FROM " + openshell.DefaultBaseImage + " AS dc-complete\nCOPY hosts /etc/hosts\n" +
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
	// World-readable: the base's sandbox user copies it in the mounted stage.
	if err := os.WriteFile(filepath.Join(dir, "hosts"), []byte(authored), 0o644); err != nil {
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

func microVMResolverFixtureStage(t *testing.T, dir string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "localhost-resolver.c"), microVMResolverSource, 0o600); err != nil {
		t.Fatal(err)
	}
	return microVMResolverToolStage()
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

// The export's /etc/ld.so.preload is judged by DefenseClaw, not by image
// tools: one that names a library, or that is not a regular file, refuses
// the image; an absent one, or one with only separators, does not.
func TestMicroVMExportedPreloadClassification(t *testing.T) {
	for _, tc := range []struct {
		name     string
		typeflag byte
		data     string
		want     string
	}{
		{"absent", 0, "", ""},
		{"empty", tar.TypeReg, "", ""},
		{"separators only", tar.TypeReg, " \n\t:\r\n", ""},
		{"a library", tar.TypeReg, "/usr/local/lib/libfake.so\n", "names a library to load"},
		{"a symlink", tar.TypeSymlink, "", "is not a regular file"},
		{"a directory", tar.TypeDir, "", "is not a regular file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var data bytes.Buffer
			tw := tar.NewWriter(&data)
			if tc.typeflag != 0 {
				h := &tar.Header{Name: "etc/ld.so.preload", Typeflag: tc.typeflag, Mode: 0o644, Size: int64(len(tc.data))}
				if tc.typeflag == tar.TypeSymlink {
					h.Linkname, h.Size = "/sandbox/preload", 0
				}
				if tc.typeflag == tar.TypeDir {
					h.Size = 0
				}
				if err := tw.WriteHeader(h); err != nil {
					t.Fatal(err)
				}
				if h.Size > 0 {
					if _, err := tw.Write([]byte(tc.data)); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := tw.Close(); err != nil {
				t.Fatal(err)
			}
			hosts, err := parseExportedHosts(&data)
			if err != nil || hosts.preload != tc.want {
				t.Fatalf("preload = %q, error %v, want %q", hosts.preload, err, tc.want)
			}
		})
	}
	var twice bytes.Buffer
	tw := tar.NewWriter(&twice)
	for range 2 {
		if err := tw.WriteHeader(&tar.Header{Name: "etc/ld.so.preload", Typeflag: tar.TypeReg, Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := parseExportedHosts(&twice); err == nil {
		t.Fatal("an export with two /etc/ld.so.preload entries was read")
	}
}

// hostsSourcesProblem reads nsswitch.conf as glibc 2.39 does (each row's
// glibc result was probed on the pinned base with a fake DNS server; see
// IN-r108-osmin23c.md): the effective hosts line must ask files first and at
// most dns after it, with only return actions, so neither a module nor DNS
// can answer localhost besides /etc/hosts (osmin23c reviews 1 to 3).
func TestMicroVMExportedNSSClassification(t *testing.T) {
	const fallback = "does not ask files first and at most dns after it on its hosts line"
	for _, tc := range []struct {
		name, data, want string
	}{
		{"stock", "passwd: files\nhosts:          files dns\nnetworks: files\n", ""},
		{"files only", "hosts: files\n", ""},
		{"return actions", "hosts: files [NOTFOUND=return] dns [!UNAVAIL=return]\n", ""},
		{"return action in other case", "hosts: files [notfound=RETURN] dns\n", ""},
		{"action glued to the sources", "hosts: files[NOTFOUND=return]dns\n", ""},
		{"full-line comment and CRLF", "# hosts: dns\r\nhosts: files dns\r\n", ""},
		{"indented comment line", "   #hosts: dns files\nhosts: files dns\n", ""},
		{"other databases may use modules", "passwd: files systemd\nhosts: files dns\n", ""},
		{"no hosts line: glibc's files dns default", "passwd: files\n", ""},
		{"upper-case database is another database", "HOSTS: dns\n", ""},
		{"no colon", "hosts files dns\n", ""},
		{"colons and spaces", "hosts : :files dns\n", ""},
		{"last hosts line wins", "hosts: dns files\nhosts: files dns\n", ""},
		{"last hosts line asks DNS first", "hosts: files dns\nhosts: dns files\n", fallback},
		{"hash glued to files", "hosts: files#x dns\n", `names the hosts source "files#x"`},
		{"hash after the sources is a source", "hosts: files dns # mdns\n", `names the hosts source "#"`},
		{"hash before the sources", "hosts: #c dns files\n", `names the hosts source "#c"`},
		{"files spelled in capitals", "hosts: Files dns\n", `names the hosts source "Files"`},
		{"empty hosts line", "hosts:\n", fallback},
		{"DNS first", "hosts: dns files\n", fallback},
		{"DNS first without a colon", "hosts dns files\n", fallback},
		{"DNS only", "hosts: dns\n", fallback},
		{"files twice", "hosts: files files\n", fallback},
		{"DNS continues after files", "hosts: files [SUCCESS=continue] dns\n", `has the hosts action "[SUCCESS=continue]", which can let DNS answer after /etc/hosts`},
		{"continue in lower case", "hosts: files [success=continue] dns\n", `has the hosts action "[success=continue]", which can let DNS answer after /etc/hosts`},
		{"merge", "hosts: files [SUCCESS=merge] dns\n", `has the hosts action "[SUCCESS=merge]", which can let DNS answer after /etc/hosts`},
		{"continue after dns", "hosts: files dns [NOTFOUND=continue]\n", `has the hosts action "[NOTFOUND=continue]", which can let DNS answer after /etc/hosts`},
		{"action before files", "hosts: [NOTFOUND=return] files dns\n", "has a hosts action it cannot read"},
		{"unknown status", "hosts: files [FOUND=return] dns\n", "has a hosts action it cannot read"},
		{"local module", "hosts: files localtest\n", `names the hosts source "localtest"`},
		{"module only", "hosts: familytest\n", `names the hosts source "familytest"`},
		{"myhostname", "hosts: files myhostname dns\n", `names the hosts source "myhostname"`},
		{"space before the colon", "hosts : familytest\n", `names the hosts source "familytest"`},
		{"module glued to an action", "hosts: files [NOTFOUND=return]familytest\n", `names the hosts source "familytest"`},
		{"unterminated action", "hosts: files [NOTFOUND=return dns\n", "has a hosts action it cannot read"},
		{"odd action", "hosts: files [NOTFOUND=/x] dns\n", `has the hosts action "[NOTFOUND=/x]", which can let DNS answer after /etc/hosts`},
		{"long line", "hosts: files " + strings.Repeat(" ", 5000) + "dns\n", "has a line too long to check"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := hostsSourcesProblem([]byte(tc.data)); got != tc.want {
				t.Fatalf("hostsSourcesProblem(%q) = %q, want %q", tc.data, got, tc.want)
			}
		})
	}
	exported := func(entries ...*tar.Header) exportedHosts {
		t.Helper()
		var data bytes.Buffer
		tw := tar.NewWriter(&data)
		for _, h := range entries {
			if err := tw.WriteHeader(h); err != nil {
				t.Fatal(err)
			}
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		hosts, err := parseExportedHosts(&data)
		if err != nil {
			t.Fatal(err)
		}
		return hosts
	}
	if hosts := exported(&tar.Header{Name: "etc/nsswitch.conf", Typeflag: tar.TypeSymlink, Linkname: "/sandbox/nsswitch.conf", Mode: 0o777}); hosts.nss != "is not a regular file" {
		t.Fatalf("linked nsswitch.conf = %q", hosts.nss)
	}
	if hosts := exported(); hosts.nss != "" {
		t.Fatalf("missing nsswitch.conf (glibc's files dns default) = %q", hosts.nss)
	}
	if hosts := exported(&tar.Header{Name: "etc/resolv.conf", Typeflag: tar.TypeSymlink, Linkname: "/sandbox/resolv.conf", Mode: 0o777}); hosts.resolv != "is not a regular file" {
		t.Fatalf("linked resolv.conf = %q", hosts.resolv)
	}
	if hosts := exported(&tar.Header{Name: "etc/resolv.conf", Typeflag: tar.TypeReg, Mode: 0o644}); hosts.resolv != "" {
		t.Fatalf("regular resolv.conf = %q", hosts.resolv)
	}
}

// The osmin23c review-2 and review-3 forms (DNS before /etc/hosts, DNS
// continuing after a successful /etc/hosts lookup, files#x, which glibc
// does not read as files) are refused by the export check and by the caller
// in the completed image; the stock, return-action and missing-file twins
// (glibc 2.39's default is files dns) pass both.
func TestMicroVMResolverRefusesDNSBesideFiles(t *testing.T) {
	localDocker(t)
	for _, tc := range []struct {
		name, change string
		want         bool
	}{
		{"DNS continues after a successful files lookup", "RUN sed -i 's/^hosts:.*/hosts: files [SUCCESS=continue] dns/' /etc/nsswitch.conf\n", false},
		{"DNS first", "RUN sed -i 's/^hosts:.*/hosts: dns files/' /etc/nsswitch.conf\n", false},
		{"source glued to a hash", "RUN sed -i 's/^hosts:.*/hosts: files#x dns/' /etc/nsswitch.conf\n", false},
		{"no nsswitch.conf: glibc's files dns default", "RUN rm /etc/nsswitch.conf\n", true},
		{"stock files dns", "", true},
		{"return action", "RUN sed -i 's/^hosts:.*/hosts: files [NOTFOUND=return] dns/' /etc/nsswitch.conf\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			layout := microVMResolverFixtureStage(t, dir) + "FROM " + openshell.DefaultBaseImage + " AS dc-complete\nUSER root\n" +
				tc.change + microVMResolverCopyStep() + "USER sandbox\n"
			if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(layout), 0o600); err != nil {
				t.Fatal(err)
			}
			tag := testImageTag(dir)
			t.Cleanup(func() { exec.Command("docker", "image", "rm", "-f", tag).Run() })
			if out, err := dockerCommand(t, "build", "--pull=false", "--progress=plain", "-t", tag, dir).CombinedOutput(); err != nil {
				t.Fatalf("build the completed image: %v\n%s", err, out)
			}
			exported, err := (&Builder{Docker: CLI{}}).exportHosts(t.Context(), tag)
			if err != nil || (exported.nss == "") != tc.want || exported.resolv != "" {
				t.Fatalf("export nss = %q, resolv = %q, error %v; want accepted %t", exported.nss, exported.resolv, err, tc.want)
			}
			caller, err := dockerCommand(t, "run", "--rm", "--network=none", "--entrypoint", microVMResolverPath, tag).Output()
			if tc.want {
				if err != nil || !strings.HasSuffix(string(caller), "loopback-only\n") {
					t.Fatalf("caller = %q, %v", caller, err)
				}
				return
			}
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 || string(caller) != "refused nss\n" {
				t.Fatalf("caller = %q, %v; want \"refused nss\"", caller, err)
			}
		})
	}
}

// The osmin23c review-1 image (an empty hosts file, hosts answered only by
// a module) and the review-2 DNS forms are refused before any resolver
// build and before a record, with the repair; the stock twin records.
func TestBuildRejectsCustomNSSMicroVMBeforeRecord(t *testing.T) {
	for _, tc := range []struct {
		name     string
		nsswitch []byte
		reason   string // "" records
	}{
		{"module answers hosts", []byte("hosts: familytest\n"), `names the hosts source "familytest"`},
		{"DNS continues after files", []byte("hosts: files [SUCCESS=continue] dns\n"), `has the hosts action "[SUCCESS=continue]"`},
		{"DNS first", []byte("hosts: dns files\n"), "does not ask files first"},
		{"source glued to a hash", []byte("hosts: files#x dns\n"), `names the hosts source "files#x"`},
		{"no nsswitch.conf: glibc's files dns default", nil, ""},
		{"stock NSS configuration", []byte("hosts: files dns\n"), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := testSpec(harness.Codex)
			spec.MicroVM = true
			c := mustContext(t, spec)
			docker := imageDocker(t, c, goodProbeOutput(c))
			docker.exportedHosts = exportedHosts{present: true, typeflag: tar.TypeReg}
			docker.exportedFiles = map[string][]byte{"etc/nsswitch.conf": tc.nsswitch}
			store := testStore(t)
			_, err := (&Builder{Docker: docker, Store: store}).Build(t.Context(), spec, BuildOptions{SkipHookFire: true})
			want := tc.reason == ""
			if (err == nil) != want {
				t.Fatalf("build error = %v, want success %t", err, want)
			}
			if err != nil && (!strings.Contains(err.Error(), tc.reason) || !strings.Contains(err.Error(), "`hosts: files dns`")) {
				t.Fatalf("refusal does not name the cause and the repair: %v", err)
			}
			items, listErr := store.List()
			if listErr != nil || (len(items) == 0) == want {
				t.Fatalf("records = %+v, %v", items, listErr)
			}
		})
	}
}

// A MicroVM image whose export preloads a library is refused before any
// resolver build and before a record, also when its hosts file is empty
// (the guest initializes that one); its twin without the preload records.
func TestBuildRejectsPreloadingMicroVMBeforeRecord(t *testing.T) {
	for _, tc := range []struct {
		name    string
		preload string
		want    bool
	}{
		{"preloaded library", "/usr/local/lib/libfake.so\n", false},
		{"empty preload file", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := testSpec(harness.Codex)
			spec.MicroVM = true
			c := mustContext(t, spec)
			docker := imageDocker(t, c, goodProbeOutput(c))
			docker.exportedHosts = exportedHosts{present: true, typeflag: tar.TypeReg}
			docker.exportedFiles = map[string][]byte{"etc/ld.so.preload": []byte(tc.preload)}
			store := testStore(t)
			_, err := (&Builder{Docker: docker, Store: store}).Build(t.Context(), spec, BuildOptions{SkipHookFire: true})
			if (err == nil) != tc.want {
				t.Fatalf("build error = %v, want success %t", err, tc.want)
			}
			if err != nil && !strings.Contains(err.Error(), "/etc/ld.so.preload names a library to load") {
				t.Fatalf("refusal does not name the preload: %v", err)
			}
			items, listErr := store.List()
			if listErr != nil || (len(items) == 0) == tc.want {
				t.Fatalf("records = %+v, %v", items, listErr)
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
