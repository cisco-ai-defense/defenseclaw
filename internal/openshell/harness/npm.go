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

package harness

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// npmPin pins one npm-distributed harness release: the registry integrity of
// its top-level package tarball and the sha256 of the native executable the
// package installs, per Linux architecture. The build downloads the tarball
// once, installs from that file only when its SHA-512 is the pinned
// integrity, and then requires the native executable's digest, so a
// registry that served other bytes for the package, or for the platform
// package that carries the executable, fails the image build. The native
// binary is what OpenShell pins by hash and what makes every model request.
type npmPin struct {
	// Package is the npm package name.
	Package string
	// Version is the exact release the digests below belong to.
	Version string
	// Integrity is the registry dist.integrity of Package@Version.
	Integrity string
	// Native maps `uname -m` to the installed executable (relative to the
	// install root) and its sha256.
	Native map[string]npmNative
}

// npmNative is one architecture's native executable.
type npmNative struct {
	Path   string
	SHA256 string
}

var (
	npmIntegrityRE = regexp.MustCompile(`^sha512-[A-Za-z0-9+/]{86}==$`)
	sha256HexRE    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	npmPathRE      = regexp.MustCompile(`^[A-Za-z0-9@._/-]+$`)
)

// validate refuses a pin that could not be rendered safely.
func (p npmPin) validate() error {
	if p.Package == "" || !npmPathRE.MatchString(p.Package) || !npmIntegrityRE.MatchString(p.Integrity) || len(p.Native) == 0 {
		return fmt.Errorf("harness: invalid npm pin for %q", p.Package)
	}
	if _, err := p.integritySHA512(); err != nil {
		return err
	}
	for arch, native := range p.Native {
		if !npmPathRE.MatchString(arch) || !npmPathRE.MatchString(native.Path) || strings.Contains(native.Path, "..") || !sha256HexRE.MatchString(native.SHA256) {
			return fmt.Errorf("harness: invalid %s native pin for %s", arch, p.Package)
		}
	}
	return nil
}

// integritySHA512 is the pinned integrity as the hex SHA-512 sha512sum
// prints.
func (p npmPin) integritySHA512() (string, error) {
	sum, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(p.Integrity, "sha512-"))
	if err != nil || len(sum) != sha512.Size {
		return "", fmt.Errorf("harness: npm pin for %q has a malformed integrity", p.Package)
	}
	return hex.EncodeToString(sum), nil
}

// installRun returns the RUN body that installs version of the pinned
// package into root (root-owned) and links command onto /usr/local/bin. It
// downloads the package tarball with `npm pack`, checks it against the
// pinned integrity, installs from that verified file (npm fetches only the
// dependencies from the registry) and checks the native digest after the
// install. uninstallBase names a copy of the package the base image ships
// globally, removed first so it can never shadow the pin.
func (p npmPin) installRun(root, version, command, uninstallBase string) (string, error) {
	if err := p.validate(); err != nil {
		return "", err
	}
	if version != p.Version {
		return "", fmt.Errorf("harness: %s %s has no pinned digests (pinned %s)", p.Package, version, p.Version)
	}
	sum, err := p.integritySHA512()
	if err != nil {
		return "", err
	}
	spec := p.Package + "@" + version
	var b strings.Builder
	b.WriteString("set -eu; root=" + shellQuote(root) + "; pkg=" + shellQuote(spec) + "; ")
	if uninstallBase != "" {
		b.WriteString("npm uninstall -g " + shellQuote(uninstallBase) + " >/dev/null 2>&1 || true; ")
	}
	b.WriteString(`tmp="$(mktemp -d)"; `)
	b.WriteString(`(cd "$tmp" && npm pack "$pkg" >/dev/null); `)
	b.WriteString(`n=0; for f in "$tmp"/*.tgz; do if [ -f "$f" ]; then tgz="$f"; n=$((n + 1)); fi; done; `)
	b.WriteString(`[ "$n" -eq 1 ] || { echo "npm pack $pkg left $n tarballs" >&2; exit 1; }; `)
	b.WriteString(`got="$(sha512sum "$tgz" | cut -d' ' -f1)"; `)
	b.WriteString(`[ "$got" = ` + shellQuote(sum) + ` ] || { echo "$pkg tarball sha512 $got is not the pinned integrity ` + p.Integrity + `" >&2; exit 1; }; `)
	b.WriteString(`install -d -o root -g root -m 0755 "$root"; `)
	b.WriteString(`npm install -g --no-fund --no-audit --prefix "$root" "$tgz"; `)
	b.WriteString(`rm -rf "$tmp"; `)
	b.WriteString(`case "$(uname -m)" in `)
	arches := make([]string, 0, len(p.Native))
	for arch := range p.Native {
		arches = append(arches, arch)
	}
	sort.Strings(arches)
	for _, arch := range arches {
		native := p.Native[arch]
		b.WriteString(arch + `) bin="$root/"` + shellQuote(native.Path) + `; want=` + shellQuote(native.SHA256) + ` ;; `)
	}
	b.WriteString(`*) echo "$pkg has no pinned native binary for $(uname -m)" >&2; exit 1 ;; esac; `)
	b.WriteString(`got="$(sha256sum "$bin" | cut -d' ' -f1)"; `)
	b.WriteString(`[ "$got" = "$want" ] || { echo "$pkg native binary $bin sha256 $got is not the pinned $want" >&2; exit 1; }; `)
	b.WriteString(`ln -sfn "$root/bin/` + command + `" /usr/local/bin/` + command)
	return b.String(), nil
}
