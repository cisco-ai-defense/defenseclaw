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
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// npmPin pins one npm-distributed harness release: the registry integrity of
// its top-level package (npm then verifies the downloaded tarball against
// it) and the sha256 of the native executable the package installs, per
// Linux architecture. The native binary is what OpenShell pins by hash and
// what makes every model request, so a registry that served other bytes
// fails the image build.
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
	for arch, native := range p.Native {
		if !npmPathRE.MatchString(arch) || !npmPathRE.MatchString(native.Path) || strings.Contains(native.Path, "..") || !sha256HexRE.MatchString(native.SHA256) {
			return fmt.Errorf("harness: invalid %s native pin for %s", arch, p.Package)
		}
	}
	return nil
}

// installRun returns the RUN body that installs version of the pinned
// package into root (root-owned), links command onto /usr/local/bin and
// checks the registry integrity before and the native digest after the
// install. uninstallBase names a copy of the package the base image ships
// globally, removed first so it can never shadow the pin.
func (p npmPin) installRun(root, version, command, uninstallBase string) (string, error) {
	if err := p.validate(); err != nil {
		return "", err
	}
	if version != p.Version {
		return "", fmt.Errorf("harness: %s %s has no pinned digests (pinned %s)", p.Package, version, p.Version)
	}
	spec := p.Package + "@" + version
	var b strings.Builder
	b.WriteString("set -eu; root=" + shellQuote(root) + "; pkg=" + shellQuote(spec) + "; ")
	if uninstallBase != "" {
		b.WriteString("npm uninstall -g " + shellQuote(uninstallBase) + " >/dev/null 2>&1 || true; ")
	}
	b.WriteString(`got="$(npm view "$pkg" dist.integrity 2>/dev/null)"; `)
	b.WriteString(`[ "$got" = ` + shellQuote(p.Integrity) + ` ] || { echo "$pkg registry integrity '$got' is not the pinned one" >&2; exit 1; }; `)
	b.WriteString(`install -d -o root -g root -m 0755 "$root"; `)
	b.WriteString(`npm install -g --no-fund --no-audit --prefix "$root" "$pkg"; `)
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
