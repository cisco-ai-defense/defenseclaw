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
	"strconv"
	"strings"
)

// tarballPin pins one vendor-hosted release archive per Linux architecture:
// the https download and its sha256. The build downloads the archive the
// vendor's own installer would fetch, refuses any other bytes, and unpacks it
// into the harness's root-owned prefix instead of the installer's $HOME
// location.
type tarballPin struct {
	// Version is the exact release the archives belong to.
	Version string
	// Archives maps `uname -m` to the archive.
	Archives map[string]tarballArchive
	// Strip is the number of leading path components the archive's entries
	// carry above the install root (tar --strip-components).
	Strip int
	// DigestSource says where the digests come from: the vendor's release
	// manifest, or DefenseClaw's own download when the vendor publishes none.
	DigestSource string
}

// tarballArchive is one architecture's release archive.
type tarballArchive struct {
	URL    string
	SHA256 string
}

var (
	tarballURLRE     = regexp.MustCompile(`^https://[a-z0-9.-]+/[A-Za-z0-9._/%-]+\.tar\.gz$`)
	tarballVersionRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$`)
)

// validate refuses a pin that could not be rendered safely.
func (p tarballPin) validate() error {
	if !tarballVersionRE.MatchString(p.Version) || len(p.Archives) == 0 || p.Strip < 0 || p.Strip > 4 {
		return fmt.Errorf("harness: invalid archive pin %q", p.Version)
	}
	if strings.TrimSpace(p.DigestSource) == "" {
		return fmt.Errorf("harness: archive pin %s does not say where its digests come from", p.Version)
	}
	for arch, archive := range p.Archives {
		if !npmPathRE.MatchString(arch) || !tarballURLRE.MatchString(archive.URL) || !sha256HexRE.MatchString(archive.SHA256) {
			return fmt.Errorf("harness: invalid %s archive pin for %s", arch, p.Version)
		}
		if !strings.Contains(archive.URL, p.Version) {
			return fmt.Errorf("harness: %s archive %s does not name release %s", arch, archive.URL, p.Version)
		}
	}
	return nil
}

// installRun returns the RUN body that downloads the archive for the build
// architecture, checks its sha256, and unpacks it into root, owned by root
// and not writable by anyone else.
func (p tarballPin) installRun(root, version string) (string, error) {
	if err := p.validate(); err != nil {
		return "", err
	}
	if version != p.Version {
		return "", fmt.Errorf("harness: release %s has no pinned archive digests (pinned %s)", version, p.Version)
	}
	var b strings.Builder
	b.WriteString("set -eu; root=" + shellQuote(root) + "; ")
	b.WriteString(`case "$(uname -m)" in `)
	arches := make([]string, 0, len(p.Archives))
	for arch := range p.Archives {
		arches = append(arches, arch)
	}
	sort.Strings(arches)
	for _, arch := range arches {
		archive := p.Archives[arch]
		b.WriteString(arch + `) url=` + shellQuote(archive.URL) + `; want=` + shellQuote(archive.SHA256) + ` ;; `)
	}
	b.WriteString(`*) echo "release ` + p.Version + ` has no pinned archive for $(uname -m)" >&2; exit 1 ;; esac; `)
	b.WriteString(`tmp="$(mktemp -d)"; `)
	b.WriteString(`curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$tmp/release.tar.gz" "$url"; `)
	b.WriteString(`got="$(sha256sum "$tmp/release.tar.gz" | cut -d' ' -f1)"; `)
	b.WriteString(`[ "$got" = "$want" ] || { echo "$url sha256 $got is not the pinned $want" >&2; exit 1; }; `)
	b.WriteString(`install -d -o root -g root -m 0755 "$root"; `)
	b.WriteString(`tar -xzf "$tmp/release.tar.gz" -C "$root" --no-same-owner --no-same-permissions`)
	if p.Strip > 0 {
		b.WriteString(` --strip-components=` + strconv.Itoa(p.Strip))
	}
	b.WriteString(`; rm -rf "$tmp"; chown -R root:root "$root"; chmod -R u+rwX,go+rX,go-w "$root"`)
	return b.String(), nil
}
