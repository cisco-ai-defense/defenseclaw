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
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
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
	tarballURLRE     = lazyregexp.New(`^https://[a-z0-9.-]+/[A-Za-z0-9._/%-]+\.tar\.gz$`)
	tarballVersionRE = lazyregexp.New(`^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$`)
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

// tarballPins are the reviewed releases of one archive harness (see npmPins).
type tarballPins []tarballPin

func (ps tarballPins) installRun(root, version string) (string, error) {
	for _, p := range ps {
		if p.Version == version {
			return p.installRun(root, version)
		}
	}
	return ps[0].installRun(root, version)
}

// binaryPin pins one vendor-hosted single-executable release per Linux
// architecture: the https download and its sha256. It is tarballPin for a
// vendor that ships the executable itself rather than an archive (Claude
// Code's native installer downloads one file per platform).
type binaryPin struct {
	// Version is the exact release the binaries belong to.
	Version string
	// Binaries maps `uname -m` to the download.
	Binaries map[string]tarballArchive
	// DigestSource says where the digests come from.
	DigestSource string
}

var binaryURLRE = lazyregexp.New(`^https://[a-z0-9.-]+/[A-Za-z0-9._/%-]+$`)

// validate refuses a pin that could not be rendered safely.
func (p binaryPin) validate() error {
	if !tarballVersionRE.MatchString(p.Version) || len(p.Binaries) == 0 {
		return fmt.Errorf("harness: invalid binary pin %q", p.Version)
	}
	if strings.TrimSpace(p.DigestSource) == "" {
		return fmt.Errorf("harness: binary pin %s does not say where its digests come from", p.Version)
	}
	for arch, bin := range p.Binaries {
		if !npmPathRE.MatchString(arch) || !binaryURLRE.MatchString(bin.URL) || !sha256HexRE.MatchString(bin.SHA256) {
			return fmt.Errorf("harness: invalid %s binary pin for %s", arch, p.Version)
		}
		if !strings.Contains(bin.URL, "/"+p.Version+"/") {
			return fmt.Errorf("harness: %s binary %s does not name release %s", arch, bin.URL, p.Version)
		}
	}
	return nil
}

// installRun returns the RUN body that downloads the executable for the
// build architecture over https only, checks its sha256 and installs it at
// dest (an absolute path), owned by root and not writable by anyone else.
func (p binaryPin) installRun(dest, version string) (string, error) {
	if err := p.validate(); err != nil {
		return "", err
	}
	if version != p.Version {
		return "", fmt.Errorf("harness: release %s has no pinned binary digests (pinned %s)", version, p.Version)
	}
	if !strings.HasPrefix(dest, "/") || !npmPathRE.MatchString(dest) || strings.Contains(dest, "..") {
		return "", fmt.Errorf("harness: invalid binary install path %q", dest)
	}
	hosts := map[string]bool{}
	for _, bin := range p.Binaries {
		u, err := url.Parse(bin.URL)
		if err != nil || u.Hostname() == "" {
			return "", fmt.Errorf("harness: invalid binary URL %q", bin.URL)
		}
		hosts[u.Hostname()] = true
	}
	names := make([]string, 0, len(hosts))
	for h := range hosts {
		names = append(names, h)
	}
	sort.Strings(names)
	need := "image builds need https to " + strings.Join(names, " and ")
	var b strings.Builder
	b.WriteString("set -eu; dest=" + shellQuote(dest) + "; ")
	b.WriteString(`case "$(uname -m)" in `)
	arches := make([]string, 0, len(p.Binaries))
	for arch := range p.Binaries {
		arches = append(arches, arch)
	}
	sort.Strings(arches)
	for _, arch := range arches {
		bin := p.Binaries[arch]
		b.WriteString(arch + `) url=` + shellQuote(bin.URL) + `; want=` + shellQuote(bin.SHA256) + ` ;; `)
	}
	b.WriteString(`*) echo "release ` + p.Version + ` has no pinned binary for $(uname -m)" >&2; exit 1 ;; esac; `)
	b.WriteString(`tmp="$(mktemp -d)"; `)
	b.WriteString(`curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 3 -o "$tmp/bin" "$url" || { rm -rf "$tmp"; echo "could not download $url (` + need + `)" >&2; exit 1; }; `)
	b.WriteString(`got="$(sha256sum "$tmp/bin" | cut -d' ' -f1)"; `)
	b.WriteString(`[ "$got" = "$want" ] || { rm -rf "$tmp"; echo "$url sha256 $got is not the pinned $want: refused (a proxy or mirror that rewrites the download fails here; ` + need + `)" >&2; exit 1; }; `)
	b.WriteString(`install -d -o root -g root -m 0755 "$(dirname "$dest")"; `)
	b.WriteString(`install -o root -g root -m 0755 "$tmp/bin" "$dest"; rm -rf "$tmp"`)
	return b.String(), nil
}
