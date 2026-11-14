// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package kit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"
)

// AgentRelease is an agent build the kit layer installs over the OpenShell
// harness base. The harness pin (internal/openshell/harness) stays as it is;
// an actor image needs a newer agent when its model requires one
// (substrate-1 GAP-0114: Bedrock serves Claude Haiku 5.5 to Claude Code
// 2.1.280 and newer, and the harness pins 2.1.156).
type AgentRelease struct {
	Version string
	// Path is where the harness installed the agent; the kit replaces the
	// file there, so the harness's /usr/local/bin link keeps working.
	Path string
	// URL is the download for an architecture ("amd64", "arm64").
	URL func(arch string) string
	// SHA256 is each architecture's checksum, copied from the vendor's
	// signed release manifest (verified with the release key DefenseClaw
	// pins in internal/sensor/claude_release_key.asc).
	SHA256 map[string]string
}

// AgentReleases are the kit's agent pins, by connector.
//
// Claude Code 2.1.323 (the cert hosts' release; 2.1.317 before lane K1): at least 2.1.280 (Haiku 5.5), covered on hosts by the
// claudecode-hooks-v2 contract (measured as the Claude Desktop 4.16336.0
// engine), and the build the Substrate spike ran hooks with in actors.
// Checksums from downloads.claude.ai claude-code-releases/2.1.323
// manifest.json, whose signature verified with the pinned key (fingerprint
// 31ddde24ddfab679f42d7bd2baa929ff1a7ecace) on 2026-11-13.
var AgentReleases = map[string]AgentRelease{
	"claudecode": {
		Version: "2.1.323",
		Path:    "/opt/defenseclaw-harness/claudecode/bin/claude",
		URL: func(arch string) string {
			return "https://downloads.claude.ai/claude-code-releases/2.1.323/" + claudePlatform(arch) + "/claude"
		},
		SHA256: map[string]string{
			"amd64": "604d29a6869409106b6a1110bdadcc8b72e8654a5a865d23258f938a696e348e",
			"arm64": "452dddff140b5caf00a5410333a3d6db82c73ea2dec74b1541fae18e97d47dca",
		},
	},
}

func claudePlatform(arch string) string {
	if arch == "arm64" {
		return "linux-arm64"
	}
	return "linux-x64"
}

// HarnessReleases are the agent releases the actor kit installs for the
// connectors whose agent is a harness install (npm package, vendor archive),
// not one file: the version is built into the base image by the harness
// (internal/openshell/harness keeps one extra, reviewed pin for each, beside
// the OpenShell default). They are the releases the cert hosts run (the 1.0.10
// connector version sweep, plans/r110/streams/CS/LATEST.md), so CERT-110 tests
// the build users have. Claude Code is in AgentReleases instead (its file is
// replaced in the kit layer).
var HarnessReleases = map[string]string{
	"codex":       "0.168.0",
	"copilot":     "1.0.110",
	"opencode":    "2.2.7",
	"amp":         "0.0.1794542441-g4e0611",
	"cursor":      "2026.11.11-b912975",
	"devin":       "3000.12.57",
	"antigravity": "1.5.8",
	"kiro":        "2.35.1",
}

// HarnessRelease is the version the base image of connector is built with
// (BuildSpec.HarnessVersion), or "" for the harness's default.
func HarnessRelease(connector string) string {
	return HarnessReleases[connector]
}

// AgentVersion is the agent version an actor image of connector carries:
// the kit's pin when there is one, else the release the base image is built
// with, else the harness's.
func AgentVersion(connector, harnessVersion string) string {
	if r, ok := AgentReleases[connector]; ok {
		return r.Version
	}
	if v, ok := HarnessReleases[connector]; ok {
		return v
	}
	return harnessVersion
}

// maxAgentBinary bounds a download.
const maxAgentBinary = 1 << 30

// FetchAgent downloads the pinned agent binary for arch and checks its
// SHA-256 against the pin. It returns nil, nil for a connector without a pin.
func FetchAgent(ctx context.Context, client *http.Client, connector, arch string) ([]byte, error) {
	r, ok := AgentReleases[connector]
	if !ok {
		return nil, nil
	}
	if _, ok := r.SHA256[arch]; !ok {
		return nil, fmt.Errorf("%s %s has no pinned checksum for %s", connector, r.Version, arch)
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Minute}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.URL(arch), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download %s %s: %w", connector, r.Version, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s %s: HTTP %d", connector, r.Version, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxAgentBinary+1))
	if err != nil {
		return nil, fmt.Errorf("download %s %s: %w", connector, r.Version, err)
	}
	if err := CheckAgent(connector, arch, b); err != nil {
		return nil, err
	}
	return b, nil
}

// CheckAgent checks b against the pinned SHA-256.
func CheckAgent(connector, arch string, b []byte) error {
	r, ok := AgentReleases[connector]
	if !ok {
		return nil
	}
	sum := sha256.Sum256(b)
	if got := hex.EncodeToString(sum[:]); got != r.SHA256[arch] {
		return fmt.Errorf("%s %s for %s: checksum %s is not the pinned %s", connector, r.Version, arch, got, r.SHA256[arch])
	}
	return nil
}

// AgentInstallScript is the kit-layer shell step that installs the pinned
// agent over the harness's (Dockerfile builds), or "" without a pin. It
// downloads over HTTPS only, checks the pinned SHA-256 and checks the
// installed version.
func AgentInstallScript(connector string) string {
	r, ok := AgentReleases[connector]
	if !ok {
		return ""
	}
	return fmt.Sprintf(`set -eu; case "$(uname -m)" in x86_64) a=amd64; sum=%s; url=%s ;; aarch64) a=arm64; sum=%s; url=%s ;; *) echo "no pinned agent build for $(uname -m)" >&2; exit 1 ;; esac; `+
		`t="$(mktemp -d)"; curl -fsSL --proto '=https' --tlsv1.2 -o "$t/agent" "$url"; echo "$sum  $t/agent" | sha256sum -c - >/dev/null; `+
		`install -o root -g root -m 0755 "$t/agent" %s; rm -rf "$t"; `+
		`got="$(DISABLE_AUTOUPDATER=1 CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 %s --version 2>/dev/null | awk 'NR==1{print $1}')"; got="${got#v}"; `+
		`[ "$got" = %s ] || { echo "installed agent is '$got', not the pinned %s" >&2; exit 1; }`,
		r.SHA256["amd64"], r.URL("amd64"), r.SHA256["arm64"], r.URL("arm64"), r.Path, r.Path, r.Version, r.Version)
}
