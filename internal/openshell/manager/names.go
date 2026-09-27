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
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// Labels on DefenseClaw sandboxes and providers.
const (
	LabelManaged = "io.defenseclaw/managed"
	LabelOwner   = "io.defenseclaw/owner"
	LabelHarness = "io.defenseclaw/harness"
	LabelProfile = "io.defenseclaw/profile"
	LabelPack    = "io.defenseclaw/pack"
	// LabelSandbox and LabelRole mark providers.
	LabelSandbox = "io.defenseclaw/sandbox"
	LabelRole    = "io.defenseclaw/role"
	// LabelProject and LabelWorkdirMode are workspace's resume labels.
	LabelProject     = workspace.ProjectLabelKey
	LabelWorkdirMode = workspace.ModeLabelKey
)

// Provider roles.
const (
	roleIngress    = "ingress"
	roleLLM        = "llm"
	roleCredential = "credential"
)

var labelValueUnsafe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// labelValue makes s a valid label value (at most 63 characters, starting
// and ending alphanumeric), or "".
func labelValue(s string) string {
	s = labelValueUnsafe.ReplaceAllString(s, "-")
	if len(s) > 63 {
		s = s[:63]
	}
	return strings.Trim(s, "._-")
}

// managedSelector selects this data dir's sandboxes and providers.
func (m *Manager) managedSelector() map[string]string {
	return map[string]string{LabelManaged: "true", LabelOwner: m.opts.Owner}
}

var dnsUnsafe = regexp.MustCompile(`[^a-z0-9-]+`)

// harnessShort is the harness's short name in generated sandbox names.
func harnessShort(harness string) string {
	switch harness {
	case "claudecode":
		return "claude"
	default:
		return harness
	}
}

// GenerateName returns dc-<harness>-<repo>-<rand4>, a valid DNS-label
// sandbox name. repo is shortened to fit.
func GenerateName(harness, project string) (string, error) {
	var buf [2]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("generate sandbox name: %w", err)
	}
	return composeName(harness, project, hex.EncodeToString(buf[:])), nil
}

func composeName(harness, project, suffix string) string {
	h := dnsUnsafe.ReplaceAllString(strings.ToLower(harnessShort(harness)), "-")
	repo := "project"
	if project != "" {
		repo = strings.ToLower(workspace.RepoName(project))
	}
	repo = strings.Trim(dnsUnsafe.ReplaceAllString(repo, "-"), "-")
	if repo == "" {
		repo = "project"
	}
	room := 63 - len("dc-") - len(h) - len(suffix) - 2
	if room < 1 {
		h = h[:min(len(h), 20)]
		room = 63 - len("dc-") - len(h) - len(suffix) - 2
	}
	if len(repo) > room {
		repo = strings.Trim(repo[:room], "-")
	}
	name := "dc-" + h + "-" + repo + "-" + suffix
	if !openshell.ValidSandboxName(name) {
		name = "dc-" + h + "-" + suffix
	}
	return name
}

func providerName(sandbox, role string, i int) string {
	if role == roleCredential {
		return fmt.Sprintf("%s-cred-%d", sandbox, i)
	}
	return sandbox + "-" + role
}

// credentialProfileID is the provider profile of one --credential binding,
// shared by every sandbox binding the same variable to the same endpoint,
// whichever DefenseClaw daemon on the gateway created it: the id hashes all
// the profile holds (variable, host, port), so sharing it re-points nothing.
func credentialProfileID(name, host string, port int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d", name, host, port)))
	return credentialProfilePrefix + hex.EncodeToString(sum[:6])
}

// credentialProfilePrefix starts every --credential provider profile id.
const credentialProfilePrefix = "dc-cred-"

var imageVersionUnsafe = regexp.MustCompile(`[^A-Za-z0-9.+_-]+`)

// ImageVersion is the DefenseClaw version baked into overlay image content
// hashes. `defenseclaw sandbox image build` must use the same value, or the
// daemon will not find the images the CLI built.
func ImageVersion() string {
	v := imageVersionUnsafe.ReplaceAllString(strings.TrimSpace(version.Current().BinaryVersion), "-")
	v = strings.Trim(v, ".+_-")
	if len(v) > 64 {
		v = v[:64]
	}
	if v == "" {
		return "dev"
	}
	return v
}
