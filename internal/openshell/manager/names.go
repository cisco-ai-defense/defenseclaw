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

// ownsLabels reports labels of an object this data dir created.
func (m *Manager) ownsLabels(labels map[string]string) bool {
	return managedBy(labels, m.opts.Owner)
}

// managedBy reports labels of an object DefenseClaw created for owner.
func managedBy(labels map[string]string, owner string) bool {
	return owner != "" && labels[LabelManaged] == "true" && labels[LabelOwner] == owner
}

var dnsUnsafe = regexp.MustCompile(`[^a-z0-9-]+`)

// nameSuffixLen is the "-<rand4>" of a generated name.
const nameSuffixLen = 5

// GenerateName returns <repo>-<rand4>: the launch folder's name, shortened
// to fit, and four random hex digits. It is a name OpenShell creates
// (openshell.ValidNewSandboxName: at most 19 characters, so there is no
// room for a dc- prefix or the harness). The sandbox carries its harness
// and DefenseClaw ownership as labels (LabelHarness, LabelManaged), and
// `sandbox list` shows the harness.
func GenerateName(project string) (string, error) {
	var buf [2]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("generate sandbox name: %w", err)
	}
	return composeName(project, hex.EncodeToString(buf[:])), nil
}

func composeName(project, suffix string) string {
	repo := ""
	if project != "" {
		repo = strings.ToLower(workspace.RepoName(project))
	}
	repo = strings.Trim(dnsUnsafe.ReplaceAllString(repo, "-"), "-")
	if room := openshell.MaxSandboxNameLen - nameSuffixLen; len(repo) > room {
		repo = strings.TrimRight(repo[:room], "-")
	}
	if repo == "" {
		repo = "project"
	}
	return repo + "-" + suffix
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
