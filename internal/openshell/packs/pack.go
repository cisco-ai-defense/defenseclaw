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

// Package packs loads sandbox policy packs and resolves the effective sandbox
// posture for a run.
//
// A pack bundles the whole sandbox posture in one file teams can adopt or
// ship: network mode, approvals mode, egress feeds and lists, workspace mode,
// secret masks and sensitive-change globs, the harness skip-permissions
// default and allowlist, MCP import and host-port access, and the hook fail
// mode. The built-in packs (open, balanced, strict) are embedded from
// policies/sandbox; custom packs are <pack_dir>/<name>/pack.yaml files or an
// absolute path, loaded with the same strict rules as guardrail rule packs.
//
// Resolve layers pack ⊕ user openshell keys ⊕ run flags and then clamps the
// result by openshell.admin, reporting every attempted loosening as a
// Violation; Effective.Allow checks runtime actions against the same policy.
package packs

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"gopkg.in/yaml.v3"
)

// FormatVersion is the only pack schema version this release understands.
const FormatVersion = 1

// DefaultPack is the pack used when neither the config nor a flag selects one.
const DefaultPack = "open"

// PackFileName is the file a pack directory must contain.
const PackFileName = "pack.yaml"

// MaxPackBytes bounds a pack file.
const MaxPackBytes = 64 << 10

const (
	maxListEntries  = 1024
	maxPatternBytes = 4096
	maxFeeds        = 16
	maxPorts        = 64
	maxDescription  = 1024
	maxUploadMB     = 1 << 20
)

// Network modes. They map onto the OpenShell policy profiles: open → open,
// allowlist → balanced, deny → strict.
const (
	NetworkOpen      = "open"
	NetworkAllowlist = "allowlist"
	NetworkDeny      = "deny"
)

// Approvals modes, loosest first: auto approves every proposal that is not
// blocked, triage auto-approves known-good destinations and asks the rest,
// manual asks every proposal.
const (
	ApprovalsAuto   = "auto"
	ApprovalsTriage = "triage"
	ApprovalsManual = "manual"
)

// FeedBuiltin is DefenseClaw's curated exfiltration/abuse blocklist feed.
const FeedBuiltin = "builtin"

// FailModeClosed is the only hook fail mode a sandbox supports: a hook that
// cannot reach DefenseClaw denies the tool call.
const FailModeClosed = "closed"

var (
	packNamePattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	blockedToolPattern = regexp.MustCompile(`^[A-Za-z0-9_.:*-]{1,256}$`)
	harnessNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
)

// Pack is a validated, normalized sandbox policy pack.
type Pack struct {
	Version     int             `yaml:"version"     json:"version"`
	Name        string          `yaml:"name"        json:"name"`
	Description string          `yaml:"description" json:"description,omitempty"`
	Network     NetworkPolicy   `yaml:"network"     json:"network"`
	Approvals   ApprovalsPolicy `yaml:"approvals"   json:"approvals"`
	Egress      EgressPolicy    `yaml:"egress"      json:"egress"`
	Workspace   WorkspacePolicy `yaml:"workspace"   json:"workspace"`
	Harness     HarnessPolicy   `yaml:"harness"     json:"harness"`
	MCP         MCPPolicy       `yaml:"mcp"         json:"mcp"`
	Hooks       HooksPolicy     `yaml:"hooks"       json:"hooks"`

	// Builtin reports an embedded pack.
	Builtin bool `yaml:"-" json:"builtin"`
	// Source is "builtin:<name>" or the pack file's absolute path.
	Source string `yaml:"-" json:"source"`
	// Digest is "sha256:<hex>" over the pack file bytes, for telemetry and
	// for comparing packs by content.
	Digest string `yaml:"-" json:"digest"`
}

// NetworkPolicy selects the egress posture.
type NetworkPolicy struct {
	Mode string `yaml:"mode" json:"mode"`
}

// ApprovalsPolicy selects how OpenShell draft proposals are handled.
type ApprovalsPolicy struct {
	Mode string `yaml:"mode" json:"mode"`
}

// EgressPolicy configures the DefenseClaw egress proxy.
type EgressPolicy struct {
	// Feeds are blocklist feeds (FeedBuiltin).
	Feeds []string `yaml:"feeds" json:"feeds"`
	// Block and Allow are host globs ("example.com", "*.example.com", "*").
	Block []string `yaml:"block" json:"block"`
	Allow []string `yaml:"allow" json:"allow"`
	// Ports are the destination ports the proxy reaches.
	Ports []int `yaml:"ports" json:"ports"`
	// LargeUploadMB alerts when a first-seen host receives more; 0 disables.
	LargeUploadMB int `yaml:"large_upload_mb" json:"large_upload_mb"`
}

// WorkspacePolicy configures how the project reaches the sandbox.
type WorkspacePolicy struct {
	Mode string `yaml:"mode" json:"mode"`
	// Masks are project-relative globs of secret files that appear empty.
	Masks []string `yaml:"masks" json:"masks"`
	// Review are project-relative globs of files that can run code on the
	// host; changes to them are called out at the end of the session.
	Review []string `yaml:"review" json:"review"`
	// MaxUploadMB caps the copy-mode upload.
	MaxUploadMB int `yaml:"max_upload_mb" json:"max_upload_mb"`
}

// HarnessPolicy configures the harness inside the sandbox.
type HarnessPolicy struct {
	// Yolo is the skip-permissions default.
	Yolo bool `yaml:"yolo" json:"yolo"`
	// Allowed lists the harnesses the pack permits; empty permits all.
	Allowed []string `yaml:"allowed" json:"allowed"`
}

// MCPPolicy configures MCP servers brought into the sandbox.
type MCPPolicy struct {
	Import bool `yaml:"import" json:"import"`
	// HostPorts permits opening consented host localhost ports for
	// host-side MCP servers.
	HostPorts bool `yaml:"host_ports" json:"host_ports"`
	// BlockedTools become OpenShell MCP deny rules.
	BlockedTools []string `yaml:"blocked_tools" json:"blocked_tools"`
}

// HooksPolicy configures the sandbox hook variant.
type HooksPolicy struct {
	FailMode string `yaml:"fail_mode" json:"fail_mode"`
}

// Profile returns the OpenShell policy profile the pack's network mode maps
// to (open, balanced or strict).
func (p *Pack) Profile() string {
	return profileForNetwork(p.Network.Mode)
}

// Marshal renders the normalized pack as YAML (for `sandbox pack show`).
func (p *Pack) Marshal() ([]byte, error) {
	return yaml.Marshal(p)
}

func profileForNetwork(mode string) string {
	switch mode {
	case NetworkAllowlist:
		return config.OpenShellProfileBalanced
	case NetworkDeny:
		return config.OpenShellProfileStrict
	default:
		return config.OpenShellProfileOpen
	}
}

func networkForProfile(profile string) string {
	switch profile {
	case config.OpenShellProfileBalanced:
		return NetworkAllowlist
	case config.OpenShellProfileStrict:
		return NetworkDeny
	default:
		return NetworkOpen
	}
}

// Error is a pack loading or validation failure. Field is the YAML key path
// ("egress.ports[1]"), empty for file-level problems.
type Error struct {
	Source string `json:"source"`
	Field  string `json:"field,omitempty"`
	Code   string `json:"code"`
	Reason string `json:"reason"`
}

func (e *Error) Error() string {
	if e == nil {
		return "sandbox pack error"
	}
	msg := "sandbox pack"
	if e.Source != "" {
		msg += " " + e.Source
	}
	if e.Field != "" {
		msg += ": " + e.Field
	}
	return msg + ": " + e.Reason
}

func packErr(source, field, code, format string, args ...any) *Error {
	return &Error{Source: source, Field: field, Code: code, Reason: fmt.Sprintf(format, args...)}
}

// Parse strictly decodes and validates pack bytes. source names the pack in
// errors and becomes Pack.Source.
func Parse(data []byte, source string) (*Pack, error) {
	if len(data) > MaxPackBytes {
		return nil, packErr(source, "", "too_large", "pack exceeds %d bytes", MaxPackBytes)
	}
	var doc packFile
	if err := decodeStrict(data, source, &doc); err != nil {
		return nil, err
	}
	pack, err := doc.normalize(source)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	pack.Digest = "sha256:" + hex.EncodeToString(sum[:])
	pack.Source = source
	return pack, nil
}

// packFile is the on-disk shape. Pointers distinguish an absent key (which
// is required or takes a documented default) from an explicit zero value.
type packFile struct {
	Version     *int           `yaml:"version"`
	Name        *string        `yaml:"name"`
	Description *string        `yaml:"description"`
	Network     *networkFile   `yaml:"network"`
	Approvals   *approvalsFile `yaml:"approvals"`
	Egress      *egressFile    `yaml:"egress"`
	Workspace   *workspaceFile `yaml:"workspace"`
	Harness     *harnessFile   `yaml:"harness"`
	MCP         *mcpFile       `yaml:"mcp"`
	Hooks       *hooksFile     `yaml:"hooks"`
}

type networkFile struct {
	Mode *string `yaml:"mode"`
}

type approvalsFile struct {
	Mode *string `yaml:"mode"`
}

type egressFile struct {
	Feeds         *[]string `yaml:"feeds"`
	Block         []string  `yaml:"block"`
	Allow         []string  `yaml:"allow"`
	Ports         *[]int    `yaml:"ports"`
	LargeUploadMB *int      `yaml:"large_upload_mb"`
}

type workspaceFile struct {
	Mode        *string  `yaml:"mode"`
	Masks       []string `yaml:"masks"`
	Review      []string `yaml:"review"`
	MaxUploadMB *int     `yaml:"max_upload_mb"`
}

type harnessFile struct {
	Yolo    *bool    `yaml:"yolo"`
	Allowed []string `yaml:"allowed"`
}

type mcpFile struct {
	Import       *bool    `yaml:"import"`
	HostPorts    *bool    `yaml:"host_ports"`
	BlockedTools []string `yaml:"blocked_tools"`
}

type hooksFile struct {
	FailMode *string `yaml:"fail_mode"`
}

// Defaults for optional pack keys.
var (
	defaultFeeds         = []string{FeedBuiltin}
	defaultPorts         = []int{80, 443}
	defaultLargeUploadMB = 25
	defaultMaxUploadMB   = 500
)

func (f *packFile) normalize(source string) (*Pack, error) {
	v := &validator{source: source}
	p := &Pack{}

	switch {
	case f.Version == nil:
		v.fail("version", "missing_field", "is required")
	case *f.Version != FormatVersion:
		v.fail("version", "unsupported_version", "%d is not supported (want %d)", *f.Version, FormatVersion)
	default:
		p.Version = *f.Version
	}
	if f.Name == nil {
		v.fail("name", "missing_field", "is required")
	} else if name := strings.TrimSpace(*f.Name); !packNamePattern.MatchString(name) {
		v.fail("name", "invalid_value", "%q must be lowercase letters, digits and dashes (at most 63)", *f.Name)
	} else {
		p.Name = name
	}
	if f.Description != nil {
		p.Description = strings.TrimSpace(*f.Description)
		if len(p.Description) > maxDescription {
			v.fail("description", "invalid_value", "is longer than %d characters", maxDescription)
		}
	}

	network := f.Network
	if network == nil {
		network = &networkFile{}
	}
	p.Network.Mode = v.enum("network.mode", network.Mode, NetworkOpen, NetworkAllowlist, NetworkDeny)

	approvals := f.Approvals
	if approvals == nil {
		approvals = &approvalsFile{}
	}
	p.Approvals.Mode = v.enum("approvals.mode", approvals.Mode, ApprovalsAuto, ApprovalsTriage, ApprovalsManual)

	egress := f.Egress
	if egress == nil {
		egress = &egressFile{}
	}
	if egress.Feeds == nil {
		p.Egress.Feeds = append([]string(nil), defaultFeeds...)
	} else {
		p.Egress.Feeds = v.feeds("egress.feeds", *egress.Feeds)
	}
	p.Egress.Block = v.hostGlobs("egress.block", egress.Block)
	p.Egress.Allow = v.allowGlobs("egress.allow", egress.Allow)
	if egress.Ports == nil {
		p.Egress.Ports = append([]int(nil), defaultPorts...)
	} else {
		p.Egress.Ports = v.ports("egress.ports", *egress.Ports)
	}
	p.Egress.LargeUploadMB = defaultLargeUploadMB
	if egress.LargeUploadMB != nil {
		p.Egress.LargeUploadMB = v.boundedInt("egress.large_upload_mb", *egress.LargeUploadMB, 0, maxUploadMB)
	}

	workspace := f.Workspace
	if workspace == nil {
		workspace = &workspaceFile{}
	}
	p.Workspace.Mode = v.enum("workspace.mode", workspace.Mode, config.OpenShellWorkdirMount, config.OpenShellWorkdirCopy)
	p.Workspace.Masks = v.projectGlobs("workspace.masks", workspace.Masks)
	p.Workspace.Review = v.projectGlobs("workspace.review", workspace.Review)
	p.Workspace.MaxUploadMB = defaultMaxUploadMB
	if workspace.MaxUploadMB != nil {
		p.Workspace.MaxUploadMB = v.boundedInt("workspace.max_upload_mb", *workspace.MaxUploadMB, 1, maxUploadMB)
	}

	harness := f.Harness
	if harness == nil {
		harness = &harnessFile{}
	}
	p.Harness.Yolo = v.requiredBool("harness.yolo", harness.Yolo)
	p.Harness.Allowed = v.harnesses("harness.allowed", harness.Allowed)

	mcp := f.MCP
	if mcp == nil {
		mcp = &mcpFile{}
	}
	p.MCP.Import = v.requiredBool("mcp.import", mcp.Import)
	p.MCP.HostPorts = v.requiredBool("mcp.host_ports", mcp.HostPorts)
	p.MCP.BlockedTools = v.blockedTools("mcp.blocked_tools", mcp.BlockedTools)

	hooks := f.Hooks
	if hooks == nil {
		hooks = &hooksFile{}
	}
	p.Hooks.FailMode = v.enum("hooks.fail_mode", hooks.FailMode, FailModeClosed)

	if p.Network.Mode != NetworkDeny && p.Egress.Ports != nil && len(p.Egress.Ports) == 0 {
		v.fail("egress.ports", "invalid_value", "must list at least one port unless network.mode is deny")
	}
	if v.err != nil {
		return nil, v.err
	}
	return p, nil
}

// validator records the first validation failure; later checks become
// no-ops so the error names the earliest offending key.
type validator struct {
	source string
	err    *Error
}

func (v *validator) fail(field, code, format string, args ...any) {
	if v.err == nil {
		v.err = packErr(v.source, field, code, format, args...)
	}
}

func (v *validator) enum(field string, value *string, allowed ...string) string {
	if value == nil {
		v.fail(field, "missing_field", "is required (one of %s)", strings.Join(allowed, ", "))
		return ""
	}
	got := strings.TrimSpace(*value)
	for _, candidate := range allowed {
		if got == candidate {
			return got
		}
	}
	v.fail(field, "invalid_value", "%q must be one of %s", *value, strings.Join(allowed, ", "))
	return ""
}

func (v *validator) requiredBool(field string, value *bool) bool {
	if value == nil {
		v.fail(field, "missing_field", "is required (true or false)")
		return false
	}
	return *value
}

func (v *validator) boundedInt(field string, value, lo, hi int) int {
	if value < lo || value > hi {
		v.fail(field, "invalid_value", "%d must be between %d and %d", value, lo, hi)
	}
	return value
}

func (v *validator) listLimit(field string, n, limit int) bool {
	if n > limit {
		v.fail(field, "invalid_value", "lists %d entries (at most %d)", n, limit)
		return false
	}
	return true
}

func (v *validator) feeds(field string, feeds []string) []string {
	if !v.listLimit(field, len(feeds), maxFeeds) {
		return nil
	}
	out := make([]string, 0, len(feeds))
	for i, feed := range feeds {
		feed = strings.TrimSpace(feed)
		if feed != FeedBuiltin {
			v.fail(fmt.Sprintf("%s[%d]", field, i), "invalid_value", "unknown feed %q (want %s)", feed, FeedBuiltin)
			continue
		}
		out = appendUnique(out, feed)
	}
	return out
}

func (v *validator) hostGlobs(field string, globs []string) []string {
	if !v.listLimit(field, len(globs), maxListEntries) {
		return nil
	}
	out := make([]string, 0, len(globs))
	for i, glob := range globs {
		if err := config.ValidateOpenShellHostGlob(glob); err != nil {
			v.fail(fmt.Sprintf("%s[%d]", field, i), "invalid_value", "%v", err)
			continue
		}
		out = appendUnique(out, config.NormalizeOpenShellHostGlob(glob))
	}
	return out
}

// allowGlobs is hostGlobs for an allow list, which may not cover every host
// or a whole public suffix (IsBroadAllowGlob).
func (v *validator) allowGlobs(field string, globs []string) []string {
	out := v.hostGlobs(field, globs)
	for i, glob := range globs {
		if IsBroadAllowGlob(glob) {
			v.fail(fmt.Sprintf("%s[%d]", field, i), "invalid_value",
				"%q covers every host or a whole top-level domain; list the destinations to allow", glob)
		}
	}
	return out
}

func (v *validator) ports(field string, ports []int) []int {
	if !v.listLimit(field, len(ports), maxPorts) {
		return nil
	}
	out := make([]int, 0, len(ports))
	seen := make(map[int]struct{}, len(ports))
	for i, port := range ports {
		if port < 1 || port > 65535 {
			v.fail(fmt.Sprintf("%s[%d]", field, i), "invalid_value", "port %d must be between 1 and 65535", port)
			continue
		}
		if _, dup := seen[port]; dup {
			continue
		}
		seen[port] = struct{}{}
		out = append(out, port)
	}
	return out
}

// projectGlobs accepts project-relative globs: no absolute paths, no ".."
// segments, no NUL bytes.
func (v *validator) projectGlobs(field string, globs []string) []string {
	if !v.listLimit(field, len(globs), maxListEntries) {
		return nil
	}
	out := make([]string, 0, len(globs))
	for i, glob := range globs {
		entry := fmt.Sprintf("%s[%d]", field, i)
		g := strings.TrimSpace(glob)
		switch {
		case g == "":
			v.fail(entry, "invalid_value", "is empty")
			continue
		case len(g) > maxPatternBytes:
			v.fail(entry, "invalid_value", "is longer than %d bytes", maxPatternBytes)
			continue
		case strings.ContainsRune(g, 0):
			v.fail(entry, "invalid_value", "contains a NUL byte")
			continue
		case strings.HasPrefix(g, "/") || strings.HasPrefix(g, "~") || strings.Contains(g, `\`):
			v.fail(entry, "invalid_value", "%q must be a project-relative glob with forward slashes", glob)
			continue
		}
		escapes := false
		for _, segment := range strings.Split(g, "/") {
			if segment == ".." {
				escapes = true
			}
		}
		if escapes {
			v.fail(entry, "invalid_value", "%q must not contain \"..\"", glob)
			continue
		}
		out = appendUnique(out, g)
	}
	return out
}

func (v *validator) harnesses(field string, names []string) []string {
	if !v.listLimit(field, len(names), 64) {
		return nil
	}
	out := make([]string, 0, len(names))
	for i, name := range names {
		normalized := config.NormalizeConnectorName(name)
		if !harnessNamePattern.MatchString(normalized) {
			v.fail(fmt.Sprintf("%s[%d]", field, i), "invalid_value", "invalid harness name %q", name)
			continue
		}
		out = appendUnique(out, normalized)
	}
	return out
}

func (v *validator) blockedTools(field string, tools []string) []string {
	if !v.listLimit(field, len(tools), maxListEntries) {
		return nil
	}
	out := make([]string, 0, len(tools))
	for i, tool := range tools {
		tool = strings.TrimSpace(tool)
		if !blockedToolPattern.MatchString(tool) {
			v.fail(fmt.Sprintf("%s[%d]", field, i), "invalid_value", "invalid MCP tool name or glob %q", tool)
			continue
		}
		out = appendUnique(out, tool)
	}
	return out
}

func appendUnique(list []string, value string) []string {
	for _, existing := range list {
		if existing == value {
			return list
		}
	}
	return append(list, value)
}
