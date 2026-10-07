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

package packs

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// RepoPolicyPath is where a project keeps its repository sandbox policy,
// relative to the project folder.
const RepoPolicyPath = ".defenseclaw/sandbox.yaml"

// MaxRepoPolicyBytes bounds a repository policy file.
const MaxRepoPolicyBytes = 16 << 10

// RepoPolicyConstraint names the repository policy in provenance and
// refusals.
const RepoPolicyConstraint = "repo policy " + RepoPolicyPath

// RepoPolicy is a project's repository sandbox policy
// (<project>/.defenseclaw/sandbox.yaml): what the repository asks of every
// sandbox that runs it. It can only tighten the effective policy, and it is
// untrusted input (anyone who can write the repository wrote it): a bounded
// file, read without following links, decoded strictly, with no includes.
// Resolve applies it on top of the pack, the user's keys and the run flags,
// before the administrator's clamps. A key that would loosen the policy is
// kept in Refused, and Resolve refuses the run with one fatal Violation per
// key. The sandbox keeps the copy its run read, so a change made during a
// session applies from the next run on.
type RepoPolicy struct {
	// Source is the file read; Digest "sha256:<hex>" over its bytes, which
	// Content holds.
	Source  string `json:"source"`
	Digest  string `json:"digest"`
	Content []byte `json:"content,omitempty"`

	// NetworkMode is allowlist or deny ("" unset), and Approvals triage or
	// manual: floors.
	NetworkMode string `json:"network_mode,omitempty"`
	Approvals   string `json:"approvals,omitempty"`
	// Copy, NoYolo, NoMCPImport, BlockLargeUploads and TamperStop are the
	// switches the repository set to their strict value.
	Copy              bool `json:"copy,omitempty"`
	NoYolo            bool `json:"no_yolo,omitempty"`
	NoMCPImport       bool `json:"no_mcp_import,omitempty"`
	BlockLargeUploads bool `json:"block_large_uploads,omitempty"`
	TamperStop        bool `json:"tamper_stop,omitempty"`
	// LargeUploadMB lowers the large-upload threshold (0 unset).
	LargeUploadMB int `json:"large_upload_mb,omitempty"`
	// Ports are the ports the project needs: the run keeps only these of
	// the ports its policy opens (nil unset).
	Ports []int `json:"ports,omitempty"`
	// Block, Masks, Review and BlockedTools add to the policy's lists.
	Block        []string `json:"block,omitempty"`
	Masks        []string `json:"masks,omitempty"`
	Review       []string `json:"review,omitempty"`
	BlockedTools []string `json:"blocked_tools,omitempty"`

	// Refused are the keys that would loosen the policy.
	Refused []RepoRefusal `json:"refused,omitempty"`
}

// RepoRefusal is one key of a repository policy that would loosen the
// sandbox policy.
type RepoRefusal struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Reason string `json:"reason"`
}

// repoPolicyFile is the on-disk shape: the pack keys a repository may
// tighten, and the two pack lists that only ever loosen (egress.allow,
// workspace.unmask), so a file that sets them is refused with a reason
// instead of an unknown key.
type repoPolicyFile struct {
	Version   *int               `yaml:"version"`
	Network   *networkFile       `yaml:"network"`
	Approvals *approvalsFile     `yaml:"approvals"`
	Egress    *repoEgressFile    `yaml:"egress"`
	Workspace *repoWorkspaceFile `yaml:"workspace"`
	Harness   *repoHarnessFile   `yaml:"harness"`
	MCP       *repoMCPFile       `yaml:"mcp"`
	Hooks     *repoHooksFile     `yaml:"hooks"`
}

type repoEgressFile struct {
	Block             []string `yaml:"block"`
	Allow             []string `yaml:"allow"`
	Ports             *[]int   `yaml:"ports"`
	LargeUploadMB     *int     `yaml:"large_upload_mb"`
	BlockLargeUploads *bool    `yaml:"block_large_uploads"`
}

type repoWorkspaceFile struct {
	Mode   *string  `yaml:"mode"`
	Masks  []string `yaml:"masks"`
	Review []string `yaml:"review"`
	Unmask []string `yaml:"unmask"`
}

type repoHarnessFile struct {
	Yolo *bool `yaml:"yolo"`
}

type repoMCPFile struct {
	Import       *bool    `yaml:"import"`
	BlockedTools []string `yaml:"blocked_tools"`
}

type repoHooksFile struct {
	OnTamper *string `yaml:"on_tamper"`
}

// repoPolicyKeys lists what a repository policy may set, for the unknown
// key error.
const repoPolicyKeys = "version, network.mode, approvals.mode, egress.block, egress.ports, egress.large_upload_mb, " +
	"egress.block_large_uploads, workspace.mode, workspace.masks, workspace.review, harness.yolo, mcp.import, " +
	"mcp.blocked_tools, hooks.on_tamper"

// LoadRepoPolicy reads <project>/.defenseclaw/sandbox.yaml. It returns nil
// and no error when the project has none. Neither the .defenseclaw folder
// nor the file may be a symbolic link, and the file must be a regular file
// of at most MaxRepoPolicyBytes; ownership is not checked, since the file
// can only tighten.
func LoadRepoPolicy(project string) (*RepoPolicy, error) {
	project = strings.TrimSpace(project)
	if project == "" {
		return nil, nil
	}
	if !filepath.IsAbs(project) {
		return nil, repoErr(project, "", "relative_path", "the project path must be absolute")
	}
	dir := filepath.Join(project, filepath.Dir(RepoPolicyPath))
	file := filepath.Join(project, RepoPolicyPath)
	for _, p := range []string{dir, file} {
		info, err := os.Lstat(p)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return nil, nil
		case err != nil:
			return nil, repoErr(file, "", "unreadable", "cannot inspect %s", p)
		case info.Mode()&fs.ModeSymlink != 0:
			return nil, repoErr(file, "", "symlink", "%s must not be a symbolic link", p)
		case p == dir && !info.IsDir():
			return nil, nil
		case p == file && !info.Mode().IsRegular():
			return nil, repoErr(file, "", "not_regular", "the repository policy must be a regular file")
		case p == file && info.Size() > MaxRepoPolicyBytes:
			return nil, repoErr(file, "", "too_large", "the repository policy exceeds %d bytes", MaxRepoPolicyBytes)
		}
	}
	data, err := safefile.ReadRegularFileBounded(file, MaxRepoPolicyBytes)
	if err != nil {
		return nil, repoErr(file, "", "unreadable", "cannot read the repository policy safely")
	}
	return ParseRepoPolicy(data, file)
}

// ParseRepoPolicy strictly decodes and validates repository policy bytes.
// Values that would loosen the policy are not errors: they are kept in
// Refused (one per key), and Resolve refuses the run with them.
func ParseRepoPolicy(data []byte, source string) (*RepoPolicy, error) {
	if len(data) > MaxRepoPolicyBytes {
		return nil, repoErr(source, "", "too_large", "the repository policy exceeds %d bytes", MaxRepoPolicyBytes)
	}
	var f repoPolicyFile
	if err := decodeStrict(data, source, &f); err != nil {
		var pe *Error
		if errors.As(err, &pe) {
			if pe.Code == "unknown_field" {
				pe.Reason += "; a repository policy may set " + repoPolicyKeys
			}
			pe.Reason, pe.Field, pe.What = printable(pe.Reason), printable(pe.Field), repoPolicyWhat
		}
		return nil, err
	}
	sum := sha256.Sum256(data)
	rp := &RepoPolicy{Source: source, Digest: "sha256:" + hex.EncodeToString(sum[:]), Content: append([]byte(nil), data...)}
	v := &validator{source: source}
	refuse := func(key, value, reason string) {
		rp.Refused = append(rp.Refused, RepoRefusal{Key: key, Value: value, Reason: reason})
	}
	switch {
	case f.Version == nil:
		v.fail("version", "missing_field", "is required")
	case *f.Version != FormatVersion:
		v.fail("version", "unsupported_version", "%d is not supported (want %d)", *f.Version, FormatVersion)
	}
	if f.Network != nil && f.Network.Mode != nil {
		switch mode := v.enum("network.mode", f.Network.Mode, NetworkOpen, NetworkAllowlist, NetworkDeny); mode {
		case NetworkOpen:
			refuse("network.mode", mode, "open is the loosest network mode; ask for allowlist or deny")
		default:
			rp.NetworkMode = mode
		}
	}
	if f.Approvals != nil && f.Approvals.Mode != nil {
		switch mode := v.enum("approvals.mode", f.Approvals.Mode, ApprovalsAuto, ApprovalsTriage, ApprovalsManual); mode {
		case ApprovalsAuto:
			refuse("approvals.mode", mode, "auto approves the most; ask for triage or manual")
		default:
			rp.Approvals = mode
		}
	}
	if e := f.Egress; e != nil {
		rp.Block = v.hostGlobs("egress.block", e.Block)
		if len(e.Allow) > 0 {
			refuse("egress.allow", plural(len(e.Allow), "entry", "entries"), "allow entries open destinations")
		}
		if e.Ports != nil {
			if len(*e.Ports) == 0 {
				v.fail("egress.ports", "invalid_value", "must list the ports the project needs; for no web egress ask for network.mode: deny")
			}
			rp.Ports = v.ports("egress.ports", *e.Ports)
		}
		if e.LargeUploadMB != nil {
			if *e.LargeUploadMB == 0 {
				refuse("egress.large_upload_mb", "0", "0 turns the large-upload report off")
			} else {
				rp.LargeUploadMB = v.boundedInt("egress.large_upload_mb", *e.LargeUploadMB, 1, maxUploadMB)
			}
		}
		if e.BlockLargeUploads != nil {
			if *e.BlockLargeUploads {
				rp.BlockLargeUploads = true
			} else {
				refuse("egress.block_large_uploads", "false", "false never blocks more")
			}
		}
	}
	if w := f.Workspace; w != nil {
		if w.Mode != nil {
			switch mode := v.enum("workspace.mode", w.Mode, config.OpenShellWorkdirMount, config.OpenShellWorkdirCopy); mode {
			case config.OpenShellWorkdirMount:
				refuse("workspace.mode", mode, "a live mount lets the agent write the project folder; ask for copy")
			case config.OpenShellWorkdirCopy:
				rp.Copy = true
			}
		}
		rp.Masks = v.projectGlobs("workspace.masks", w.Masks)
		rp.Review = v.projectGlobs("workspace.review", w.Review)
		if len(w.Unmask) > 0 {
			refuse("workspace.unmask", plural(len(w.Unmask), "entry", "entries"), "unmask entries reveal masked secret files")
		}
	}
	if h := f.Harness; h != nil && h.Yolo != nil {
		if *h.Yolo {
			refuse("harness.yolo", "true", "skip-permissions mode drops the harness's own prompts")
		} else {
			rp.NoYolo = true
		}
	}
	if m := f.MCP; m != nil {
		if m.Import != nil {
			if *m.Import {
				refuse("mcp.import", "true", "it brings your MCP servers into the sandbox")
			} else {
				rp.NoMCPImport = true
			}
		}
		rp.BlockedTools = v.blockedTools("mcp.blocked_tools", m.BlockedTools)
	}
	if h := f.Hooks; h != nil && h.OnTamper != nil {
		switch mode := v.enum("hooks.on_tamper", h.OnTamper, OnTamperStop, OnTamperAlert); mode {
		case OnTamperAlert:
			refuse("hooks.on_tamper", mode, "alert keeps a tampered sandbox running; ask for stop")
		case OnTamperStop:
			rp.TamperStop = true
		}
	}
	if v.err != nil {
		v.err.Reason, v.err.Field, v.err.What = printable(v.err.Reason), printable(v.err.Field), repoPolicyWhat
		return nil, v.err
	}
	return rp, nil
}

// repoPolicyWhat names a repository policy in its errors.
const repoPolicyWhat = "repository policy"

func repoErr(source, field, code, format string, args ...any) *Error {
	e := packErr(source, field, code, format, args...)
	e.Reason, e.What = printable(e.Reason), repoPolicyWhat
	return e
}

// printable replaces control characters, line separators and bidirectional
// overrides, which a hostile repository could put in a key or a value to
// drive or garble the terminal that shows the error.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r < 0x20, r == 0x7f, r >= 0x80 && r < 0xa0, r == '\u2028', r == '\u2029',
			r >= '\u202a' && r <= '\u202e', r >= '\u2066' && r <= '\u2069':
			return '?'
		}
		return r
	}, s)
}

// repoLayer is the repository policy's provenance.
var repoLayer = layer{SourceRepo, RepoPolicyConstraint}

// refuseRepoLoosening takes the run's repository policy and refuses every
// key of it that would loosen the sandbox policy: one fatal Violation per
// key, so the run is refused with all the reasons, as a refused harness is.
func (r *resolver) refuseRepoLoosening(rp *RepoPolicy) {
	if rp == nil {
		return
	}
	r.repo, r.repoRequested, r.eff.RepoPolicy = rp, map[string]string{}, rp
	for _, ref := range rp.Refused {
		r.violate(Violation{
			Key: ref.Key, Source: SourceRepo, Attempted: ref.Value, Constraint: RepoPolicyConstraint, Fatal: true,
			Message: "the repository policy " + RepoPolicyPath + " would loosen the sandbox policy: " + ref.Key + " " + ref.Value,
			Detail:  ref.Reason + "; a repository policy can only tighten, so remove " + ref.Key + " from " + RepoPolicyPath,
		})
	}
}

// tightened notes that the repository policy made a setting (named by its
// key in the repository policy file) stricter, and returns its layer.
func (r *resolver) tightened(key string) layer {
	if !containsString(r.eff.RepoTightened, key) {
		r.eff.RepoTightened = append(r.eff.RepoTightened, key)
	}
	return repoLayer
}

// repoList is one list of the run's repository policy (nil without one).
func (r *resolver) repoList(list func(*RepoPolicy) []string) []string {
	if r.repo == nil {
		return nil
	}
	return list(r.repo)
}

// addRepo adds the repository policy's entries of a list setting; when that
// adds any, the setting's provenance names the repository policy too.
func (r *resolver) addRepo(key string, list, extra []string, from layer) ([]string, layer) {
	merged := mergeLists(list, extra)
	if len(merged) == len(list) {
		return list, from
	}
	r.tightened(key)
	return merged, layer{SourceRepo, from.origin + " + " + RepoPolicyConstraint}
}

// repoPorts keeps only the ports the repository policy lists. A policy that
// would keep none refuses the run, unless the proxy is off (deny), where
// the ports only bound what an approval can open.
func (r *resolver) repoPorts() {
	if r.repo == nil || r.repo.Ports == nil {
		return
	}
	eg := &r.eff.Egress
	kept := []int{}
	for _, port := range eg.Ports {
		if containsInt(r.repo.Ports, port) {
			kept = append(kept, port)
		}
	}
	switch {
	case len(kept) == len(eg.Ports):
	case len(kept) == 0 && r.eff.NetworkMode != NetworkDeny:
		r.violate(Violation{
			Key: "egress.ports", Source: SourceRepo, Attempted: joinInts(r.repo.Ports), Enforced: joinInts(eg.Ports),
			Constraint: RepoPolicyConstraint, Fatal: true,
			Message: "the repository policy " + RepoPolicyPath + " leaves no egress port open: it lists " + joinInts(r.repo.Ports) +
				", the sandbox policy opens " + joinInts(eg.Ports),
			Detail: "list a port the policy opens, or ask for network.mode: deny for no web egress",
		})
	default:
		r.repoRequested["egress.ports"] = joinInts(eg.Ports)
		eg.Ports = kept
		r.set("egress.ports", joinInts(kept), r.tightened("egress.ports"))
	}
}

// finishRepo records, on each setting the repository policy decided, the
// value it replaced.
func (r *resolver) finishRepo() {
	for key, requested := range r.repoRequested {
		if s, ok := r.eff.settings[key]; ok && s.Source == SourceRepo && s.Requested == "" {
			s.Requested = requested
			r.eff.settings[key] = s
		}
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
