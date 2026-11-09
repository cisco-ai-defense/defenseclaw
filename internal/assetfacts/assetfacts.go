// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package assetfacts holds what asset_policy needs to know about an agent
// asset beyond the name a hook names: the name a skill folder declares in
// its SKILL.md, the skill folders a tool call reaches into, and how an MCP
// server is configured.
//
// A standalone gateway runs as a service account. On Linux and macOS it
// cannot read the home of the user whose hook it answers (the unit runs
// with ProtectHome), so the standalone hook, which runs as that user, reads
// these facts and sends them in Header. They are claims: the gateway uses a
// declared skill name only to match denied rules, never to admit an asset,
// and an MCP server definition only for the server the tool call names.
package assetfacts

import (
	"bytes"
	"compress/flate"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/mcplocal"
)

// Header carries the encoded Facts on a standalone hook request.
const Header = "X-DefenseClaw-Asset-Facts"

const (
	// maxHeaderBytes bounds the encoded facts. It holds the ordinary text of
	// the most candidate owners one plugin tool name can have (23, each up to
	// the per-file and escaped-text caps of content.go) even when the text
	// does not shrink, together with the most an MCP definition adds. The
	// gateway servers that take the hook request read headers up to
	// MaxRequestHeaderBytes, which leaves room for the other headers. Their
	// worst case is about 2.4 MiB of text (random printable characters deflate
	// to four fifths). The argument digests of a Codex project definition (up
	// to 0.7 MiB) come with a request that selects no plugin.
	maxHeaderBytes = 3 << 20
	// MaxRequestHeaderBytes is the request header limit of a gateway server
	// that takes a hook request: the largest Header value plus room for the
	// other headers (the net/http default of 1 MiB cannot carry it).
	MaxRequestHeaderBytes = maxHeaderBytes + 64<<10
	// compressedPrefix marks a header value whose JSON is deflated before
	// the base64 step ('.' is not in the base64url alphabet, so it cannot be
	// mistaken for the plain form). Only a large value is deflated: the
	// ordinary small claim keeps the plain form and its cost.
	compressedPrefix = "z."
	compressAbove    = 16 << 10
	// maxDecodedBytes bounds the JSON a header value may expand to, so that a
	// small deflated value cannot make the gateway allocate without limit.
	maxDecodedBytes = 8 << 20
	maxSkills       = 16
	// maxSkillLinks, maxSkillLinkBytes and maxSkillLinkPathBytes bound the
	// linked skill folders a claim carries: their number, their text in all
	// and one path (a Windows path can be 32 KiB). They are the evidence a
	// gateway that cannot follow a link has, so the bounds are far past any
	// ordinary call, and a link the claim does not carry for any reason says
	// so (Facts.SkillLinksTruncated).
	maxSkillLinks         = 4096
	maxSkillLinkBytes     = 512 << 10
	maxSkillLinkPathBytes = 32 << 10
	maxFieldBytes         = 1024
	maxArgs               = 32
	// maxPinArgs bounds the argument digests a claim carries: a definition
	// past maxArgs still pins every argument a deny prefix can sensibly name.
	// A prefix longer than this cannot be ruled out and is refused.
	maxPinArgs = 2048
	// maxTailPins bounds the argument digests (MCPPins.Tail, pinTailDigestLen
	// bytes each) that follow the maxPinArgs full ones, so a deny prefix that
	// differs deep in a long argument list is still ruled out. An argument
	// past both bounds cannot be ruled out and is refused as a possible match.
	// The bound is the one the one-byte digests had (65,536 positions): a
	// wider digest must not shorten the list an ordinary call can have.
	maxTailPins = 1 << 16
	// pinTailDigestLen is the byte length of a tail digest. It is as wide as
	// the full ones (pinArgDigestLen hex characters), so an argument that is
	// not the one a rule names has no practical chance of sharing it: a
	// matching tail digest is decisive, not a coin flip that blocks an
	// ordinary call.
	pinTailDigestLen = pinArgDigestLen / 2
	// maxPinArgCount bounds the argument count a claim states; it is a
	// sanity bound, not a clamp that could rule out an exact deny.
	maxPinArgCount = math.MaxInt32
	// pinArgDigestLen is the hex length of an argument digest: a collision
	// only makes a rule "may match", the safe side.
	pinArgDigestLen  = 16
	maxManifestBytes = 64 << 10
	maxNameBytes     = 255
	maxInputStrings  = 64
	maxInputDepth    = 4
	maxProjectLevels = 16
)

// Facts are the claims one hook request carries.
type Facts struct {
	// Skills lists skill folders the request names or reaches into whose
	// SKILL.md declares another name.
	Skills []Skill `json:"skills,omitempty"`
	// MCP is the configuration of the MCP server the tool call names.
	MCP *MCPServer `json:"mcp,omitempty"`
	// MCPUnproven names the MCP server the tool call names when the agent
	// loads its servers from a command-line source the hook could not read,
	// so no definition of it can be proven (GAP-0954).
	MCPUnproven string `json:"mcp_unproven,omitempty"`
	// SkillDirs lists the folders of the skill a request selects by name
	// that exist in the skill folders of its agent, found as the user. The
	// gateway takes only folders it would look at itself (GAP-1212).
	SkillDirs []string `json:"skill_dirs,omitempty"`
	// SkillLinks lists the skill folders a path in the request reaches
	// through a link, resolved as the user: a gateway that may not read the
	// profile cannot follow the link itself and so would judge only the
	// spelling of the path.
	SkillLinks []string `json:"skill_links,omitempty"`
	// SkillLinksTruncated says a linked folder the hook found is not in
	// SkillLinks (past the bounds, or a path the claim cannot carry): the
	// gateway cannot rule out that it is held or denied, so it refuses the
	// call as unproven when it has a held or denied skill to protect, instead
	// of judging only the folders it was told of.
	SkillLinksTruncated bool `json:"skill_links_truncated,omitempty"`
	// SkillLinksUnproven says a network share a path of the request is on did
	// not answer within the hook call's wait for shares, so the links on it
	// were not followed: a skill folder a link there leads to is not shown. The
	// gateway judges it by the policy tier when it has a held or denied skill
	// to protect, as it judges any check it could not finish.
	SkillLinksUnproven bool `json:"skill_links_unproven,omitempty"`
	// SkillsTruncated says Skills holds only the first maxSkills claims: a
	// folder the request reaches into may declare a name no claim names, so
	// a gateway that cannot read it cannot prove it is not a denied skill
	// (GAP-1303).
	SkillsTruncated bool `json:"skills_truncated,omitempty"`
	// Contents holds the text of the skill or plugin folders the request
	// selects, read as the user, for a gateway that may not read a profile
	// (GAP-0699, GAP-0701).
	Contents []Content `json:"contents,omitempty"`
}

// SourceCommandLine marks an MCP definition read from the agent's command
// line (claude --mcp-config, codex -c mcp_servers.*), which takes precedence
// over every config file the gateway can read.
const SourceCommandLine = "command-line"

// Skill is one skill folder and the name its SKILL.md frontmatter declares.
type Skill struct {
	Folder   string `json:"folder"`
	Declared string `json:"declared"`
}

// MCPServer is an MCP server definition from the agent configuration.
type MCPServer struct {
	Name      string   `json:"name"`
	URL       string   `json:"url,omitempty"`
	Command   string   `json:"command,omitempty"`
	Args      []string `json:"args,omitempty"`
	Transport string   `json:"transport,omitempty"`
	// LocalRefusal is the scanner verdict on the complete definition of a
	// local server, taken by the hook that read it: Args holds at most
	// maxArgs arguments, and the verdict depends on all of them (an
	// execution flag or the package may be past the bound). A mcplocal
	// class, empty when the hook did not state it.
	LocalRefusal string `json:"local_refusal,omitempty"`
	// ArgsCut says the hook read more arguments than Args holds, so Args is
	// the start of the list and an exact allow of the complete list cannot be
	// checked against it.
	ArgsCut bool `json:"args_cut,omitempty"`
	// Source is SourceCommandLine for a definition from the agent's command
	// line, "" for one from its config files.
	Source string `json:"source,omitempty"`
	// Relocated marks a user-scope, non-built-in definition the hook read
	// from the config file of a CODEX_HOME other than ~/.codex: the file the
	// agent runs, which a gateway reading the default one would miss. A
	// managed Windows gateway admits it only when the enumerator published
	// the same definition (GAP-0686).
	Relocated bool `json:"relocated,omitempty"`
	// ProjectScope marks a definition the hook read from a project
	// .codex/config.toml, which takes precedence over the user config and
	// which a managed Windows enumerator does not publish (GAP-0686).
	ProjectScope bool `json:"project,omitempty"`
	// Digest is config.MCPLaunchDigest of the complete definition the hook
	// read, set with Relocated or ProjectScope. The fields above are bounded
	// and carry no environment, so a gateway that holds the published record
	// compares the digest, never the bounded fields.
	Digest string `json:"digest,omitempty"`
	// Pins holds, for a claim whose definition does not fit the bounds, what
	// a rule that pins where the server points can be checked against: a
	// SHA-256 of each value a rule compares exactly. A gateway tells a deny
	// pinned to another endpoint from one that may match, instead of
	// refusing every server of that name.
	Pins *MCPPins `json:"pins,omitempty"`
}

// VerdictUnstatedCut reports a claim of a hook that stated no verdict and
// holds as many arguments as the bound keeps: its Args can be the start of a
// longer list, so the gateway reads a verdict out of them only as far as they
// prove it (mcplocal.Proven).
func (s MCPServer) VerdictUnstatedCut() bool { return s.LocalRefusal == "" && len(s.Args) >= maxArgs }

// ArgsMayBeCut reports a claim whose Args can be the first maxArgs of a longer
// list: an exact allow of the complete argument list does not match it.
func (s MCPServer) ArgsMayBeCut() bool { return s.ArgsCut || s.VerdictUnstatedCut() }

// MCPPins are the SHA-256 digests (hex) of the values an asset_policy rule
// compares on an MCP server, taken from the complete definition the hook
// read: the trimmed URL, the base name of the trimmed command, and each
// trimmed argument (up to maxPinArgs, as PinArgSum), then the same-width
// digest of each further argument (Tail, up to maxTailPins), with the count
// of arguments and the transport.
type MCPPins struct {
	URL      string   `json:"url,omitempty"`
	Command  string   `json:"command,omitempty"`
	Args     []string `json:"args,omitempty"`
	ArgCount int      `json:"arg_count,omitempty"`
	// Tail holds PinTailDigest of the arguments from position len(Args) on,
	// concatenated and base64url encoded, only when Args is full. A digest
	// that differs rules a deny out; one that matches keeps it.
	Tail      string `json:"tail,omitempty"`
	Transport string `json:"transport,omitempty"`
}

// TailBytes are the decoded Tail digests, pinTailDigestLen bytes per
// argument and whole digests only, or nil.
func (p *MCPPins) TailBytes() []byte {
	if p == nil || p.Tail == "" {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(p.Tail)
	if err != nil {
		return nil
	}
	return raw[:min(len(raw)/pinTailDigestLen, maxTailPins)*pinTailDigestLen]
}

// TailDigestAt is the digest at position i of tail (TailBytes, decoded once
// by the caller: the argument at position len(Args)+i), or nil when the claim
// holds none there.
func TailDigestAt(tail []byte, i int) []byte {
	if i < 0 || (i+1)*pinTailDigestLen > len(tail) {
		return nil
	}
	return tail[i*pinTailDigestLen : (i+1)*pinTailDigestLen]
}

// Encode renders facts as a header value, or "" when there is nothing to
// send. The cap fits every bounded fact set, including escaped arguments;
// otherwise an oversized MCP definition could silently lose a pinned deny.
func Encode(facts Facts) string {
	facts.MCP = withLocalRefusal(facts.MCP)
	facts = bounded(facts)
	if len(facts.Skills) == 0 && facts.MCP == nil && facts.MCPUnproven == "" && len(facts.SkillDirs) == 0 && len(facts.SkillLinks) == 0 && !facts.SkillLinksTruncated && !facts.SkillLinksUnproven && !facts.SkillsTruncated && len(facts.Contents) == 0 {
		return ""
	}
	var raw bytes.Buffer
	encoder := json.NewEncoder(&raw)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(facts) != nil {
		return ""
	}
	plain := bytes.TrimSuffix(raw.Bytes(), []byte{10})
	value := base64.RawURLEncoding.EncodeToString(plain)
	if len(value) > compressAbove {
		if packed, ok := deflate(plain); ok && len(packed) < len(value) {
			value = packed
		}
	}
	if len(value) > maxHeaderBytes {
		if len(facts.Contents) > 0 && hasContentFiles(facts.Contents) {
			// Too much text for one header: keep the facts, and the contents
			// as truncated ones without text, which the gateway refuses as
			// unknown; dropping them would let the asset run unjudged.
			facts.Contents = withoutContentFiles(facts.Contents)
			return Encode(facts)
		}
		return ""
	}
	return value
}

// withLocalRefusal states the scanner verdict on a local server from its
// complete definition, which only the hook that reads it has: bounded keeps at
// most maxArgs arguments, and a refusal may depend on one past them (GAP-0925).
func withLocalRefusal(server *MCPServer) *MCPServer {
	if server == nil || server.LocalRefusal != "" || strings.TrimSpace(server.URL) != "" || strings.TrimSpace(server.Command) == "" {
		return server
	}
	stated := *server
	stated.LocalRefusal = mcplocal.Class(server.Command, server.Args)
	return &stated
}

// deflate renders json as a compressed header value: the prefix and the
// base64url of the deflated bytes. Ordinary text (the candidate owners of one
// tool name, each a few tens of KiB of documentation) shrinks to a fraction of
// its size; digests do not, and keep their own bound.
func deflate(json []byte) (string, bool) {
	var packed bytes.Buffer
	writer, err := flate.NewWriter(&packed, flate.DefaultCompression)
	if err != nil {
		return "", false
	}
	if _, err := writer.Write(json); err != nil || writer.Close() != nil {
		return "", false
	}
	return compressedPrefix + base64.RawURLEncoding.EncodeToString(packed.Bytes()), true
}

// decodeValue returns the JSON a header value carries, or false when it is
// malformed or expands past maxDecodedBytes.
func decodeValue(value string) ([]byte, bool) {
	rest, compressed := strings.CutPrefix(value, compressedPrefix)
	raw, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil {
		return nil, false
	}
	if !compressed {
		return raw, true
	}
	reader := flate.NewReader(bytes.NewReader(raw))
	defer reader.Close()
	out, err := io.ReadAll(io.LimitReader(reader, maxDecodedBytes+1))
	if err != nil || len(out) > maxDecodedBytes {
		return nil, false
	}
	return out, true
}

// Decode parses a header value. ok is false for an absent, oversized or
// malformed value; the fields are bounded as Encode bounds them.
func Decode(value string) (Facts, bool) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxHeaderBytes {
		return Facts{}, false
	}
	raw, ok := decodeValue(value)
	if !ok {
		return Facts{}, false
	}
	var facts Facts
	if json.Unmarshal(raw, &facts) != nil {
		return Facts{}, false
	}
	facts = bounded(facts)
	return facts, len(facts.Skills) > 0 || facts.MCP != nil || facts.MCPUnproven != "" || len(facts.SkillDirs) > 0 || len(facts.SkillLinks) > 0 || facts.SkillLinksTruncated || facts.SkillLinksUnproven || facts.SkillsTruncated || len(facts.Contents) > 0
}

// DeclaredFor returns the names the facts say folder declares.
func (f Facts) DeclaredFor(folder string) []string {
	var out []string
	for _, skill := range f.Skills {
		if sameFolderName(skill.Folder, folder) {
			out = append(out, skill.Declared)
		}
	}
	return out
}

// sameFolderName reports whether two folder names are the same folder: exactly,
// or (for a claim from a hook that trimmed the name) once surrounding space is
// trimmed from names that hold more than space.
func sameFolderName(a, b string) bool {
	if strings.EqualFold(a, b) {
		return true
	}
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	return a != "" && strings.EqualFold(a, b)
}

func bounded(facts Facts) Facts {
	var skills []Skill
	for _, skill := range facts.Skills {
		// A folder name is exact: a folder named with space is a folder, and
		// trimming it to nothing would drop its claim. A claim that cannot be
		// carried is signalled, as one past the bound is.
		if skill.Folder == "" || strings.TrimSpace(skill.Declared) == "" {
			continue
		}
		folder, declared := cleanFileName(skill.Folder, maxNameBytes), clean(skill.Declared, maxNameBytes)
		if folder == "" || declared == "" || len(skills) == maxSkills {
			facts.SkillsTruncated = true
			continue
		}
		skills = append(skills, Skill{Folder: folder, Declared: declared})
	}
	facts.Skills = skills
	var dirs []string
	for _, dir := range facts.SkillDirs {
		if dir = clean(dir, maxFieldBytes); filepath.IsAbs(dir) && len(dirs) < maxSkills {
			dirs = append(dirs, filepath.Clean(dir))
		}
	}
	facts.SkillDirs = dirs
	var links []string
	linkBytes := 0
	for _, dir := range facts.SkillLinks {
		// A link that is not carried must be signalled, whatever the reason:
		// it is a folder the gateway would otherwise never look at.
		// The path is exact: trimming a folder named with space would name
		// its parent.
		dir = cleanFileName(dir, maxSkillLinkPathBytes)
		if !filepath.IsAbs(dir) || len(links) == maxSkillLinks || linkBytes+len(dir) > maxSkillLinkBytes {
			facts.SkillLinksTruncated = true
			continue
		}
		linkBytes += len(dir)
		links = append(links, filepath.Clean(dir))
	}
	facts.SkillLinks = links
	facts.Contents = boundedContents(facts.Contents)
	if server := facts.MCP; server != nil {
		out := MCPServer{
			Name: clean(server.Name, maxNameBytes), URL: clean(server.URL, maxFieldBytes),
			Command: clean(server.Command, maxFieldBytes), Transport: clean(server.Transport, 64),
		}
		switch server.LocalRefusal {
		case mcplocal.None, mcplocal.Launcher, mcplocal.Arguments:
			out.LocalRefusal = server.LocalRefusal
		}
		out.ArgsCut = server.ArgsCut || len(server.Args) > maxArgs
		lossy := out.URL != strings.TrimSpace(server.URL) || out.Command != strings.TrimSpace(server.Command) ||
			out.Transport != strings.TrimSpace(server.Transport) || len(server.Args) > maxArgs
		for _, arg := range server.Args {
			if len(out.Args) == maxArgs {
				break
			}
			out.Args = append(out.Args, clean(arg, maxFieldBytes))
			lossy = lossy || out.Args[len(out.Args)-1] != strings.TrimSpace(arg)
		}
		commandLine := server.Source == SourceCommandLine
		unpublished := false
		if commandLine {
			out.Source = SourceCommandLine
		} else {
			out.Relocated, out.ProjectScope = server.Relocated, server.ProjectScope
			out.Digest = cleanDigest(server.Digest)
			unpublished = out.Relocated || out.ProjectScope
		}
		facts.MCP = nil
		switch {
		case out.Name != "" && unpublished && (lossy || (out.URL == "" && out.Command == "")):
			// The definition does not fit (or was already reduced to the name and
			// digest by an earlier pass): keep the claim without it, so the
			// gateway still knows an unpublished source runs and judges the
			// published record by its digest; falling back to the config
			// files it reads would judge another definition.
			facts.MCP = &MCPServer{Name: out.Name, Relocated: out.Relocated, ProjectScope: out.ProjectScope, Digest: out.Digest, Pins: pinsOf(*server)}
		case out.Name != "" && (out.URL != "" || out.Command != "") && !(commandLine && lossy):
			facts.MCP = &out
		case commandLine && facts.MCPUnproven == "":
			// A command-line definition that does not fit must not fall
			// back to the config files the gateway reads.
			facts.MCPUnproven = server.Name
		}
	}
	facts.MCPUnproven = clean(facts.MCPUnproven, maxNameBytes)
	return facts
}

// PinSum is the digest of one value as MCPPins holds it.
func PinSum(value string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(sum[:])
}

// PinTailDigest is the digest of one argument as MCPPins.Tail holds it: the
// first pinTailDigestLen bytes of the SHA-256 of the trimmed value.
func PinTailDigest(value string) []byte {
	sum := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return sum[:pinTailDigestLen]
}

// PinArgSum is the digest of one argument as MCPPins.Args holds it: the
// first pinArgDigestLen hex characters of PinSum.
func PinArgSum(value string) string { return PinSum(value)[:pinArgDigestLen] }

// PinArgMatches reports whether digest is PinArgSum(value). It allocates
// nothing, so a rule prefix of thousands of arguments is compared without
// garbage per argument.
func PinArgMatches(value, digest string) bool {
	if len(digest) != pinArgDigestLen {
		return false
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(value)))
	var hexed [pinArgDigestLen]byte
	hex.Encode(hexed[:], sum[:pinArgDigestLen/2])
	return string(hexed[:]) == digest
}

// PinTailMatches reports whether held is PinTailDigest(value), without
// allocating.
func PinTailMatches(value string, held []byte) bool {
	sum := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return bytes.Equal(sum[:pinTailDigestLen], held)
}

// pinsOf takes the pins of a definition: from its fields while it holds them,
// otherwise the ones an earlier pass already took, or none: a claim from a
// hook that took no pins cannot refute a rule.
func pinsOf(server MCPServer) *MCPPins {
	if server.URL == "" && server.Command == "" && len(server.Args) == 0 {
		if server.Pins == nil {
			return nil
		}
		pins := MCPPins{
			URL: cleanDigest(server.Pins.URL), Command: cleanDigest(server.Pins.Command),
			ArgCount: min(max(server.Pins.ArgCount, 0), maxPinArgCount), Transport: clean(server.Pins.Transport, 64),
		}
		for _, arg := range server.Pins.Args {
			if sum := cleanArgDigest(arg); sum != "" && len(pins.Args) < maxPinArgs {
				pins.Args = append(pins.Args, sum)
			}
		}
		held := len(pins.Args)
		if held == maxPinArgs {
			// A tail follows only a full run of digests; its positions start
			// there.
			if tail := server.Pins.TailBytes(); len(tail) > 0 {
				pins.Tail = base64.RawURLEncoding.EncodeToString(tail)
				held += len(tail) / pinTailDigestLen
			}
		}
		pins.ArgCount = max(pins.ArgCount, held)
		return &pins
	}
	pins := MCPPins{ArgCount: len(server.Args), Transport: clean(server.Transport, 64)}
	var tail []byte
	if strings.TrimSpace(server.URL) != "" {
		pins.URL = PinSum(server.URL)
	}
	if command := strings.TrimSpace(server.Command); command != "" {
		pins.Command = PinSum(filepath.Base(command))
	}
	for i, arg := range server.Args {
		switch {
		case i < maxPinArgs:
			pins.Args = append(pins.Args, PinArgSum(arg))
		case len(tail) < maxTailPins*pinTailDigestLen:
			tail = append(tail, PinTailDigest(arg)...)
		}
	}
	if len(tail) > 0 {
		pins.Tail = base64.RawURLEncoding.EncodeToString(tail)
	}
	return &pins
}

// cleanDigest keeps a value only when it is a hex SHA-256.
func cleanDigest(value string) string { return cleanHexDigest(value, 64) }

// cleanArgDigest keeps a value only when it is a PinArgSum.
func cleanArgDigest(value string) string { return cleanHexDigest(value, pinArgDigestLen) }

func cleanHexDigest(value string, length int) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) != length {
		return ""
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return ""
		}
	}
	return value
}

// clean drops a value that is not valid UTF-8, holds a control character or
// is longer than limit; it trims surrounding space.
func clean(value string, limit int) string {
	value = strings.TrimSpace(value)
	if strings.ContainsFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return ""
	}
	return cleanFileName(value, limit)
}

// cleanFileName keeps a folder name or path as the file system holds it: no
// trim, and a control character (a tab, a newline) is kept, since the claim is
// JSON and a file name may hold one. It drops a value that is not valid UTF-8,
// that holds a NUL (no file name can), or that is longer than limit.
func cleanFileName(value string, limit int) string {
	if len(value) > limit || !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 {
		return ""
	}
	return value
}

// DeclaredSkillName returns the name the SKILL.md in dir declares in its
// frontmatter ("name: ..."), or "" when there is no readable regular
// SKILL.md or it declares none. Only the start of the file is read.
func DeclaredSkillName(dir string) string {
	if strings.TrimSpace(dir) == "" {
		return ""
	}
	path := filepath.Join(dir, "SKILL.md")
	// A manifest on a network share that has not answered is not read: the
	// hook would wait for the system connect timeout (ShareGate). That holds
	// for the folder a link of the path leads to as for the path as spelled.
	if !readableTarget(path) {
		return ""
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	return DeclaredSkillNameOf(file)
}

// DeclaredSkillNameOf returns the name the SKILL.md read from r declares in
// its frontmatter, or "" when it declares none. Only the start is read. A
// caller that opens the manifest as the agent does, through a link, uses it
// on the file it opened.
func DeclaredSkillNameOf(r io.Reader) string {
	data, err := io.ReadAll(io.LimitReader(r, maxManifestBytes))
	if err != nil {
		return ""
	}
	return frontmatterName(string(data))
}

func frontmatterName(text string) string {
	text = strings.TrimPrefix(text, "\ufeff")
	lines := strings.Split(text, "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != "---" {
		return ""
	}
	for _, line := range lines[1:] {
		line = strings.TrimRight(line, "\r")
		if trimmed := strings.TrimSpace(line); trimmed == "---" || trimmed == "..." {
			return ""
		}
		rest, ok := strings.CutPrefix(line, "name:")
		if !ok {
			continue
		}
		value := strings.TrimSpace(rest)
		if len(value) >= 2 && (value[0] == 0x22 || value[0] == 0x27) && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		} else if hash := strings.Index(value, " #"); hash >= 0 {
			value = strings.TrimSpace(value[:hash])
		}
		return clean(value, maxNameBytes)
	}
	return ""
}

// ProjectSkillDirs lists the folders, relative to a project folder, that
// connector loads project skills from.
func ProjectSkillDirs(connector string) []string {
	switch strings.ToLower(strings.TrimSpace(connector)) {
	case "claudecode":
		return []string{filepath.Join(".claude", "skills")}
	case "codex":
		return []string{filepath.Join(".agents", "skills"), filepath.Join(".codex", "skills")}
	case "copilot":
		return []string{filepath.Join(".github", "skills"), filepath.Join(".claude", "skills"), filepath.Join(".agents", "skills")}
	}
	return nil
}

// SkillRoots lists the folders connector loads skills from for a user with
// home and working folder cwd: the user skill folders and the project ones
// from cwd up to the repository root (or a few levels).
func SkillRoots(connector, home, cwd string) []string {
	var user []string
	switch strings.ToLower(strings.TrimSpace(connector)) {
	case "claudecode":
		user = []string{filepath.Join(".claude", "skills")}
	case "codex":
		user = []string{filepath.Join(".codex", "skills"), filepath.Join(".agents", "skills")}
	case "copilot":
		user = []string{filepath.Join(".copilot", "skills"), filepath.Join(".claude", "skills"), filepath.Join(".agents", "skills")}
	default:
		return nil
	}
	project := ProjectSkillDirs(connector)
	var roots []string
	if home = strings.TrimSpace(home); filepath.IsAbs(home) {
		for _, rel := range user {
			roots = append(roots, filepath.Join(home, rel))
		}
	}
	for _, dir := range projectLevels(home, cwd) {
		for _, rel := range project {
			roots = append(roots, filepath.Join(dir, rel))
		}
	}
	return roots
}

// SkillLinkConnectors are the connectors that load skills from folders; a link
// of any connector's call may lead into the skill root of another one (Codex
// reading a folder of the Claude Code skill root).
var SkillLinkConnectors = []string{"claudecode", "codex", "copilot"}

// KnownSkillRoots lists the skill folders of every connector in
// SkillLinkConnectors for a user with home and working folder cwd. A link is
// judged by the folder it ends in, whatever connector's call followed it, so a
// link claim is taken for a folder in any of these roots.
func KnownSkillRoots(home, cwd string) []string {
	var roots []string
	for _, connector := range SkillLinkConnectors {
		for _, root := range SkillRoots(connector, home, cwd) {
			if !slices.Contains(roots, root) {
				roots = append(roots, root)
			}
		}
	}
	return roots
}

// projectLevels lists the folders from cwd up to the repository root (or
// maxProjectLevels folders, stopping at home) a project skill folder is
// looked for in.
func projectLevels(home, cwd string) []string {
	dir := strings.TrimSpace(cwd)
	if !filepath.IsAbs(dir) {
		return nil
	}
	dir = filepath.Clean(dir)
	var levels []string
	for level := 0; level < maxProjectLevels; level++ {
		if home != "" && filepath.Clean(home) == dir {
			break
		}
		levels = append(levels, dir)
		if pathExists(filepath.Join(dir, ".git")) {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return levels
}

// CopilotHomeSet reports whether COPILOT_HOME is set: Copilot then loads its
// user skills from there and not from ~/.copilot, whether or not the value is
// usable.
func CopilotHomeSet() bool {
	_, exists := os.LookupEnv("COPILOT_HOME")
	return exists
}

// EnvSkillRoots lists the skill folders a connector takes from the
// environment of the agent process: Copilot's COPILOT_HOME and
// COPILOT_SKILLS_DIRS (comma separated; "~/" is the home, a relative one is
// below the folder Copilot runs in: launch when the hook can read it from the
// agent process, otherwise the guesses of launchWorkspaces). Only the
// standalone hook, which runs in the environment of the agent, can know them;
// the environment of a gateway is not the one of the user.
//
// launch reads the folder Copilot runs in from the agent process. It is called
// at most once and only for a relative entry, the one case that needs it, so a
// hook without such an entry never walks the process table.
func EnvSkillRoots(connector, home, cwd string, launch func() string) []string {
	if strings.ToLower(strings.TrimSpace(connector)) != "copilot" {
		return nil
	}
	var roots []string
	var launched string
	launchRead := false
	if configured, exists := os.LookupEnv("COPILOT_HOME"); exists {
		if strings.TrimSpace(configured) == configured && !strings.ContainsAny(configured, "\x00\r\n") &&
			filepath.IsAbs(configured) && filepath.Clean(configured) == configured {
			roots = append(roots, filepath.Join(configured, "skills"))
		}
	}
	for _, raw := range strings.Split(os.Getenv("COPILOT_SKILLS_DIRS"), ",") {
		dir := strings.TrimSpace(raw)
		switch {
		case dir == "":
			continue
		case strings.HasPrefix(dir, "~/") || strings.HasPrefix(dir, `~\`):
			if !filepath.IsAbs(home) {
				continue
			}
			dir = filepath.Join(home, dir[2:])
		case !filepath.IsAbs(dir):
			if !launchRead && launch != nil {
				launchRead, launched = true, launch()
			}
			for _, level := range launchWorkspaces(home, cwd, launched) {
				if root := filepath.Join(level, dir); !slices.Contains(roots, root) {
					roots = append(roots, root)
				}
			}
			continue
		}
		if dir = filepath.Clean(dir); !slices.Contains(roots, dir) {
			roots = append(roots, dir)
		}
	}
	return roots
}

// launchWorkspaces are the folders a relative COPILOT_SKILLS_DIRS entry can
// belong to: Copilot resolves it against the one folder it runs in, never
// against the folders between it and the repository root. launch is that
// folder as the hook read it from the agent process. When the hook knows it,
// it is the only root, whatever the event cwd is (below it, above it, beside
// it or absent): a skill of any other folder is not loaded, so judging it
// would decide the selection on a copy the agent never reads.
// Without it the hook sees only its event cwd, which is that folder or a
// folder below it, so the roots are cwd itself and the outermost folder above
// it that is a repository root, or home when no repository is found below
// home. A skill folder of an intermediate folder is not a guessed root, so it
// can neither be judged in place of the selected one nor hide it behind a
// nested repository or the home folder.
func launchWorkspaces(home, cwd, launch string) []string {
	if launch = strings.TrimSpace(launch); filepath.IsAbs(launch) {
		return []string{filepath.Clean(launch)}
	}
	dir := strings.TrimSpace(cwd)
	if !filepath.IsAbs(dir) {
		return nil
	}
	dir = filepath.Clean(dir)
	out := []string{dir}
	home = filepath.Clean(strings.TrimSpace(home))
	outer, homeAbove := "", ""
	for level := 0; level < maxProjectLevels; level++ {
		if pathExists(filepath.Join(dir, ".git")) {
			outer = dir
		}
		if home != "" && home == dir {
			homeAbove = dir
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	if outer == "" {
		outer = homeAbove
	}
	if outer != "" && outer != out[0] {
		out = append(out, outer)
	}
	return out
}

// SkillNameFromInput is the folder name of the skill a tool call selects
// through its arguments, under every spelling the gateway's skill probe
// reads (skill_name, skill, skill_key, a nested skill object, a skill path),
// or "" when it selects none. The hook reads the folder under the name the
// gateway will judge, so a spelling the gateway recognises cannot be one the
// hook skips.
func SkillNameFromInput(input map[string]any) string {
	first := func(values map[string]any, keys ...string) string {
		for _, key := range keys {
			if text, ok := values[key].(string); ok && strings.TrimSpace(text) != "" {
				return strings.TrimSpace(text)
			}
		}
		return ""
	}
	if raw := first(input, "skill_name", "skillName", "skill_key", "skillKey", "skill_id", "skillId"); raw != "" {
		return normalizeSkillName(raw)
	}
	for _, key := range []string{"skill", "skill_info", "skillInfo", "source_skill", "sourceSkill"} {
		switch value := input[key].(type) {
		case string:
			if name := normalizeSkillName(value); name != "" {
				return name
			}
		case map[string]any:
			raw := first(value, "name", "key", "id", "skill_name", "skillName", "skill_key", "skillKey", "skill_id", "skillId")
			if raw == "" {
				raw = first(value, "path", "source_path", "sourcePath", "skill_path", "skillPath")
			}
			if name := normalizeSkillName(raw); name != "" {
				return name
			}
		}
	}
	return normalizeSkillName(first(input, "skill_path", "skillPath", "source_path", "sourcePath"))
}

func normalizeSkillName(value string) string {
	name := strings.Trim(strings.TrimSpace(value), `"'`)
	if strings.ContainsAny(name, `/\`) {
		path := filepath.Clean(name)
		if strings.EqualFold(filepath.Base(path), "SKILL.md") {
			path = filepath.Dir(path)
		}
		name = filepath.Base(path)
	}
	return strings.TrimSpace(strings.TrimPrefix(name, "@"))
}

// FolderRef is a skill folder a tool call names: the folder path as far as
// it can be resolved and the folder name.
type FolderRef struct {
	Dir  string
	Name string
	// Manifest is set when the call names the folder's SKILL.md itself.
	Manifest bool
	// ExplicitDirectory means a leading static cd fixed the directory for
	// this reference, so a missing folder must not be resolved in other roots.
	ExplicitDirectory bool
	// Linked is set when the folder is the target of a link the call's path
	// goes through, not the spelling of the path.
	Linked bool
	// BareOperand is set when the call names the folder with a word that has
	// no slash and names an existing entry in the working folder (a link, or
	// SKILL.md from inside the folder): a gateway that cannot look into that
	// folder cannot tell the word from any other, so the hook reports it.
	BareOperand bool
}

// SkillFolderRefs lists the skill folders the strings of a tool input reach
// into: every distinct path with a "skills/<name>" pair of components, in a command
// line, a file path or a working folder. "~" and $HOME expand to home and
// a relative path resolves against cwd. tool is the name of the tool the call
// is for (it may be empty): a search tool that names no place searches cwd. A
// slash-free word is a path only where the call uses it as one (see
// operand_context.go).
func SkillFolderRefs(tool string, input any, home, cwd string, caller ...string) []FolderRef {
	account := ""
	if len(caller) > 0 {
		account = caller[0]
	}
	return skillFolderRefsForCaller(tool, input, home, cwd, account, os.Geteuid(), os.Getegid())
}

// SkillFolderRefsForPeer resolves a managed hook request using the kernel
// credentials of the caller, rather than the gateway service account.
func SkillFolderRefsForPeer(tool string, input any, home, cwd, caller string, uid, gid int) []FolderRef {
	return skillFolderRefsForCaller(tool, input, home, cwd, caller, uid, gid)
}

func skillFolderRefsForCaller(tool string, input any, home, cwd, account string, uid, gid int) []FolderRef {
	var fields []inputField
	collectFields(tool, input, "", 0, &fields)
	seen := map[string]int{}
	var refs []FolderRef
	addToken := func(token, dir string, explicit bool) {
		for _, ref := range skillFolderRefs(token, home, dir, account) {
			ref.ExplicitDirectory = explicit
			if index, ok := seen[ref.Dir]; ok {
				refs[index].Manifest = refs[index].Manifest || ref.Manifest
				refs[index].BareOperand = refs[index].BareOperand || ref.BareOperand
				refs[index].ExplicitDirectory = refs[index].ExplicitDirectory && explicit
				continue
			}
			seen[ref.Dir] = len(refs)
			refs = append(refs, ref)
		}
	}
	add := func(f inputField, text, dir string, explicit bool) {
		switch kindOfField(tool, f.key) {
		case kindPath:
			// One path, with the spaces and tabs of its folder names, and the
			// words it splits into as well.
			addToken(text, dir, explicit)
			if hasBlank(text) {
				for _, w := range shellWords(text, false, 0) {
					addToken(w.text, dir, explicit)
				}
			}
		case kindText:
			for _, w := range shellWords(text, false, 0) {
				if strings.ContainsAny(w.text, "/\\") {
					addToken(w.text, dir, explicit)
				}
			}
		default:
			words, cwdSearch := commandWords(text, f.argv)
			for _, w := range words {
				if w.mayNamePath() {
					addToken(w.text, dir, explicit)
				}
			}
			if cwdSearch {
				addToken(dir, dir, explicit)
			}
		}
	}
	if searchesWorkingFolder(tool, fields) {
		addToken(cwd, cwd, false)
	}
	for _, field := range fields {
		if field.argv != nil || kindOfField(tool, field.key) != kindCommand {
			add(field, field.text, cwd, false)
			continue
		}
		type position struct {
			value    string
			dir      string
			explicit bool
		}
		positions := []position{{value: field.text, dir: cwd}}
		for i := 0; i < 8; i++ {
			var nextPositions []position
			changed := false
			for _, current := range positions {
				prefix, rest, next, sequential, certain, ok := leadingSkillDirectoryChange(current.value, current.dir, home, account, uid, gid)
				if !ok {
					nextPositions = append(nextPositions, current)
					continue
				}
				changed = true
				add(field, prefix, current.dir, current.explicit)
				nextPositions = append(nextPositions, position{rest, next, true})
				if sequential && !certain {
					// A sequential successor runs in cwd when cd fails. A
					// gateway unable to prove entry must check both paths.
					nextPositions = append(nextPositions, position{rest, current.dir, current.explicit})
				}
			}
			if !changed {
				positions = nextPositions
				break
			}
			unique := make(map[position]bool, len(nextPositions))
			positions = positions[:0]
			for _, next := range nextPositions {
				if !unique[next] {
					unique[next] = true
					positions = append(positions, next)
				}
			}
		}
		for _, current := range positions {
			add(field, current.value, current.dir, current.explicit)
		}
	}
	return refs
}

// leadingSkillDirectoryChange follows a literal cd before another command.
// A command after a failed cd in a sequential list runs in the original dir.
func leadingSkillDirectoryChange(value, cwd, home, caller string, uid, gid int) (prefix, rest, dir string, sequential, certain, ok bool) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "cd ") && !strings.HasPrefix(value, "cd\t") {
		return "", "", "", false, false, false
	}
	var quote rune
	escaped := false
	for i, ch := range value {
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' && quote != '\'' {
			escaped = true
			continue
		}
		switch {
		case ch == '\'' || ch == '"':
			switch quote {
			case 0:
				quote = ch
			case ch:
				quote = 0
			}
		case quote == 0 && (ch == ';' || ch == '\n' ||
			ch == '&' && i+1 < len(value) && value[i+1] == '&'):
			prefix = value[:i]
			words := wordTexts(shellWords(prefix, true, 0))
			if len(words) != 2 || words[0] != "cd" || words[1] == "-" ||
				strings.ContainsAny(words[1], "*?[]{}$`") {
				return "", "", "", false, false, false
			}
			dir = words[1]
			if dir == "~" {
				dir = home
			} else if strings.HasPrefix(dir, "~/") {
				dir = filepath.Join(home, dir[2:])
			} else if caller != "" && strings.HasPrefix(dir, "~"+caller+"/") {
				dir = filepath.Join(home, strings.TrimPrefix(dir, "~"+caller+"/"))
			}
			if dir == "" || strings.HasPrefix(dir, "~") {
				return "", "", "", false, false, false
			}
			if !filepath.IsAbs(dir) {
				dir = filepath.Join(cwd, dir)
			}
			separatorWidth := 1
			if ch == '&' {
				separatorWidth = 2
			}
			// The links of the directory are followed as the path walk follows
			// them: one part at a time, and on a network share only once it
			// has answered. Entry is proven only for a directory that exists.
			original := dir
			dir = ResolveLinks(dir)
			if shareAnswers(original) && shareAnswers(dir) {
				if info, statErr := os.Stat(dir); statErr == nil && info.IsDir() {
					certain = callerCanEnterDirectory(original, uid, gid) && callerCanEnterDirectory(dir, uid, gid)
				}
			}
			return prefix, value[i+separatorWidth:], filepath.Clean(dir), ch != '&', certain, true
		}
	}
	return "", "", "", false, false, false
}

// pathInputKeys are the tool-input fields that usually carry a path or a
// command line. They are visited first so a large field such as the edits of
// a MultiEdit cannot push them past maxInputStrings (GAP-1301).
var pathInputKeys = map[string]bool{
	"file_path": true, "filePath": true, "notebook_path": true, "path": true,
	"paths": true, "file": true, "files": true, "target": true,
	"target_file": true, "targetFile": true, "dir": true, "directory": true,
	"cwd": true, "workdir": true, "working_directory": true,
	"command": true, "cmd": true,
}

// inputKeys orders a map's keys deterministically: path-bearing keys first,
// then the rest, each group sorted.
func inputKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		pi, pj := pathInputKeys[keys[i]], pathInputKeys[keys[j]]
		if pi != pj {
			return pi
		}
		return keys[i] < keys[j]
	})
	return keys
}

func isCommandSeparator(r rune) bool {
	switch r {
	case 0x20, 0x09, 0x0a, 0x0d, 0x22, 0x27, 0x60, 0x3b, 0x7c, 0x26, 0x28, 0x29, 0x3c, 0x3e, 0x3d, 0x2c:
		return true
	}
	return false
}

// msysDriveSpelling spells a Git Bash drive mount (/c/x, /cygdrive/c/x,
// and //c/x) as the drive path C:/x on Windows, where Git Bash, the shell
// Claude Code and other agents run, maps it to that drive: the deny list
// then sees one name for the folder whatever spelling a call uses
// (rel-1-0-6:GAP-0299). //c/x is read as the drive too, the cautious
// reading for a deny list. Elsewhere the path is returned unchanged.
func msysDriveSpelling(path string) string {
	if runtime.GOOS != "windows" || !strings.HasPrefix(path, "/") {
		return path
	}
	if len(path) > 3 && path[1] == '/' && path[3] == '/' {
		path = path[1:]
	}
	return actionfacts.MSYSDrivePath(path)
}

func skillFolderRefs(token, home, cwd, caller string) []FolderRef {
	bare := !strings.ContainsAny(token, "/\\")
	if bare && !namesEntryIn(cwd, token) {
		return nil
	}
	path := trimExtendedPrefix(strings.ReplaceAll(token, "\\", "/"))
	if caller != "" && !strings.ContainsAny(caller, "/\\") && strings.HasPrefix(path, "~"+caller+"/") && home != "" {
		path = filepath.ToSlash(home) + "/" + strings.TrimPrefix(path, "~"+caller+"/")
	}
	for _, prefix := range []string{"~/", "$HOME/", "${HOME}/"} {
		if strings.HasPrefix(path, prefix) && home != "" {
			path = filepath.ToSlash(home) + "/" + strings.TrimPrefix(path, prefix)
			break
		}
	}
	path = msysDriveSpelling(path)
	// Resolve the entire path before selecting skills/<name> pairs. A
	// parent segment can otherwise change which skill folders are reached.
	raw := filepath.FromSlash(path)
	if !filepath.IsAbs(raw) && strings.TrimSpace(cwd) != "" {
		raw = cwd + string(filepath.Separator) + raw
	}
	dir := filepath.Clean(raw)
	refs := skillFolderRefsIn(dir, false)
	for i := range refs {
		refs[i].BareOperand = bare
	}
	// A link anywhere on the path leads into a skill folder the spelling
	// does not show. The folder it ends in is judged as the direct path is.
	// The raw spelling is followed in the order the filesystem takes it: a
	// parent segment after a link leaves the folder the link leads to, not the
	// folder that holds the link. A path that cannot be followed (a missing
	// folder, one the caller may not enter) stays as written.
	if real := ResolveLinks(raw); real != dir {
		for _, ref := range skillFolderRefsIn(real, true) {
			ref.BareOperand = bare
			refs = append(refs, ref)
		}
	}
	return refs
}

// namesEntryIn reports whether the slash-free word token names an entry that
// exists in the folder cwd. A word that names one is a path, spelled as
// ./token would be: a link, or SKILL.md read from inside a skill folder. Any
// other word stays a word (a command, a flag, a pattern), so an ordinary call
// is not read as naming a folder. On a network share the entry is looked up
// only once the share has answered.
func namesEntryIn(cwd, token string) bool {
	if token == "" || !filepath.IsAbs(cwd) {
		return false
	}
	path := cwd + string(filepath.Separator) + token
	if !ShareAnswers(path) {
		return false
	}
	_, err := os.Lstat(path)
	return err == nil
}

// pathExists reports whether path exists; a path on a network share that has
// not answered reads as missing.
func pathExists(path string) bool {
	if !readableTarget(path) {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

// skillFolderRefsIn lists the skills/<name> pairs of the cleaned path dir.
func skillFolderRefsIn(dir string, linked bool) []FolderRef {
	parts := strings.Split(filepath.ToSlash(dir), "/")
	var refs []FolderRef
	for i := 0; i+1 < len(parts); i++ {
		if !strings.EqualFold(parts[i], "skills") {
			continue
		}
		name := parts[i+1]
		if name == "" || strings.HasPrefix(name, ".") || strings.EqualFold(name, "SKILL.md") || strings.ContainsAny(name, "*?[]{}$") {
			continue
		}
		skillDir := filepath.FromSlash(strings.Join(parts[:i+2], "/"))
		manifest := i+2 < len(parts) && strings.EqualFold(parts[i+2], "SKILL.md")
		refs = append(refs, FolderRef{Dir: skillDir, Name: name, Manifest: manifest, Linked: linked})
	}
	return refs
}

// maxLinkHops bounds the links ResolveLinks follows.
const maxLinkHops = 40

// ShareGate tells ResolveLinks whether the file system under path may be
// read: true for a local path and for a path on a network share that has
// answered, false for a share that has not (within the wait the hook call has
// for shares). The hookpaths package, which asks the shares, sets it at start
// (it imports this package, so this one cannot ask); with none set every path
// is read.
var ShareGate func(path string) bool

func shareAnswers(path string) bool { return ShareGate == nil || ShareGate(path) }

// ShareAnswers reports whether the hook may look path up (Lstat): it is local
// or on a network share that has answered (ShareGate), and so is the folder
// that holds it once the links on its way are followed, since the lookup goes
// where they lead. Lookups of a path a call names go through it.
func ShareAnswers(path string) bool {
	return ShareGate == nil || ShareGate(path) && ShareGate(ResolveLinks(filepath.Dir(path)))
}

// readableTarget reports whether the hook may read path: it, and the folder
// every link on it leads to, are local or on a network share that has
// answered. The read of a path whose folder is a link goes where the link
// leads, not where the spelling shows.
func readableTarget(path string) bool {
	return ShareGate == nil || ShareGate(path) && ShareGate(ResolveLinks(path))
}

// trimExtendedPrefix spells a Windows extended-length path (//?/C:/x,
// //./C:/x, //?/UNC/host/share/x, written with forward slashes) the usual way
// (C:/x, //host/share/x), so the links of the path are followed once, from a
// spelling the deny rules and the skill roots share. path uses forward
// slashes. A path of any other shape (a volume GUID) is returned unchanged.
func trimExtendedPrefix(path string) string {
	rest, ok := strings.CutPrefix(path, "//?/")
	if !ok {
		rest, ok = strings.CutPrefix(path, "//./")
	}
	switch {
	case !ok:
		return path
	case len(rest) >= 4 && strings.EqualFold(rest[:4], "unc/"):
		return "//" + rest[4:]
	case len(rest) >= 2 && rest[1] == 0x3a && (rest[0]|0x20) >= 0x61 && (rest[0]|0x20) <= 0x7a:
		return rest
	}
	return path
}

// ResolveLinks follows every link (symlink, junction or reparse point) in
// path, one component at a time in the order the filesystem takes them: a
// parent segment removes the last component of the path as resolved so far,
// so it leaves the folder a link leads to, not the folder that holds the link.
// A part on a network share (a Windows UNC path, or a path a link leads onto
// one) is examined only once the share has answered (ShareGate): reading its
// attributes opens a session with another machine, and one that does not
// answer holds the hook for the system connect timeout. A share that answers
// is followed like any folder, links on it included; the rest of a path after
// a share that did not answer stays as spelled.
// Pass the path as it is spelled; cleaning it first would drop that segment
// before the link in front of it is known. A link whose target is missing is
// read and followed all the same, so a link placed before its target exists
// leads the same way once it does. A part that cannot be examined (missing, or
// a folder the caller may not enter) is kept as written and the rest follows
// lexically after it: the spelling is then the only evidence there is. A
// relative path, or one with more than maxLinkHops links (a loop), comes back
// cleaned and unresolved.
func ResolveLinks(path string) string {
	if runtime.GOOS == "windows" {
		path = filepath.FromSlash(trimExtendedPrefix(filepath.ToSlash(path)))
	}
	volume := filepath.VolumeName(path)
	rest := filepath.ToSlash(path[len(volume):])
	if !strings.HasPrefix(rest, "/") {
		return filepath.Clean(path)
	}
	resolved := volume + string(filepath.Separator)
	pending := strings.Split(rest, "/")
	hops := 0
	for len(pending) > 0 {
		part := pending[0]
		pending = pending[1:]
		switch part {
		case "", ".":
			continue
		case "..":
			resolved = filepath.Dir(resolved)
			continue
		}
		next := filepath.Join(resolved, part)
		if !shareAnswers(next) {
			return filepath.Join(append([]string{next}, pending...)...)
		}
		info, err := os.Lstat(next)
		if err != nil || info.Mode()&(os.ModeSymlink|os.ModeIrregular) == 0 {
			resolved = next
			continue
		}
		target, err := os.Readlink(next)
		if err != nil {
			resolved = next
			continue
		}
		if hops++; hops > maxLinkHops {
			return filepath.Clean(path)
		}
		targetVolume := filepath.VolumeName(target)
		targetRest := filepath.ToSlash(target[len(targetVolume):])
		if strings.HasPrefix(targetRest, "/") {
			if targetVolume == "" {
				targetVolume = filepath.VolumeName(resolved)
			}
			resolved = targetVolume + string(filepath.Separator)
		}
		pending = append(strings.Split(targetRest, "/"), pending...)
	}
	// A path that exists and has no link left is spelled as the filesystem
	// spells it (a Windows short name, the case of a folder); a missing one
	// stays as written.
	if !shareAnswers(resolved) {
		return resolved
	}
	if real, err := filepath.EvalSymlinks(resolved); err == nil {
		return real
	}
	return resolved
}
