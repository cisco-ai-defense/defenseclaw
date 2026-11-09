// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package assetfacts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

// Kinds of asset a Content describes.
const (
	ContentSkill  = "skill"
	ContentPlugin = "plugin"
)

const (
	maxContentFiles   = 64
	maxContentFile    = 64 << 10
	maxContentEscaped = 96 << 10
	// maxContentTotal bounds the escaped text of every content in one fact
	// set, so that the facts decode within maxDecodedBytes with the most an
	// MCP definition adds (its pins). It holds the ordinary text of the many
	// candidate owners one plugin tool name can have (an install per
	// version, and a plugin per name prefix: a tool name of at most 64
	// characters has about 26 of the first), each up to maxContentEscaped.
	// Whether the encoded header fits is decided by Encode, on the deflated
	// size: ordinary documentation shrinks to a fraction, and a set that
	// still does not fit keeps its contents as truncated ones, which the
	// gateway refuses.
	maxContentTotal = 3 << 20
	// contentFraming is charged to maxContentTotal for each content, with
	// its name and folder, so that the number of contents is bounded by the
	// same budget as their text and not by a count a valid set of candidate
	// owners could pass.
	contentFraming    = 64
	maxContentEntries = 512
	maxContentDepth   = 4
	maxRegistryBytes  = 4 << 20
)

// Content is the text of one skill or plugin folder the hook read as the
// user, bounded. A managed Windows gateway reads nothing in a profile, so it
// has no other way to judge what the folder says (GAP-0699, GAP-0701). Like
// every fact it is the hook's claim.
type Content struct {
	Kind string `json:"kind"`
	// Name is the folder name of a skill, the plugin name of a plugin.
	Name string `json:"name"`
	Dir  string `json:"dir"`
	// Digest is ContentDigest of Files; the receiver recomputes it.
	Digest string        `json:"digest,omitempty"`
	Files  []ContentFile `json:"files,omitempty"`
	// Truncated says the folder holds more than Files: files over the bounds,
	// links that do not lead to a text file, text that is not UTF-8 or past
	// the entry limit. A verdict on Files is then not a verdict on the folder.
	Truncated bool `json:"truncated,omitempty"`
}

// ContentFile is one text file of a Content, with its path below the folder.
type ContentFile struct {
	Rel  string `json:"rel"`
	Text string `json:"text"`
}

// ContentDigest is a hex SHA-256 over the paths and text of files.
func ContentDigest(files []ContentFile) string {
	sum := sha256.New()
	for _, file := range files {
		sum.Write([]byte(file.Rel))
		sum.Write([]byte{0})
		sum.Write([]byte(file.Text))
		sum.Write([]byte{0})
	}
	return hex.EncodeToString(sum.Sum(nil))
}

// ContentsFor returns the claimed contents of the assets of that kind and
// name (a plugin may be installed in more than one folder).
func (f Facts) ContentsFor(kind, name string) []Content {
	var out []Content
	for _, content := range f.Contents {
		if content.Kind == kind && strings.EqualFold(content.Name, strings.TrimSpace(name)) {
			out = append(out, content)
		}
	}
	return out
}

// UnreadContent is the failure state of an asset the hook found or was
// told of but could not read: a truncated content without text, which the
// gateway refuses as unscanned. dir may be empty when no folder is known.
func UnreadContent(kind, name, dir string) Content {
	out := Content{Kind: kind, Name: name, Truncated: true}
	if dir != "" {
		out.Dir = filepath.Clean(dir)
	}
	return out
}

var contentTextExt = map[string]bool{
	"": true, ".md": true, ".txt": true, ".json": true, ".yaml": true, ".yml": true, ".toml": true,
	".py": true, ".js": true, ".mjs": true, ".cjs": true, ".ts": true, ".sh": true, ".ps1": true,
	".bat": true, ".cmd": true, ".rb": true,
}

var contentSkipDir = map[string]bool{".git": true, "node_modules": true, "__pycache__": true}

// ReadContent reads the text files of the folder dir, within the bounds a
// hook fact carries: the files nearest the root first, SKILL.md and the
// manifests among them. A folder that is a link, and a file that is a link
// to a text file, are read through, as the agent reads them; any other link
// marks the content Truncated. ok is false when dir is not a readable
// folder.
func ReadContent(kind, name, dir string) (Content, bool) {
	out := Content{Kind: kind, Name: name, Dir: filepath.Clean(dir)}
	if !shareAnswers(dir) {
		return Content{}, false
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return Content{}, false
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		real, err := filepath.EvalSymlinks(dir)
		if err != nil {
			return Content{}, false
		}
		dir = real
		if info, err = os.Stat(dir); err != nil {
			return Content{}, false
		}
	}
	if !info.IsDir() {
		return Content{}, false
	}
	type candidate struct {
		rel   string
		depth int
		size  int64
	}
	var found []candidate
	visited := 0
	_ = filepath.WalkDir(dir, func(p string, entry fs.DirEntry, err error) error {
		if err != nil {
			out.Truncated = true
			return nil
		}
		if p == dir {
			return nil
		}
		if visited++; visited > maxContentEntries {
			out.Truncated = true
			return filepath.SkipAll
		}
		rel, relErr := filepath.Rel(dir, p)
		if relErr != nil {
			return nil
		}
		depth := strings.Count(filepath.ToSlash(rel), "/")
		switch {
		case entry.Type()&fs.ModeSymlink != 0:
			target, statErr := os.Stat(p)
			switch {
			case statErr != nil || !target.Mode().IsRegular():
				out.Truncated = true
			case contentTextExt[strings.ToLower(filepath.Ext(entry.Name()))]:
				found = append(found, candidate{rel: filepath.ToSlash(rel), depth: depth, size: target.Size()})
			}
		case entry.IsDir():
			if contentSkipDir[entry.Name()] {
				return filepath.SkipDir
			}
			if depth >= maxContentDepth {
				out.Truncated = true
				return filepath.SkipDir
			}
		case entry.Type().IsRegular():
			if !contentTextExt[strings.ToLower(filepath.Ext(entry.Name()))] {
				return nil
			}
			size := int64(0)
			if fi, err := entry.Info(); err == nil {
				size = fi.Size()
			}
			found = append(found, candidate{rel: filepath.ToSlash(rel), depth: depth, size: size})
		default:
			out.Truncated = true
		}
		return nil
	})
	sort.SliceStable(found, func(i, j int) bool {
		a, b := found[i], found[j]
		if a.depth != b.depth {
			return a.depth < b.depth
		}
		return a.rel < b.rel
	})
	escaped := 0
	for _, c := range found {
		if len(out.Files) == maxContentFiles {
			out.Truncated = true
			break
		}
		raw, truncated := readPrefix(filepath.Join(dir, filepath.FromSlash(c.rel)), maxContentFile)
		if raw == nil || !utf8.Valid(raw) || strings.IndexByte(string(raw), 0) >= 0 {
			out.Truncated = true
			continue
		}
		text := string(raw)
		quoted, _ := json.Marshal(text)
		if escaped+len(quoted) > maxContentEscaped {
			out.Truncated = true
			continue
		}
		escaped += len(quoted)
		out.Truncated = out.Truncated || truncated || c.size > maxContentFile
		out.Files = append(out.Files, ContentFile{Rel: c.rel, Text: text})
	}
	out.Digest = ContentDigest(out.Files)
	return out, true
}

// readPrefix reads at most limit bytes of a regular file, or of the regular
// file a link leads to; nil when it cannot.
func readPrefix(p string, limit int) (data []byte, truncated bool) {
	info, err := os.Stat(p)
	if err != nil || !info.Mode().IsRegular() {
		return nil, false
	}
	file, err := os.Open(p)
	if err != nil {
		return nil, false
	}
	defer file.Close()
	data, err = io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, false
	}
	if len(data) > limit {
		return data[:limit], true
	}
	return data, false
}

// claudePluginRegistry reads plugins/installed_plugins.json under claudeDir.
func claudePluginRegistry(claudeDir string) map[string]json.RawMessage {
	data, _ := readPrefix(filepath.Join(claudeDir, "plugins", "installed_plugins.json"), maxRegistryBytes)
	if data == nil {
		return nil
	}
	var registry struct {
		Plugins map[string]json.RawMessage `json:"plugins"`
	}
	if json.Unmarshal(data, &registry) != nil {
		return nil
	}
	return registry.Plugins
}

// ClaudePluginRoots lists the install folders of the Claude Code plugin
// called plugin in the registry under claudeDir.
func ClaudePluginRoots(claudeDir, plugin string) []string {
	plugin = strings.TrimSpace(plugin)
	if plugin == "" {
		return nil
	}
	type record struct {
		InstallPath string `json:"installPath"`
	}
	var roots []string
	for id, raw := range claudePluginRegistry(claudeDir) {
		if name, _, _ := strings.Cut(id, "@"); !strings.EqualFold(strings.TrimSpace(name), plugin) {
			continue
		}
		var records []record
		if json.Unmarshal(raw, &records) != nil {
			var one record
			if json.Unmarshal(raw, &one) != nil {
				continue
			}
			records = []record{one}
		}
		for _, r := range records {
			if root := strings.TrimSpace(r.InstallPath); filepath.IsAbs(root) {
				roots = append(roots, filepath.Clean(root))
			}
		}
	}
	sort.Strings(roots)
	return roots
}

// ClaudePluginNames lists the names of the Claude Code plugins in the
// registry under claudeDir.
func ClaudePluginNames(claudeDir string) []string {
	var names []string
	for id := range claudePluginRegistry(claudeDir) {
		if name, _, _ := strings.Cut(id, "@"); strings.TrimSpace(name) != "" {
			names = append(names, strings.TrimSpace(name))
		}
	}
	sort.Strings(names)
	return names
}

// maxContentStubs bounds the contents kept as a failure state only.
const maxContentStubs = 32

// boundedContents applies the bounds of a hook fact to claimed contents and
// recomputes their digests. A content is never dropped for not fitting: one
// whose folder path is too long or unusable keeps its text and loses the
// path, and one past the size budget is kept as a truncated content without
// text, which the gateway refuses as unscanned. Dropping it would let the
// asset run unjudged. Every content that fits the budget keeps its text,
// however many candidate owners of one tool name there are.
func boundedContents(in []Content) []Content {
	var out []Content
	total, stubs := 0, 0
	stubbed := map[string]bool{}
	for _, content := range in {
		if content.Kind != ContentSkill && content.Kind != ContentPlugin {
			continue
		}
		name, dir := clean(content.Name, maxNameBytes), clean(content.Dir, maxFieldBytes)
		if name == "" {
			continue
		}
		if !filepath.IsAbs(dir) {
			dir = ""
		} else {
			dir = filepath.Clean(dir)
		}
		next := Content{Kind: content.Kind, Name: name, Dir: dir, Truncated: content.Truncated}
		if total+len(name)+len(dir)+contentFraming > maxContentTotal {
			// One failure state per asset name is enough: the gateway refuses
			// the asset when any of its contents is truncated.
			key := content.Kind + "\x00" + strings.ToLower(name)
			if !stubbed[key] && stubs < maxContentStubs {
				stubbed[key] = true
				stubs++
				next.Truncated = true
				out = append(out, next)
			}
			continue
		}
		total += len(name) + len(dir) + contentFraming
		escaped := 0
		for _, file := range content.Files {
			rel := clean(file.Rel, maxFieldBytes)
			if len(next.Files) == maxContentFiles || rel == "" || path.IsAbs(rel) || len(file.Text) > maxContentFile || !utf8.ValidString(file.Text) {
				next.Truncated = true
				continue
			}
			quoted, _ := json.Marshal(file.Text)
			if escaped+len(quoted) > maxContentEscaped || total+len(quoted) > maxContentTotal {
				next.Truncated = true
				continue
			}
			escaped += len(quoted)
			total += len(quoted)
			next.Files = append(next.Files, ContentFile{Rel: rel, Text: file.Text})
		}
		next.Digest = ContentDigest(next.Files)
		out = append(out, next)
	}
	return out
}

func hasContentFiles(in []Content) bool {
	for _, content := range in {
		if len(content.Files) > 0 {
			return true
		}
	}
	return false
}

// withoutContentFiles returns in with the text removed and every content
// marked truncated.
func withoutContentFiles(in []Content) []Content {
	out := make([]Content, len(in))
	for i, content := range in {
		out[i] = Content{Kind: content.Kind, Name: content.Name, Dir: content.Dir, Truncated: true}
	}
	return out
}
