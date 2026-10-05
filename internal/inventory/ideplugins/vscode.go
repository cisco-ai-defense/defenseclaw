// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package ideplugins

import (
	"encoding/json"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// vscodeProduct is one VS Code-family editor: its home-relative dot
// directory (which holds extensions/), its user-data directory name and
// the dot directories of its Remote-SSH server.
type vscodeProduct struct {
	token    string
	channel  string
	dotDirs  []string
	dataName string
	servers  []string
}

var vscodeProducts = []vscodeProduct{
	{token: "vscode", channel: "stable", dotDirs: []string{".vscode"}, dataName: "Code", servers: []string{".vscode-server"}},
	{token: "vscode-insiders", channel: "insiders", dotDirs: []string{".vscode-insiders"}, dataName: "Code - Insiders", servers: []string{".vscode-server-insiders", ".vscode-insiders-server"}},
	{token: "vscodium", channel: "stable", dotDirs: []string{".vscode-oss", ".vscodium"}, dataName: "VSCodium", servers: []string{".vscodium-server", ".vscode-oss-server"}},
	{token: "cursor", channel: "stable", dotDirs: []string{".cursor"}, dataName: "Cursor", servers: []string{".cursor-server"}},
	{token: "windsurf", channel: "stable", dotDirs: []string{".windsurf"}, dataName: "Windsurf", servers: []string{".windsurf-server"}},
	{token: "devin-desktop", channel: "stable", dotDirs: []string{".devin"}, dataName: "Devin", servers: []string{".devin-server"}},
	{token: "kiro", channel: "stable", dotDirs: []string{".kiro"}, dataName: "Kiro", servers: []string{".kiro-server"}},
	{token: "trae", channel: "stable", dotDirs: []string{".trae"}, dataName: "Trae", servers: []string{".trae-server"}},
	{token: "void", channel: "stable", dotDirs: []string{".void-editor"}, dataName: "Void", servers: []string{".void-server"}},
	{token: "antigravity", channel: "stable", dotDirs: []string{".antigravity"}, dataName: "Antigravity", servers: []string{".antigravity-server"}},
	{token: "positron", channel: "stable", dotDirs: []string{".positron"}, dataName: "Positron", servers: []string{".positron-server"}},
}

const (
	vscodeDisabledKey     = "extensionsIdentifiers/disabled"
	vscodeMaxExtensions   = 8192
	vscodeMaxProfiles     = 64
	vscodeMaxServers      = 32
	vscodePackageMaxBytes = 512 << 10
)

func (s *scanner) scanVSCode() {
	for _, product := range vscodeProducts {
		for _, dot := range product.dotDirs {
			extDir := filepath.Join(s.layout.home, dot, "extensions")
			if !s.isDir(extDir) {
				continue
			}
			s.scanVSCodeLocal(product, extDir)
			break
		}
		for _, server := range product.servers {
			root := filepath.Join(s.layout.home, server)
			if !s.isDir(root) {
				continue
			}
			if extDir := filepath.Join(root, "extensions"); s.isDir(extDir) {
				inst := Install{Family: FamilyVSCode, Product: product.token, RemoteKind: RemoteSSHServer, Root: extDir}
				inst.Plugins = s.readVSCodeExtensions(extDir, ScopeRemote, nil, true)
				s.add(inst)
			}
			s.scanVSCodeServerBuilds(product, root)
		}
	}
}

func (s *scanner) scanVSCodeLocal(product vscodeProduct, extDir string) {
	inst := Install{Family: FamilyVSCode, Product: product.token, Channel: product.channel, Root: extDir}
	userDir := filepath.Join(s.layout.appSupport, product.dataName, "User")
	disabled, state := s.readVSCodeDisabled(filepath.Join(userDir, "globalStorage", "state.vscdb"))
	inst.Plugins = s.readVSCodeExtensions(extDir, ScopeUser, &vscodeState{disabled: disabled, known: state}, false)
	for _, profile := range s.subdirs(filepath.Join(userDir, "profiles"), vscodeMaxProfiles) {
		if !safeName(profile) {
			continue
		}
		profileDir := filepath.Join(userDir, "profiles", profile)
		manifest := filepath.Join(profileDir, "extensions.json")
		if !s.isFile(manifest) {
			continue
		}
		pd, pstate := s.readVSCodeDisabled(filepath.Join(profileDir, "globalStorage", "state.vscdb"))
		entries := s.readVSCodeManifest(manifest, extDir, "profile:"+clean(profile), &vscodeState{disabled: pd, known: pstate}, false)
		inst.Plugins = append(inst.Plugins, entries...)
	}
	s.add(inst)
}

// scanVSCodeServerBuilds records each server build under
// <server>/cli/servers/* as an installation of its own (it has no
// extensions; they live in <server>/extensions).
func (s *scanner) scanVSCodeServerBuilds(product vscodeProduct, root string) {
	builds := filepath.Join(root, "cli", "servers")
	for _, name := range s.subdirs(builds, vscodeMaxServers) {
		if !safeName(name) {
			continue
		}
		dir := filepath.Join(builds, name)
		version := ""
		if data, ok := s.readFileLimit(filepath.Join(dir, "server", "package.json"), vscodePackageMaxBytes); ok {
			var pkg struct {
				Version string `json:"version"`
			}
			if json.Unmarshal(data, &pkg) == nil {
				version = clean(pkg.Version)
			}
		}
		channel := ""
		if before, _, ok := strings.Cut(name, "-"); ok {
			channel = strings.ToLower(clean(before))
		}
		s.add(Install{Family: FamilyVSCode, Product: product.token, Channel: channel, RemoteKind: RemoteSSHServer, Version: version, Root: dir})
	}
}

// vscodeState is the disabled list of one profile; known is false when the
// state database exists but could not be read.
type vscodeState struct {
	disabled map[string]bool
	known    stateKnowledge
}

type stateKnowledge int

const (
	stateAbsent stateKnowledge = iota
	stateRead
	stateUnreadable
)

func (st *vscodeState) enabled(id string) (string, string) {
	if st == nil {
		return EnabledUnknown, SourceUnknown
	}
	switch st.known {
	case stateRead:
		if st.disabled[strings.ToLower(id)] {
			return EnabledOff, SourceStateDB
		}
		return EnabledOn, SourceStateDB
	case stateAbsent:
		return EnabledOn, SourceDefault
	default:
		return EnabledUnknown, SourceUnknown
	}
}

// readVSCodeExtensions lists an extensions directory: its extensions.json
// when present, else its <publisher>.<name>-<version> folders. A remote
// server's state is kept by the client, so it is client_side_unknown.
func (s *scanner) readVSCodeExtensions(extDir, scope string, state *vscodeState, remote bool) []Plugin {
	manifest := filepath.Join(extDir, "extensions.json")
	if s.isFile(manifest) {
		if out := s.readVSCodeManifest(manifest, extDir, scope, state, remote); out != nil {
			return out
		}
	}
	return s.readVSCodeFolders(extDir, scope, state, remote)
}

type vscodeManifestEntry struct {
	Identifier struct {
		ID string `json:"id"`
	} `json:"identifier"`
	Version          string          `json:"version"`
	Location         json.RawMessage `json:"location"`
	RelativeLocation string          `json:"relativeLocation"`
	Metadata         struct {
		InstalledTimestamp   int64  `json:"installedTimestamp"`
		PublisherDisplayName string `json:"publisherDisplayName"`
	} `json:"metadata"`
}

// readVSCodeManifest reads one extensions.json. It returns nil (not an
// empty slice) when the file is unreadable, so the caller can fall back to
// the folder listing.
func (s *scanner) readVSCodeManifest(manifest, extDir, scope string, state *vscodeState, remote bool) []Plugin {
	data, ok := s.readFile(manifest)
	if !ok {
		return nil
	}
	var entries []vscodeManifestEntry
	if json.Unmarshal(data, &entries) != nil {
		return nil
	}
	if len(entries) > vscodeMaxExtensions {
		entries = entries[:vscodeMaxExtensions]
	}
	obsolete := s.readVSCodeObsolete(extDir)
	out := make([]Plugin, 0, len(entries))
	for _, entry := range entries {
		id := clean(entry.Identifier.ID)
		if id == "" {
			continue
		}
		folder := entry.RelativeLocation
		if folder == "" {
			folder = vscodeLocationBase(entry.Location)
		}
		if folder != "" && obsolete[folder] {
			continue
		}
		p := Plugin{ID: id, Version: clean(entry.Version), Scope: scope, Publisher: clean(entry.Metadata.PublisherDisplayName)}
		if ts := entry.Metadata.InstalledTimestamp; ts > 0 && ts < 1<<45 {
			at := time.UnixMilli(ts).UTC()
			p.InstalledAt = &at
		}
		if safeName(folder) {
			p.Path = filepath.Join(extDir, folder)
			s.fillVSCodePackage(&p)
		} else {
			p.Path = filepath.Join(extDir, id)
		}
		if p.Publisher == "" {
			p.Publisher, _, _ = strings.Cut(id, ".")
		}
		if remote {
			p.Enabled, p.EnabledSource = EnabledClientSideUnknown, SourceRemoteServer
		} else {
			p.Enabled, p.EnabledSource = state.enabled(id)
		}
		out = append(out, p)
	}
	return out
}

// vscodeLocationBase returns the folder name of an extensions.json
// location, which is a URI object ({"path": "..."}) or a string.
func vscodeLocationBase(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var loc struct {
		Path   string `json:"path"`
		FSPath string `json:"fsPath"`
	}
	var str string
	switch {
	case json.Unmarshal(raw, &loc) == nil && loc.Path != "":
		str = loc.Path
	case json.Unmarshal(raw, &loc) == nil && loc.FSPath != "":
		str = strings.ReplaceAll(loc.FSPath, `\`, "/")
	case json.Unmarshal(raw, &str) == nil:
		str = strings.ReplaceAll(str, `\`, "/")
	default:
		return ""
	}
	base := path.Base(strings.TrimRight(str, "/"))
	if !safeName(base) {
		return ""
	}
	return base
}

// readVSCodeFolders lists <publisher>.<name>-<version> folders when an
// extensions directory has no extensions.json.
func (s *scanner) readVSCodeFolders(extDir, scope string, state *vscodeState, remote bool) []Plugin {
	obsolete := s.readVSCodeObsolete(extDir)
	var out []Plugin
	for _, name := range s.subdirs(extDir, vscodeMaxExtensions) {
		if strings.HasPrefix(name, ".") || obsolete[name] || !safeName(name) {
			continue
		}
		p := Plugin{Scope: scope, Path: filepath.Join(extDir, name)}
		s.fillVSCodePackage(&p)
		if p.ID == "" {
			p.ID, p.Version = splitVSCodeFolder(name)
		}
		if p.ID == "" {
			continue
		}
		if p.Publisher == "" {
			p.Publisher, _, _ = strings.Cut(p.ID, ".")
		}
		if remote {
			p.Enabled, p.EnabledSource = EnabledClientSideUnknown, SourceRemoteServer
		} else {
			p.Enabled, p.EnabledSource = state.enabled(p.ID)
		}
		out = append(out, p)
	}
	return out
}

// splitVSCodeFolder splits "publisher.name-1.2.3[-platform]" into its id
// and version.
func splitVSCodeFolder(name string) (string, string) {
	for i := 0; i < len(name)-1; i++ {
		if name[i] == '-' && name[i+1] >= '0' && name[i+1] <= '9' {
			version := name[i+1:]
			if j := strings.IndexByte(version, '-'); j >= 0 {
				version = version[:j]
			}
			return clean(name[:i]), clean(version)
		}
	}
	return clean(name), ""
}

// fillVSCodePackage reads the extension's package.json for its id, display
// name and version.
func (s *scanner) fillVSCodePackage(p *Plugin) {
	data, ok := s.readFileLimit(filepath.Join(p.Path, "package.json"), vscodePackageMaxBytes)
	if !ok {
		return
	}
	var pkg struct {
		Name        string `json:"name"`
		Publisher   string `json:"publisher"`
		Version     string `json:"version"`
		DisplayName string `json:"displayName"`
	}
	if json.Unmarshal(data, &pkg) != nil {
		return
	}
	if p.ID == "" && pkg.Publisher != "" && pkg.Name != "" {
		p.ID = clean(pkg.Publisher + "." + pkg.Name)
	}
	if p.Version == "" {
		p.Version = clean(pkg.Version)
	}
	display := strings.TrimSpace(pkg.DisplayName)
	if strings.HasPrefix(display, "%") && strings.HasSuffix(display, "%") && len(display) > 2 {
		display = s.vscodeNLS(p.Path, strings.Trim(display, "%"))
	}
	if display == "" {
		display = pkg.Name
	}
	p.DisplayName = clean(display)
}

// vscodeNLS resolves a %key% display name from package.nls.json.
func (s *scanner) vscodeNLS(dir, key string) string {
	data, ok := s.readFileLimit(filepath.Join(dir, "package.nls.json"), vscodePackageMaxBytes)
	if !ok {
		return ""
	}
	var nls map[string]json.RawMessage
	if json.Unmarshal(data, &nls) != nil {
		return ""
	}
	var value string
	if json.Unmarshal(nls[key], &value) == nil {
		return value
	}
	var msg struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(nls[key], &msg) == nil {
		return msg.Message
	}
	return ""
}

// readVSCodeObsolete reads an extensions folder's .obsolete record, a JSON
// object whose keys are removed extension folders (an unreadable record
// hides nothing).
func (s *scanner) readVSCodeObsolete(extDir string) map[string]bool {
	data, ok := s.readFileLimit(filepath.Join(extDir, ".obsolete"), 1<<20)
	if !ok {
		return nil
	}
	var record map[string]bool
	if json.Unmarshal(data, &record) != nil {
		return nil
	}
	return record
}

// readVSCodeDisabled reads the disabled-extension list from a state
// database.
func (s *scanner) readVSCodeDisabled(db string) (map[string]bool, stateKnowledge) {
	if !s.isFile(db) {
		return nil, stateAbsent
	}
	if !s.charge(0) {
		return nil, stateUnreadable
	}
	raw, ok := readStateDBValue(db, vscodeDisabledKey, s.limits.StateDBTimeout)
	if !ok {
		return nil, stateUnreadable
	}
	out := map[string]bool{}
	if len(raw) == 0 {
		return out, stateRead
	}
	var ids []struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(raw, &ids) != nil {
		return nil, stateUnreadable
	}
	for _, id := range ids {
		if id.ID != "" {
			out[strings.ToLower(id.ID)] = true
		}
	}
	return out, stateRead
}
