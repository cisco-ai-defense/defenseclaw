// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package ideplugins

import (
	"bytes"
	"encoding/xml"
	"io"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	visualStudioMaxInstances  = 32
	visualStudioMaxExtensions = 2048
)

// visualStudioInstanceDir matches %LOCALAPPDATA%\Microsoft\VisualStudio
// instance folders such as 17.0_1a2b3c4d (and the 17.0_1a2b3c4dExp
// experimental hive).
var visualStudioInstanceDir = regexp.MustCompile(`^(\d+)\.(\d+)_[0-9A-Za-z]+$`)

// visualStudioEnabledLookup returns the enabled extension ids of one
// instance (from its privateregistry.bin hive), and false when the hive
// could not be read (it is locked while Visual Studio runs). Replaced on
// Windows.
var visualStudioEnabledLookup = func(_ *scanner, instanceDir, instanceName string) (map[string]bool, bool) {
	return nil, false
}

// visualStudioEnabledNames accepts io.EOF from ReadValueNames when fewer
// than the requested maximum are present.
func visualStudioEnabledNames(read func(int) ([]string, error)) (map[string]bool, bool) {
	names, err := read(visualStudioMaxExtensions)
	if err != nil && err != io.EOF || len(names) > visualStudioMaxExtensions {
		return nil, false
	}
	out := make(map[string]bool, len(names))
	for _, name := range names {
		id, _, _ := strings.Cut(name, ",")
		if id = strings.ToLower(strings.TrimSpace(id)); id != "" {
			out[id] = true
		}
	}
	return out, true
}

func (s *scanner) scanVisualStudio() {
	if s.goos != "windows" {
		return
	}
	base := filepath.Join(s.layout.localData, "Microsoft", "VisualStudio")
	for _, name := range s.subdirs(base, visualStudioMaxInstances*4) {
		m := visualStudioInstanceDir.FindStringSubmatch(name)
		if m == nil || !safeName(name) {
			continue
		}
		instance := filepath.Join(base, name)
		extDir := filepath.Join(instance, "Extensions")
		if !s.isDir(extDir) {
			continue
		}
		enabled, known := visualStudioEnabledLookup(s, instance, name)
		inst := Install{Family: FamilyVisualStudio, Product: "visual-studio", Channel: "stable", Version: m[1] + "." + m[2], Root: extDir}
		if strings.HasSuffix(name, "Exp") {
			inst.Channel = "experimental"
		}
		for _, p := range s.readVSIXManifests(extDir, ScopeUser, false) {
			switch {
			case !known:
				p.Enabled, p.EnabledSource = EnabledUnknown, SourceUnknown
			case enabled[strings.ToLower(p.ID)]:
				p.Enabled, p.EnabledSource = EnabledOn, SourcePrivateRegistry
			default:
				p.Enabled, p.EnabledSource = EnabledOff, SourcePrivateRegistry
			}
			inst.Plugins = append(inst.Plugins, p)
		}
		s.add(inst)
	}
}

// scanVisualStudioMachine reads <Program Files>\Microsoft Visual
// Studio\<year>\<edition>\Common7\IDE\Extensions. Whether an all-users
// extension is enabled is each user's setting, so the state is unknown.
func (s *scanner) scanVisualStudioMachine() {
	for _, pf := range s.limits.ProgramFiles {
		if pf == "" {
			continue
		}
		base := filepath.Join(pf, "Microsoft Visual Studio")
		for _, year := range s.subdirs(base, 16) {
			for _, edition := range s.subdirs(filepath.Join(base, year), 16) {
				if !safeName(year) || !safeName(edition) {
					continue
				}
				extDir := filepath.Join(base, year, edition, "Common7", "IDE", "Extensions")
				if !s.isDir(extDir) {
					continue
				}
				inst := Install{Family: FamilyVisualStudio, Product: "visual-studio", Channel: strings.ToLower(clean(edition)), Version: clean(year), Root: extDir}
				for _, p := range s.readVSIXManifests(extDir, ScopeMachine, true) {
					p.Enabled, p.EnabledSource = EnabledUnknown, SourceUnknown
					inst.Plugins = append(inst.Plugins, p)
				}
				s.add(inst)
			}
		}
	}
}

// readVSIXManifests finds extension.vsixmanifest files up to three levels
// below extDir (<random>\ or <publisher>\<name>\<version>\).
func (s *scanner) readVSIXManifests(extDir, scope string, skipSystem bool) []Plugin {
	var out []Plugin
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if len(out) >= visualStudioMaxExtensions {
			return
		}
		manifest := filepath.Join(dir, "extension.vsixmanifest")
		if depth > 0 && s.isFile(manifest) {
			if data, ok := s.readFile(manifest); ok {
				if p, system, ok := parseVSIXManifest(data); ok && !(skipSystem && system) {
					p.Scope, p.Path = scope, dir
					out = append(out, p)
				}
			}
			return
		}
		if depth >= 3 {
			return
		}
		for _, name := range s.subdirs(dir, visualStudioMaxExtensions) {
			if safeName(name) {
				walk(filepath.Join(dir, name), depth+1)
			}
		}
	}
	walk(extDir, 0)
	return out
}

// parseVSIXManifest reads the identity of a VSIX v2 manifest
// (<PackageManifest><Metadata><Identity Id Version Publisher/>
// <DisplayName/>) or a v1 manifest (<Vsix><Identifier Id><Name/>
// <Author/><Version/>). system reports a component Visual Studio ships
// itself (SystemComponent or InstalledByMsi).
func parseVSIXManifest(data []byte) (Plugin, bool, bool) {
	var doc struct {
		XMLName  xml.Name
		Metadata struct {
			Identity struct {
				ID        string `xml:"Id,attr"`
				Version   string `xml:"Version,attr"`
				Publisher string `xml:"Publisher,attr"`
			} `xml:"Identity"`
			DisplayName string `xml:"DisplayName"`
		} `xml:"Metadata"`
		Installation struct {
			SystemComponent string `xml:"SystemComponent,attr"`
			InstalledByMsi  string `xml:"InstalledByMsi,attr"`
		} `xml:"Installation"`
		Identifier struct {
			ID      string `xml:"Id,attr"`
			Name    string `xml:"Name"`
			Author  string `xml:"Author"`
			Version string `xml:"Version"`
			System  string `xml:"SystemComponent"`
			MSI     string `xml:"InstalledByMsi"`
		} `xml:"Identifier"`
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = false
	if err := dec.Decode(&doc); err != nil {
		return Plugin{}, false, false
	}
	var p Plugin
	var system bool
	switch doc.XMLName.Local {
	case "PackageManifest":
		id := doc.Metadata.Identity
		p = Plugin{ID: clean(id.ID), Version: clean(id.Version), Publisher: clean(id.Publisher), DisplayName: clean(doc.Metadata.DisplayName)}
		system = strings.EqualFold(doc.Installation.SystemComponent, "true") || strings.EqualFold(doc.Installation.InstalledByMsi, "true")
	case "Vsix":
		id := doc.Identifier
		p = Plugin{ID: clean(id.ID), Version: clean(id.Version), Publisher: clean(id.Author), DisplayName: clean(id.Name)}
		system = strings.EqualFold(strings.TrimSpace(id.System), "true") || strings.EqualFold(strings.TrimSpace(id.MSI), "true")
	default:
		return Plugin{}, false, false
	}
	return p, system, p.ID != ""
}
