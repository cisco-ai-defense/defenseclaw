// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package ideplugins

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"io"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	jetbrainsMaxProducts   = 128
	jetbrainsMaxPlugins    = 1024
	jetbrainsMaxJars       = 32
	jetbrainsMaxJarBytes   = 256 << 20
	jetbrainsMaxXMLBytes   = 1 << 20
	jetbrainsMaxRemoteDist = 32
)

// jetbrainsProductDir matches a versioned product directory such as
// IntelliJIdea2024.3, PyCharmCE2023.1 or AndroidStudio2024.2.
var jetbrainsProductDir = regexp.MustCompile(`^([A-Za-z][A-Za-z-]*?)(\d{4}\.\d+(?:\.\d+)?)$`)

var jetbrainsProductTokens = map[string]string{
	"intellijidea":  "intellij-idea",
	"ideaic":        "intellij-idea-ce",
	"pycharm":       "pycharm",
	"pycharmce":     "pycharm-ce",
	"webstorm":      "webstorm",
	"goland":        "goland",
	"clion":         "clion",
	"rider":         "rider",
	"rubymine":      "rubymine",
	"phpstorm":      "phpstorm",
	"datagrip":      "datagrip",
	"dataspell":     "dataspell",
	"rustrover":     "rustrover",
	"aqua":          "aqua",
	"writerside":    "writerside",
	"androidstudio": "android-studio",
	"studio":        "android-studio",
}

// jetbrainsToken turns a product directory prefix into a token of at most
// maxProductLen bytes: a product the table does not name keeps its
// lowercased prefix, cut to fit.
func jetbrainsToken(prefix string) string {
	key := strings.ToLower(strings.ReplaceAll(prefix, "-", ""))
	if token, ok := jetbrainsProductTokens[key]; ok {
		return token
	}
	const unknown = "jetbrains-"
	if len(key) > maxProductLen-len(unknown) {
		key = key[:maxProductLen-len(unknown)] // ASCII letters only (jetbrainsProductDir)
	}
	return unknown + key
}

type jetbrainsProduct struct {
	name       string // directory name, e.g. PyCharm2024.1
	config     string // holds disabled_plugins.txt
	pluginDirs []string
}

func (s *scanner) scanJetBrains() {
	l := s.layout
	vendors := []struct {
		config, plugins string
		prefix          string // "" or a required directory-name prefix
	}{
		{filepath.Join(l.appSupport, "JetBrains"), "", ""},
		{filepath.Join(l.appSupport, "Google"), "", "AndroidStudio"},
	}
	for _, vendor := range vendors {
		products := map[string]*jetbrainsProduct{}
		var order []string
		get := func(name string) *jetbrainsProduct {
			if p, ok := products[name]; ok {
				return p
			}
			p := &jetbrainsProduct{name: name}
			products[name] = p
			order = append(order, name)
			return p
		}
		accept := func(name string) bool {
			return safeName(name) && jetbrainsProductDir.MatchString(name) && strings.HasPrefix(name, vendor.prefix)
		}
		for _, name := range s.subdirs(vendor.config, jetbrainsMaxProducts) {
			if !accept(name) {
				continue
			}
			p := get(name)
			p.config = filepath.Join(vendor.config, name)
			if s.goos == "darwin" || s.goos == "windows" {
				p.pluginDirs = append(p.pluginDirs, filepath.Join(p.config, "plugins"))
			}
		}
		// Plugins live apart from the config on Linux (~/.local/share) and,
		// for some installs, in %LOCALAPPDATA% on Windows.
		var pluginBase string
		switch s.goos {
		case "linux", "freebsd", "openbsd", "netbsd":
			pluginBase = filepath.Join(l.localData, filepath.Base(vendor.config))
		case "windows":
			pluginBase = filepath.Join(l.localData, filepath.Base(vendor.config))
		}
		if pluginBase != "" {
			for _, name := range s.subdirs(pluginBase, jetbrainsMaxProducts) {
				if !accept(name) {
					continue
				}
				dir := filepath.Join(pluginBase, name)
				if s.goos == "windows" {
					dir = filepath.Join(dir, "plugins")
				}
				p := get(name)
				p.pluginDirs = append(p.pluginDirs, dir)
			}
		}
		for _, name := range order {
			s.scanJetBrainsProduct(products[name])
		}
	}
	s.scanJetBrainsRemoteDev()
}

func (s *scanner) scanJetBrainsProduct(p *jetbrainsProduct) {
	m := jetbrainsProductDir.FindStringSubmatch(p.name)
	if m == nil {
		return
	}
	disabled, haveList := s.readJetBrainsDisabled(p.config)
	inst := Install{Family: FamilyJetBrains, Product: jetbrainsToken(m[1]), Channel: "stable", Version: m[2]}
	seen := map[string]bool{}
	for _, dir := range p.pluginDirs {
		if !s.isDir(dir) {
			continue
		}
		if inst.Root == "" {
			inst.Root = dir
		}
		for _, entry := range s.listDir(dir, jetbrainsMaxPlugins) {
			name := entry.Name()
			if !safeName(name) || strings.HasPrefix(name, ".") {
				continue
			}
			path := filepath.Join(dir, name)
			var meta jetbrainsPluginXML
			var ok bool
			switch {
			case s.isDir(path):
				meta, ok = s.readJetBrainsPluginDir(path)
			case strings.HasSuffix(strings.ToLower(name), ".jar"):
				meta, ok = s.readJetBrainsJar(path)
			default:
				continue
			}
			id := clean(meta.ID)
			if id == "" {
				id = clean(meta.Name)
			}
			if !ok || id == "" {
				id = clean(strings.TrimSuffix(name, ".jar"))
			}
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			plugin := Plugin{
				ID: id, DisplayName: clean(meta.Name), Version: clean(meta.Version),
				Publisher: clean(meta.Vendor), Scope: ScopeUser, Path: path,
				Enabled: EnabledOn, EnabledSource: SourceDefault,
			}
			if haveList {
				plugin.EnabledSource = SourceDisabledPlugins
				if disabled[id] {
					plugin.Enabled = EnabledOff
				}
			}
			inst.Plugins = append(inst.Plugins, plugin)
		}
	}
	if inst.Root == "" {
		if p.config == "" {
			return
		}
		inst.Root = p.config
	}
	s.add(inst)
}

// readJetBrainsDisabled reads disabled_plugins.txt, one plugin id a line.
func (s *scanner) readJetBrainsDisabled(config string) (map[string]bool, bool) {
	if config == "" {
		return nil, false
	}
	data, ok := s.readFile(filepath.Join(config, "disabled_plugins.txt"))
	if !ok {
		return nil, false
	}
	out := map[string]bool{}
	lines := bufio.NewScanner(bytes.NewReader(data))
	for lines.Scan() {
		if id := clean(lines.Text()); id != "" {
			out[id] = true
		}
	}
	return out, true
}

type jetbrainsPluginXML struct {
	ID      string
	Name    string
	Version string
	Vendor  string
}

// readJetBrainsPluginDir reads an unpacked plugin: META-INF/plugin.xml at
// its top, or inside one of its lib/*.jar files (the jar named like the
// plugin first).
func (s *scanner) readJetBrainsPluginDir(dir string) (jetbrainsPluginXML, bool) {
	if data, ok := s.readFileLimit(filepath.Join(dir, "META-INF", "plugin.xml"), jetbrainsMaxXMLBytes); ok {
		return parseJetBrainsPluginXML(bytes.NewReader(data))
	}
	lib := filepath.Join(dir, "lib")
	var jars []string
	for _, entry := range s.listDir(lib, 4*jetbrainsMaxJars) {
		if name := entry.Name(); strings.HasSuffix(strings.ToLower(name), ".jar") && entry.Type().IsRegular() {
			jars = append(jars, name)
		}
	}
	base := strings.ToLower(filepath.Base(dir))
	prefer := func(name string) bool { return strings.HasPrefix(strings.ToLower(name), base) }
	ordered := make([]string, 0, len(jars))
	for _, name := range jars {
		if prefer(name) {
			ordered = append(ordered, name)
		}
	}
	for _, name := range jars {
		if !prefer(name) {
			ordered = append(ordered, name)
		}
	}
	if len(ordered) > jetbrainsMaxJars {
		ordered = ordered[:jetbrainsMaxJars]
	}
	for _, name := range ordered {
		if meta, ok := s.readJetBrainsJar(filepath.Join(lib, name)); ok {
			return meta, true
		}
	}
	return jetbrainsPluginXML{}, false
}

// readJetBrainsJar reads META-INF/plugin.xml from a jar. Only the central
// directory and that one entry are read, both bounded.
func (s *scanner) readJetBrainsJar(path string) (jetbrainsPluginXML, bool) {
	if !s.isFile(path) {
		return jetbrainsPluginXML{}, false
	}
	f, err := openNonblocking(path, s.limits.FollowSymlinks)
	if err != nil {
		return jetbrainsPluginXML{}, false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > jetbrainsMaxJarBytes {
		return jetbrainsPluginXML{}, false
	}
	if !s.charge(0) {
		return jetbrainsPluginXML{}, false
	}
	zr, err := zip.NewReader(f, info.Size())
	if err != nil || len(zr.File) > 1<<16 {
		return jetbrainsPluginXML{}, false
	}
	for _, entry := range zr.File {
		if entry.Name != "META-INF/plugin.xml" {
			continue
		}
		if entry.UncompressedSize64 > jetbrainsMaxXMLBytes || !s.charge(int64(entry.UncompressedSize64)) {
			return jetbrainsPluginXML{}, false
		}
		rc, err := entry.Open()
		if err != nil {
			return jetbrainsPluginXML{}, false
		}
		defer rc.Close()
		return parseJetBrainsPluginXML(io.LimitReader(rc, jetbrainsMaxXMLBytes))
	}
	return jetbrainsPluginXML{}, false
}

// parseJetBrainsPluginXML reads the id, name, version and vendor children
// of <idea-plugin>.
func parseJetBrainsPluginXML(r io.Reader) (jetbrainsPluginXML, bool) {
	dec := xml.NewDecoder(r)
	dec.Strict = false
	var out jetbrainsPluginXML
	depth := 0
	root := false
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if depth == 1 {
				root = t.Name.Local == "idea-plugin"
				if !root {
					return out, false
				}
				continue
			}
			if depth != 2 {
				continue
			}
			var target *string
			switch t.Name.Local {
			case "id":
				target = &out.ID
			case "name":
				target = &out.Name
			case "version":
				target = &out.Version
			case "vendor":
				target = &out.Vendor
			default:
				if err := dec.Skip(); err != nil {
					return out, root && (out.ID != "" || out.Name != "")
				}
				depth--
				continue
			}
			var text string
			if err := dec.DecodeElement(&text, &t); err != nil {
				return out, root && (out.ID != "" || out.Name != "")
			}
			depth--
			if *target == "" {
				*target = strings.TrimSpace(text)
			}
		case xml.EndElement:
			depth--
			if depth == 0 {
				return out, root && (out.ID != "" || out.Name != "")
			}
		}
	}
	return out, root && (out.ID != "" || out.Name != "")
}

// scanJetBrainsRemoteDev records each JetBrains remote-development backend
// under the cache's RemoteDev/dist as an installation. Its plugins are
// bundled; user plugins of a backend live in the product directories above.
func (s *scanner) scanJetBrainsRemoteDev() {
	dist := filepath.Join(s.layout.cache, "JetBrains", "RemoteDev", "dist")
	for _, name := range s.subdirs(dist, jetbrainsMaxRemoteDist) {
		if !safeName(name) {
			continue
		}
		dir := filepath.Join(dist, name)
		inst := Install{Family: FamilyJetBrains, Product: "jetbrains-remote-dev", RemoteKind: RemoteJetBrainsDevEnv, Root: dir}
		if data, ok := s.readFileLimit(filepath.Join(dir, "product-info.json"), 256<<10); ok {
			var info struct {
				Name        string `json:"name"`
				Version     string `json:"version"`
				ProductCode string `json:"productCode"`
			}
			if json.Unmarshal(data, &info) == nil {
				inst.Version = clean(info.Version)
				if code := strings.ToLower(clean(info.ProductCode)); code != "" && jetbrainsCodeToken(code) != "" {
					inst.Product = jetbrainsCodeToken(code)
				}
			}
		}
		s.add(inst)
	}
}

// jetbrainsCodeToken maps a product-info.json productCode to a token.
func jetbrainsCodeToken(code string) string {
	switch code {
	case "iu":
		return "intellij-idea"
	case "ic":
		return "intellij-idea-ce"
	case "py":
		return "pycharm"
	case "pc":
		return "pycharm-ce"
	case "ws":
		return "webstorm"
	case "go":
		return "goland"
	case "cl":
		return "clion"
	case "rd":
		return "rider"
	case "rm":
		return "rubymine"
	case "ps":
		return "phpstorm"
	case "db":
		return "datagrip"
	case "rr":
		return "rustrover"
	}
	return ""
}
