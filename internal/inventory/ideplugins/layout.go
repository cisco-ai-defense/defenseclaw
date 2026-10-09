// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package ideplugins

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// layout holds the per-platform base directories of one home.
type layout struct {
	home string
	goos string
	// appSupport is where desktop apps keep their user data: macOS
	// ~/Library/Application Support, Linux ~/.config, Windows %APPDATA%.
	appSupport string
	// localData is the machine-local data directory: macOS
	// ~/Library/Application Support, Linux ~/.local/share, Windows
	// %LOCALAPPDATA%.
	localData string
	// cache is the cache directory: macOS ~/Library/Caches, Linux
	// ~/.cache, Windows %LOCALAPPDATA%.
	cache string
}

func newLayout(home, goos string, limits Limits) layout {
	l := layout{home: home, goos: goos}
	switch goos {
	case "darwin":
		l.appSupport = filepath.Join(home, "Library", "Application Support")
		l.localData = l.appSupport
		l.cache = filepath.Join(home, "Library", "Caches")
	case "windows":
		l.appSupport = limits.RoamingAppData
		if l.appSupport == "" {
			l.appSupport = filepath.Join(home, "AppData", "Roaming")
		}
		l.localData = limits.LocalAppData
		if l.localData == "" {
			l.localData = filepath.Join(home, "AppData", "Local")
		}
		l.cache = l.localData
	default:
		l.appSupport = filepath.Join(home, ".config")
		l.localData = filepath.Join(home, ".local", "share")
		l.cache = filepath.Join(home, ".cache")
	}
	return l
}

// WindowsGrant is one path of a Windows home that Scan reads, relative to
// the home. A managed Windows gateway runs as a service account with no
// access to user profiles, and the SYSTEM enumerator grants it read access
// to each of these (enterprisehooks).
type WindowsGrant struct {
	Path string
	// Tree grants what the folder holds as well, by inheritance. Otherwise
	// only the folder or file itself is granted: Scan lists the folder's
	// names, or reads that one file, and nothing else below it.
	Tree bool
	// Attributes grants only metadata needed to reject intermediate reparse points.
	Attributes bool
}

// WindowsHomeGrants lists what Scan reads in a Windows home with the
// default %APPDATA% and %LOCALAPPDATA%. Folders that also hold large or
// unrelated data (a Remote-SSH server's builds and state,
// %LOCALAPPDATA%\JetBrains with its index caches, Google's folders, Oomph's
// Eclipse installs) are granted narrowly: the folder itself, so Scan can
// list it, and below it only the plugin folders and metadata files Scan
// reads. Those are versioned, so the folders are listed here; a link
// anywhere below home is not followed.
func WindowsHomeGrants(home string) []WindowsGrant {
	var out []WindowsGrant
	tree := func(rel string) { out = append(out, WindowsGrant{Path: rel, Tree: true}) }
	self := func(rel string) { out = append(out, WindowsGrant{Path: rel}) }
	// A live VS Code database may keep disabled-extension changes in its WAL.
	// Grant each existing sidecar as a file, without exposing sibling storage.
	stateDB := func(rel string) {
		self(rel)
		self(rel + "-wal")
		self(rel + "-shm")
	}
	for _, product := range vscodeProducts {
		for _, dot := range product.dotDirs {
			tree(dot + `\extensions`)
		}
		user := `AppData\Roaming\` + product.dataName + `\User`
		self(user + `\globalStorage`)
		stateDB(user + `\globalStorage\state.vscdb`)
		profiles := user + `\profiles`
		self(profiles)
		for _, profile := range windowsSubdirs(home, profiles, vscodeMaxProfiles) {
			if !safeName(profile) {
				continue
			}
			base := profiles + `\` + profile
			self(base + `\extensions.json`)
			stateDB(base + `\globalStorage\state.vscdb`)
		}
		for _, server := range product.servers {
			self(server)
			tree(server + `\extensions`)
			builds := server + `\cli\servers`
			self(builds)
			for _, build := range windowsSubdirs(home, builds, vscodeMaxServers) {
				self(builds + `\` + build + `\server\package.json`)
			}
		}
	}
	for _, vendor := range []struct{ root, prefix string }{
		{`AppData\Roaming\JetBrains`, ``},
		{`AppData\Roaming\Google`, "AndroidStudio"},
	} {
		self(vendor.root)
		for _, name := range windowsSubdirs(home, vendor.root, jetbrainsMaxProducts) {
			if !jetbrainsProductDir.MatchString(name) || !strings.HasPrefix(name, vendor.prefix) {
				continue
			}
			self(vendor.root + `\` + name + `\disabled_plugins.txt`)
			tree(vendor.root + `\` + name + `\plugins`)
		}
	}
	for _, vendor := range []struct{ root, prefix string }{
		{`AppData\Local\JetBrains`, ``},
		{`AppData\Local\Google`, "AndroidStudio"},
	} {
		self(vendor.root)
		for _, name := range windowsSubdirs(home, vendor.root, jetbrainsMaxProducts) {
			if jetbrainsProductDir.MatchString(name) && strings.HasPrefix(name, vendor.prefix) {
				tree(vendor.root + `\` + name + `\plugins`)
			}
		}
	}
	const remoteDev = `AppData\Local\JetBrains\RemoteDev\dist`
	self(remoteDev)
	for _, name := range windowsSubdirs(home, remoteDev, jetbrainsMaxRemoteDist) {
		self(remoteDev + `\` + name + `\product-info.json`)
	}
	const visualStudio = `AppData\Local\Microsoft\VisualStudio`
	self(visualStudio)
	for _, name := range windowsSubdirs(home, visualStudio, visualStudioMaxInstances*4) {
		if visualStudioInstanceDir.MatchString(name) {
			self(visualStudio + `\` + name + `\privateregistry.bin`)
			tree(visualStudio + `\` + name + `\Extensions`)
		}
	}
	tree(`AppData\Local\Zed\extensions\installed`)
	windowsVimGrants(home, `AppData\Local\nvim`, &out)
	windowsVimGrants(home, `AppData\Local\nvim-data`, &out)
	windowsVimGrants(home, `vimfiles`, &out)
	self(`.eclipse`)
	const bundles = `\configuration\org.eclipse.equinox.simpleconfigurator\bundles.info`
	for _, name := range windowsSubdirs(home, `.eclipse`, eclipseMaxInstalls) {
		self(`.eclipse\` + name + bundles)
	}
	self(`eclipse`)
	self(`eclipse` + bundles)
	for _, name := range windowsSubdirs(home, `eclipse`, eclipseMaxInstalls) {
		self(`eclipse\` + name + `\eclipse` + bundles)
	}
	// Lstat checks every parent. Grant only attributes on those folders:
	// listing or reading sibling files is unnecessary.
	seen := make(map[string]bool, len(out))
	for _, g := range out {
		seen[g.Path] = true
	}
	for _, g := range append([]WindowsGrant(nil), out...) {
		parts := strings.Split(g.Path, `\`)
		for i := 1; i < len(parts); i++ {
			parent := strings.Join(parts[:i], `\`)
			if !seen[parent] {
				out = append(out, WindowsGrant{Path: parent, Attributes: true})
				seen[parent] = true
			}
		}
	}
	return out
}

// WindowsLegacyBroadGrants lists the old inherited grants. The enumerator
// removes these before applying the narrower WindowsHomeGrants on upgrades.
func WindowsLegacyBroadGrants(home string) []string {
	var out []string
	for _, product := range vscodeProducts {
		user := `AppData\Roaming\` + product.dataName + `\User`
		out = append(out, user+`\globalStorage`, user+`\profiles`)
	}
	out = append(out,
		`AppData\Roaming\JetBrains`,
		`AppData\Local\Microsoft\VisualStudio`,
		`AppData\Local\nvim`,
		`AppData\Local\nvim-data`,
		`vimfiles`,
		`.eclipse`,
	)
	const google = `AppData\Roaming\Google`
	for _, name := range windowsSubdirs(home, google, jetbrainsMaxProducts) {
		if strings.HasPrefix(name, "AndroidStudio") && jetbrainsProductDir.MatchString(name) {
			out = append(out, google+`\`+name)
		}
	}
	return out
}

// windowsVimGrants grants the listings and lockfile Scan uses, without
// granting editor swap, history or plugin content files.
func windowsVimGrants(home, root string, out *[]WindowsGrant) {
	self := func(rel string) { *out = append(*out, WindowsGrant{Path: rel}) }
	self(root)
	if strings.HasSuffix(root, `\nvim`) {
		self(root + `\lazy-lock.json`)
	}
	if strings.HasSuffix(root, `\nvim-data`) {
		lazy := root + `\lazy`
		self(lazy)
		for _, name := range windowsSubdirs(home, lazy, vimMaxPlugins) {
			self(lazy + `\` + name)
		}
		plugged := root + `\plugged`
		self(plugged)
		for _, name := range windowsSubdirs(home, plugged, vimMaxPlugins) {
			self(plugged + `\` + name)
		}
		root += `\site`
	}
	if root == `vimfiles` {
		plugged := root + `\plugged`
		self(plugged)
		for _, name := range windowsSubdirs(home, plugged, vimMaxPlugins) {
			if safeName(name) && !strings.HasPrefix(name, ".") {
				self(plugged + `\` + name)
			}
		}
	}
	packRoot := root + `\pack`
	self(packRoot)
	for _, pack := range windowsSubdirs(home, packRoot, vimMaxPacks) {
		if !safeName(pack) {
			continue
		}
		for _, kind := range []string{"start", "opt"} {
			dir := packRoot + `\` + pack + `\` + kind
			self(dir)
			for _, name := range windowsSubdirs(home, dir, vimMaxPlugins) {
				if safeName(name) && !strings.HasPrefix(name, ".") {
					self(dir + `\` + name)
				}
			}
		}
	}
}

// windowsSubdirs lists up to limit folder names in home\rel, as Scan's
// subdirs does. Nothing is listed when a link or other reparse point is
// anywhere below home on the way, and linked entries are left out.
func windowsSubdirs(home, rel string, limit int) []string {
	dir := home
	for _, part := range strings.Split(rel, `\`) {
		dir = filepath.Join(dir, part)
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			return nil
		}
	}
	f, err := os.Open(dir)
	if err != nil {
		return nil
	}
	defer f.Close()
	entries, _ := f.ReadDir(limit)
	var out []string
	for _, e := range entries {
		if e.IsDir() && e.Type()&(os.ModeSymlink|os.ModeIrregular) == 0 && safeName(e.Name()) {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}
