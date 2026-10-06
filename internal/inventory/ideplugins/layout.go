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
	for _, product := range vscodeProducts {
		for _, dot := range product.dotDirs {
			tree(dot + `\extensions`)
		}
		user := `AppData\Roaming\` + product.dataName + `\User`
		tree(user + `\globalStorage`)
		tree(user + `\profiles`)
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
	tree(`AppData\Roaming\JetBrains`)
	const localJetBrains = `AppData\Local\JetBrains`
	self(localJetBrains)
	for _, name := range windowsSubdirs(home, localJetBrains, jetbrainsMaxProducts) {
		if jetbrainsProductDir.MatchString(name) {
			tree(localJetBrains + `\` + name + `\plugins`)
		}
	}
	const remoteDev = localJetBrains + `\RemoteDev\dist`
	self(remoteDev)
	for _, name := range windowsSubdirs(home, remoteDev, jetbrainsMaxRemoteDist) {
		self(remoteDev + `\` + name + `\product-info.json`)
	}
	// Android Studio: the whole config folder in %APPDATA% (it holds
	// disabled_plugins.txt and the plugins, as for JetBrains' own
	// products), only the plugins in %LOCALAPPDATA%, where the caches are.
	for _, google := range []struct{ dir, sub string }{
		{`AppData\Roaming\Google`, ""},
		{`AppData\Local\Google`, `\plugins`},
	} {
		self(google.dir)
		for _, name := range windowsSubdirs(home, google.dir, jetbrainsMaxProducts) {
			if strings.HasPrefix(name, "AndroidStudio") && jetbrainsProductDir.MatchString(name) {
				tree(google.dir + `\` + name + google.sub)
			}
		}
	}
	tree(`AppData\Local\Microsoft\VisualStudio`)
	tree(`AppData\Local\Zed\extensions\installed`)
	tree(`AppData\Local\nvim`)
	tree(`AppData\Local\nvim-data`)
	tree(`vimfiles`)
	tree(`.eclipse`)
	const bundles = `\configuration\org.eclipse.equinox.simpleconfigurator\bundles.info`
	self(`eclipse`)
	self(`eclipse` + bundles)
	for _, name := range windowsSubdirs(home, `eclipse`, eclipseMaxInstalls) {
		self(`eclipse\` + name + `\eclipse` + bundles)
	}
	return out
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
