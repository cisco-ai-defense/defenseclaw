// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package ideplugins

import (
	"archive/zip"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeStateDB(t *testing.T, path, disabled string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{
		`CREATE TABLE ItemTable (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB)`,
		`INSERT INTO ItemTable (key, value) VALUES ('extensionsIdentifiers/disabled', '` + disabled + `')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
}

func TestStateDBRejectsView(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.vscdb")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE VIEW ItemTable AS SELECT 'extensionsIdentifiers/disabled' AS key, '[]' AS value`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, ok := readStateDBValue(path, "extensionsIdentifiers/disabled", DefaultStateDBTimeout); ok {
		t.Fatal("a state database view must not be evaluated")
	}
}

func writeJar(t *testing.T, path, pluginXML string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("META-INF/plugin.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(pluginXML)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestJetBrainsJarChargesCompressedBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plugin.jar")
	writeJar(t, path, `<idea-plugin><id>example.plugin</id></idea-plugin>`)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	s := newScanner("linux", Limits{MaxBytes: info.Size() - 1})
	if _, ok := s.readJetBrainsJar(path); ok {
		t.Fatal("jar exceeded scan byte budget")
	}
}

func byID(installs []Install, family, product, remote string) map[string]Plugin {
	out := map[string]Plugin{}
	for _, inst := range installs {
		if inst.Family == family && inst.Product == product && inst.RemoteKind == remote {
			for _, p := range inst.Plugins {
				out[p.ID+"|"+p.Scope] = p
			}
		}
	}
	return out
}

func TestScanVSCodeFamily(t *testing.T) {
	home := t.TempDir()
	ext := filepath.Join(home, ".vscode", "extensions")
	writeFile(t, filepath.Join(ext, "extensions.json"), `[
	 {"identifier":{"id":"anthropic.claude-code"},"version":"2.0.1","relativeLocation":"anthropic.claude-code-2.0.1","metadata":{"installedTimestamp":1700000000000,"publisherDisplayName":"Anthropic"}},
	 {"identifier":{"id":"ms-python.python"},"version":"2024.1.0","location":{"$mid":1,"path":"/x/ms-python.python-2024.1.0","scheme":"file"}},
	 {"identifier":{"id":"old.removed"},"version":"1.0.0","relativeLocation":"old.removed-1.0.0"}]`)
	writeFile(t, filepath.Join(ext, ".obsolete"), `{"old.removed-1.0.0":true}`)
	writeFile(t, filepath.Join(ext, "anthropic.claude-code-2.0.1", "package.json"), `{"name":"claude-code","publisher":"anthropic","version":"2.0.1","displayName":"%ext.name%"}`)
	writeFile(t, filepath.Join(ext, "anthropic.claude-code-2.0.1", "package.nls.json"), `{"ext.name":"Claude Code for VS Code"}`)
	user := filepath.Join(home, ".config", "Code", "User")
	writeStateDB(t, filepath.Join(user, "globalStorage", "state.vscdb"), `[{"id":"MS-Python.python"}]`)
	writeFile(t, filepath.Join(user, "profiles", "a1b2", "extensions.json"), `[{"identifier":{"id":"anthropic.claude-code"},"version":"2.0.1","relativeLocation":"anthropic.claude-code-2.0.1"}]`)
	writeStateDB(t, filepath.Join(user, "profiles", "a1b2", "globalStorage", "state.vscdb"), `[{"id":"anthropic.claude-code"}]`)
	// A Remote-SSH server without extensions.json, and one server build.
	writeFile(t, filepath.Join(home, ".cursor-server", "extensions", "openai.chatgpt-1.2.3-linux-x64", "package.json"), `{"name":"chatgpt","publisher":"openai","version":"1.2.3","displayName":"Codex"}`)
	writeFile(t, filepath.Join(home, ".vscode-server", "cli", "servers", "Stable-abc123", "server", "package.json"), `{"version":"1.95.0"}`)

	installs := Scan(home, "linux", Limits{})
	local := byID(installs, FamilyVSCode, "vscode", "")
	if len(local) != 3 {
		t.Fatalf("local vscode plugins = %v", local)
	}
	claude := local["anthropic.claude-code|user"]
	if claude.DisplayName != "Claude Code for VS Code" || claude.Version != "2.0.1" || claude.Enabled != EnabledOn ||
		claude.EnabledSource != SourceStateDB || claude.InstalledAt == nil || claude.Publisher != "Anthropic" {
		t.Fatalf("claude = %+v", claude)
	}
	if p := local["ms-python.python|user"]; p.Enabled != EnabledOff {
		t.Fatalf("python should be disabled from state.vscdb: %+v", p)
	}
	if p := local["anthropic.claude-code|profile:a1b2"]; p.Enabled != EnabledOff {
		t.Fatalf("profile state should disable claude: %+v", p)
	}
	remote := byID(installs, FamilyVSCode, "cursor", RemoteSSHServer)
	if p := remote["openai.chatgpt|remote"]; p.Version != "1.2.3" || p.DisplayName != "Codex" || p.Enabled != EnabledClientSideUnknown {
		t.Fatalf("remote = %v", remote)
	}
	var build bool
	for _, inst := range installs {
		build = build || (inst.Product == "vscode" && inst.RemoteKind == RemoteSSHServer && inst.Version == "1.95.0" && inst.Channel == "stable")
	}
	if !build {
		t.Fatalf("server build missing: %+v", installs)
	}

	// The plugin limit cuts the list and marks the installation partial.
	capped := Scan(home, "linux", Limits{MaxPlugins: 2})
	total := 0
	partial := false
	for _, inst := range capped {
		total += len(inst.Plugins)
		partial = partial || inst.Partial
	}
	if total != 3 || !partial {
		t.Fatalf("capped scan: total=%d partial=%v", total, partial)
	}

	// A scan that must not follow links passes through none above the last
	// element either: another home's .cursor linked in is not read.
	other := t.TempDir()
	writeFile(t, filepath.Join(other, ".cursor", "extensions", "x.y-1.0.0", "package.json"), `{"name":"y","publisher":"x","version":"1.0.0"}`)
	if err := os.Symlink(filepath.Join(other, ".cursor"), filepath.Join(home, ".cursor")); err != nil {
		t.Skipf("symlink: %v", err) // Windows without the symlink privilege
	}
	if got := byID(Scan(home, "linux", Limits{}), FamilyVSCode, "cursor", ""); len(got) != 0 {
		t.Fatalf("a scan that must not follow links read a linked folder: %v", got)
	}
	if got := byID(Scan(home, "linux", Limits{FollowSymlinks: true}), FamilyVSCode, "cursor", ""); len(got) != 1 {
		t.Fatalf("a scan that follows links missed the linked folder: %v", got)
	}
}

func TestLargeVSCodeInventoryKeepsLaterJetBrainsPlugins(t *testing.T) {
	home := t.TempDir()
	var manifest strings.Builder
	manifest.WriteByte('[')
	for i := 0; i < 5000; i++ {
		if i > 0 {
			manifest.WriteByte(',')
		}
		manifest.WriteString(fmt.Sprintf(`{"identifier":{"id":"bulk.ext%04d"},"version":"1"}`, i))
	}
	manifest.WriteByte(']')
	writeFile(t, filepath.Join(home, ".vscode", "extensions", "extensions.json"), manifest.String())
	writeFile(t, filepath.Join(home, ".local", "share", "JetBrains", "IdeaIC2025.2", "ai", "META-INF", "plugin.xml"),
		`<idea-plugin><id>com.example.ai</id></idea-plugin>`)
	installs := Scan(home, "linux", Limits{})
	vs, jb := false, false
	for _, inst := range installs {
		if inst.Product == "vscode" {
			vs = len(inst.Plugins) == DefaultMaxPlugins && inst.Partial
		}
		if inst.Product == "intellij-idea-ce" {
			jb = len(inst.Plugins) == 1 && inst.Plugins[0].ID == "com.example.ai"
		}
	}
	if !vs || !jb {
		t.Fatalf("later IDE was starved: vscode=%v jetbrains=%v", vs, jb)
	}
}

func TestScanJetBrains(t *testing.T) {
	home := t.TempDir()
	config := filepath.Join(home, ".config", "JetBrains", "PyCharm2024.1")
	writeFile(t, filepath.Join(config, "disabled_plugins.txt"), "com.example.off\n")
	plugins := filepath.Join(home, ".local", "share", "JetBrains", "PyCharm2024.1")
	writeJar(t, filepath.Join(plugins, "github-copilot-intellij", "lib", "github-copilot-intellij-1.5.jar"),
		`<?xml version="1.0"?><idea-plugin><id>com.github.copilot</id><name>GitHub Copilot</name><version>1.5.20</version><vendor url="https://github.com">GitHub</vendor><depends>com.intellij.modules.platform</depends></idea-plugin>`)
	writeJar(t, filepath.Join(plugins, "off-plugin.jar"), `<idea-plugin><id>com.example.off</id><name>Off</name><version>0.1</version></idea-plugin>`)
	writeFile(t, filepath.Join(home, ".cache", "JetBrains", "RemoteDev", "dist", "abc_ideaIU-2024.1", "product-info.json"), `{"name":"IntelliJ IDEA","version":"2024.1","productCode":"IU"}`)

	writeFile(t, filepath.Join(plugins, "meta", "cache.json"), `{}`)
	installs := Scan(home, "linux", Limits{})
	got := byID(installs, FamilyJetBrains, "pycharm", "")
	if _, cache := got["meta|user"]; cache {
		t.Fatal("JetBrains metadata cache was reported as a plugin")
	}
	copilot := got["com.github.copilot|user"]
	if copilot.DisplayName != "GitHub Copilot" || copilot.Version != "1.5.20" || copilot.Publisher != "GitHub" || copilot.Enabled != EnabledOn {
		t.Fatalf("copilot = %+v (all %v)", copilot, got)
	}
	if off := got["com.example.off|user"]; off.Enabled != EnabledOff || off.EnabledSource != SourceDisabledPlugins {
		t.Fatalf("off = %+v", off)
	}
	var remote bool
	for _, inst := range installs {
		remote = remote || (inst.RemoteKind == RemoteJetBrainsDevEnv && inst.Product == "intellij-idea" && inst.Version == "2024.1")
	}
	if !remote {
		t.Fatalf("remote dev dist missing: %+v", installs)
	}

	// macOS keeps plugins inside the config directory.
	mac := t.TempDir()
	writeJar(t, filepath.Join(mac, "Library", "Application Support", "Google", "AndroidStudio2024.2", "plugins", "x.jar"), `<idea-plugin><id>x.y</id></idea-plugin>`)
	if got := byID(Scan(mac, "darwin", Limits{}), FamilyJetBrains, "android-studio", ""); got["x.y|user"].ID != "x.y" {
		t.Fatalf("android studio = %v", got)
	}
}

func TestScanOtherEditors(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".local", "share", "zed", "extensions", "installed", "html", "extension.toml"),
		"id = \"html\"\nname = \"HTML\"\nversion = \"0.1.2\"\nauthors = [\"Zed <hi@zed.dev>\"]\n[grammars.html]\nrepository = \"x\"\n")
	writeFile(t, filepath.Join(home, ".config", "nvim", "lazy-lock.json"), `{"copilot.lua":{"branch":"master","commit":"0123456789abcdef"}}`)
	writeFile(t, filepath.Join(home, ".config", "nvim", "pack", "p", "opt", "avante.nvim", "README"), "x")
	writeFile(t, filepath.Join(home, ".vim", "pack", "p", "start", "copilot.vim", "README"), "x")
	writeFile(t, filepath.Join(home, ".eclipse", "org.eclipse.platform_1", "configuration", "org.eclipse.equinox.simpleconfigurator", "bundles.info"),
		"#encoding=UTF-8\norg.eclipse.core.runtime,3.0.0,plugins/a.jar,4,true\ncom.example.tool,1.2.0,plugins/b.jar,4,false\n")

	installs := Scan(home, "linux", Limits{})
	if p := byID(installs, FamilyZed, "zed", "")["html|user"]; p.Version != "0.1.2" || p.Publisher != "Zed" || p.Enabled != EnabledOn {
		t.Fatalf("zed = %+v", p)
	}
	nvim := byID(installs, FamilyVim, "neovim", "")
	if p := nvim["copilot.lua|user"]; p.Version != "0123456789ab" || p.EnabledSource != SourceLockfile {
		t.Fatalf("lazy = %+v", p)
	}
	if p := nvim["avante.nvim|user"]; p.Enabled != EnabledOff || p.EnabledSource != SourcePackOpt {
		t.Fatalf("pack opt = %+v", p)
	}
	if p := byID(installs, FamilyVim, "vim", "")["copilot.vim|user"]; p.Enabled != EnabledOn {
		t.Fatalf("pack start = %+v", p)
	}
	eclipse := byID(installs, FamilyEclipse, "eclipse", "")
	if len(eclipse) != 1 || eclipse["com.example.tool|user"].Version != "1.2.0" {
		t.Fatalf("eclipse = %v", eclipse)
	}

	// Visual Studio: a VSIX v2 manifest, with the enabled list stubbed
	// (the privateregistry.bin hive is only readable on Windows).
	win := t.TempDir()
	instance := filepath.Join(win, "AppData", "Local", "Microsoft", "VisualStudio", "17.0_1a2b3c4d")
	writeFile(t, filepath.Join(instance, "Extensions", "q1w2", "extension.vsixmanifest"),
		`<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011"><Metadata><Identity Id="Example.Tool" Version="1.0" Language="en-US" Publisher="Example"/><DisplayName>Example Tool</DisplayName></Metadata><Installation><InstallationTarget Id="Microsoft.VisualStudio.Community"/></Installation></PackageManifest>`)
	writeFile(t, filepath.Join(instance, "Extensions", "e3r4", "extension.vsixmanifest"),
		`<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011"><Metadata><Identity Id="Other.Ext" Version="2.0" Publisher="Other"/><DisplayName>Other</DisplayName></Metadata></PackageManifest>`)
	saved := visualStudioEnabledLookup
	t.Cleanup(func() { visualStudioEnabledLookup = saved })
	visualStudioEnabledLookup = func(string, string) (map[string]bool, bool) { return map[string]bool{"example.tool": true}, true }
	vs := byID(Scan(win, "windows", Limits{}), FamilyVisualStudio, "visual-studio", "")
	if p := vs["Example.Tool|user"]; p.DisplayName != "Example Tool" || p.Enabled != EnabledOn || p.EnabledSource != SourcePrivateRegistry {
		t.Fatalf("vs = %v", vs)
	}
	if p := vs["Other.Ext|user"]; p.Enabled != EnabledOff {
		t.Fatalf("vs other = %+v", p)
	}
}

func TestWindowsHomeGrantsIncludeTraversalAttributes(t *testing.T) {
	grants := WindowsHomeGrants(t.TempDir())
	byPath := make(map[string]WindowsGrant, len(grants))
	for _, g := range grants {
		byPath[g.Path] = g
	}
	for _, path := range []string{`.vscode`, `AppData`, `AppData\Roaming`, `AppData\Roaming\Code`, `AppData\Roaming\Code\User`, `AppData\Local\Microsoft`} {
		g, ok := byPath[path]
		if !ok || g.Tree {
			t.Errorf("missing narrow traversal grant: %s", path)
		}
	}
}

func TestVisualStudioEnabledNamesAcceptsShortEnumeration(t *testing.T) {
	enabled, ok := visualStudioEnabledNames(func(limit int) ([]string, error) {
		if limit != visualStudioMaxExtensions {
			t.Fatalf("limit = %d", limit)
		}
		return []string{"Example.Tool,1.0"}, io.EOF
	})
	if !ok || !enabled["example.tool"] {
		t.Fatalf("short registry enumeration: %v, %v", enabled, ok)
	}
}

// A managed Windows gateway reads only what the enumerator grants it
// (WindowsHomeGrants): every path a Windows scan reads, including Remote-SSH
// servers, %LOCALAPPDATA%\JetBrains and Android Studio, must be granted.
// Lockfile entries can report a path without reading it. Caches, unrelated
// data beside plugin folders and linked folders remain ungranted (GAP-0042).
func TestWindowsHomeGrantsCoverTheWindowsScan(t *testing.T) {
	home := t.TempDir()
	local, roaming := filepath.Join(home, "AppData", "Local"), filepath.Join(home, "AppData", "Roaming")
	writeFile(t, filepath.Join(home, ".vscode", "extensions", "anthropic.claude-code-2.0.1", "package.json"),
		`{"name":"claude-code","publisher":"anthropic","version":"2.0.1"}`)
	writeFile(t, filepath.Join(roaming, "Code", "User", "profiles", "a1b2", "extensions.json"),
		`[{"identifier":{"id":"anthropic.claude-code"},"version":"2.0.1","relativeLocation":"anthropic.claude-code-2.0.1"}]`)
	writeFile(t, filepath.Join(home, ".vscode-server", "extensions", "openai.chatgpt-1.0.0", "package.json"),
		`{"name":"chatgpt","publisher":"openai","version":"1.0.0"}`)
	writeFile(t, filepath.Join(home, ".vscode-server", "cli", "servers", "Stable-0a1b2c", "server", "package.json"), `{"version":"1.105.0"}`)
	writeJar(t, filepath.Join(roaming, "JetBrains", "PyCharm2024.1", "plugins", "copilot", "lib", "copilot.jar"),
		`<idea-plugin><id>com.github.copilot</id><version>1.5</version></idea-plugin>`)
	writeJar(t, filepath.Join(local, "JetBrains", "IntelliJIdea2025.2", "plugins", "ai", "lib", "ai.jar"),
		`<idea-plugin><id>com.intellij.ml.llm</id><version>252.1</version></idea-plugin>`)
	writeFile(t, filepath.Join(local, "JetBrains", "RemoteDev", "dist", "a1_ideaIU-252", "product-info.json"), `{"version":"2025.2","productCode":"IU"}`)
	writeJar(t, filepath.Join(roaming, "Google", "AndroidStudio2025.1", "plugins", "gemini", "lib", "gemini.jar"),
		`<idea-plugin><id>com.google.gemini</id><version>1.0</version></idea-plugin>`)
	writeFile(t, filepath.Join(roaming, "Google", "AndroidStudio2025.1", "disabled_plugins.txt"), "com.google.gemini\n")
	writeJar(t, filepath.Join(local, "Google", "AndroidStudio2025.1", "plugins", "flutter.jar"),
		`<idea-plugin><id>io.flutter</id><version>85.0</version></idea-plugin>`)
	writeFile(t, filepath.Join(home, "eclipse", "java-2025-09", "eclipse", "configuration", "org.eclipse.equinox.simpleconfigurator", "bundles.info"),
		"com.example.tool,1.2.0,plugins/com.example.tool_1.2.0.jar,4,false\n")
	writeFile(t, filepath.Join(local, "Zed", "extensions", "installed", "html", "extension.toml"), "id = \"html\"\n")
	writeFile(t, filepath.Join(local, "nvim", "lazy-lock.json"), `{"copilot.lua":{"commit":"0123456789abcdef"}}`)
	private := []string{
		filepath.Join(home, ".vscode-server", "data", "User", "History", "entries.json"),
		filepath.Join(local, "JetBrains", "IntelliJIdea2025.2", "caches", "content.dat"),
		filepath.Join(local, "Google", "Chrome", "User Data", "Local State"),
	}
	for _, path := range private {
		writeFile(t, path, "{}")
	}
	outside := t.TempDir()
	writeJar(t, filepath.Join(outside, "plugins", "x", "lib", "x.jar"), `<idea-plugin><id>x.linked</id></idea-plugin>`)
	// Without the symlink privilege (Windows) the link check is left out.
	linkErr := os.Symlink(outside, filepath.Join(local, "JetBrains", "GoLand2025.1"))

	grants := WindowsHomeGrants(home)
	abs := func(rel string) string {
		return filepath.Join(home, filepath.FromSlash(strings.ReplaceAll(rel, `\`, "/")))
	}
	under := func(path, dir string) bool { return strings.HasPrefix(path, dir+string(filepath.Separator)) }
	readable := func(path string) bool {
		for _, g := range grants {
			if dir := abs(g.Path); path == dir || (g.Tree && under(path, dir)) {
				return true
			}
		}
		return false
	}
	// A server build or remote-dev backend is read through one metadata
	// file below its root.
	grantedBelow := func(root string) bool {
		for _, g := range grants {
			if under(abs(g.Path), root) {
				return true
			}
		}
		return false
	}
	plugins := 0
	for _, inst := range Scan(home, "windows", Limits{}) {
		if !readable(inst.Root) && !grantedBelow(inst.Root) {
			t.Errorf("%s installation at %s is not granted", inst.Product, inst.Root)
		}
		for _, p := range inst.Plugins {
			plugins++
			// Lockfile entries supply a path as metadata; Scan never reads it.
			if p.EnabledSource != SourceLockfile && !readable(p.Path) {
				t.Errorf("%s plugin %s at %s is not granted", inst.Product, p.ID, p.Path)
			}
		}
	}
	if plugins != 10 {
		t.Errorf("the Windows fixture scan found %d plugins, want 10", plugins)
	}
	for _, path := range private {
		if readable(path) {
			t.Errorf("%s is granted", path)
		}
	}
	for _, g := range grants {
		if linkErr == nil && strings.Contains(g.Path, "GoLand") {
			t.Errorf("the linked folder is granted: %s", g.Path)
		}
	}
}

func TestZedDirectoryCapMarksPartial(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, ".local", "share", "zed", "extensions", "installed")
	for i := 0; i <= zedMaxExtensions; i++ {
		if err := os.MkdirAll(filepath.Join(root, fmt.Sprintf("extension-%04d", i)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, inst := range Scan(home, "linux", Limits{}) {
		if inst.Family == FamilyZed {
			if len(inst.Plugins) != zedMaxExtensions || !inst.Partial {
				t.Fatalf("Zed directory cap: plugins=%d partial=%v", len(inst.Plugins), inst.Partial)
			}
			return
		}
	}
	t.Fatal("Zed installation missing")
}

func TestVSCodeDisabledStateReadsLiveWAL(t *testing.T) {
	home := t.TempDir()
	ext := filepath.Join(home, ".vscode", "extensions")
	writeFile(t, filepath.Join(ext, "extensions.json"), `[{"identifier":{"id":"example.extension"},"version":"1.0"}]`)
	path := filepath.Join(home, ".config", "Code", "User", "globalStorage", "state.vscdb")
	writeStateDB(t, path, "[]")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA wal_autocheckpoint=0`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE ItemTable SET value=? WHERE key=?`, `[{"id":"example.extension"}]`, "extensionsIdentifiers/disabled"); err != nil {
		t.Fatal(err)
	}
	plugins := byID(Scan(home, "linux", Limits{}), FamilyVSCode, "vscode", "")
	p := plugins["example.extension|user"]
	if p.Enabled != EnabledOff || p.EnabledSource != SourceStateDB {
		t.Fatalf("live disabled state: %+v", p)
	}
}

func TestUnreadableVSCodeExtensionsKeepInstallationPartial(t *testing.T) {
	if os.Geteuid() == 0 || runtime.GOOS == "windows" {
		t.Skip("requires Unix directory permissions")
	}
	home := t.TempDir()
	ext := filepath.Join(home, ".vscode", "extensions")
	writeFile(t, filepath.Join(ext, "example.plugin-1.0", "package.json"), `{"name":"plugin","publisher":"example"}`)
	if err := os.Chmod(ext, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ext, 0o755) })
	installs := Scan(home, runtime.GOOS, Limits{})
	for _, inst := range installs {
		if inst.Family == FamilyVSCode && inst.Product == "vscode" && inst.Root == ext {
			if !inst.Partial {
				t.Fatal("unreadable extension directory reported as complete")
			}
			return
		}
	}
	t.Fatal("visible installation was omitted")
}

// A display name is readable text on one line: bidi overrides and other
// format characters go, controls become one space, and the length stays
// bounded (GAP-0670).
func TestCleanKeepsDisplayNamesReadable(t *testing.T) {
	for in, want := range map[string]string{
		"safe \u202egnp.exe":            "safe gnp.exe",
		"a\u2066b\u2069c\u200bd":        "abcd",
		"line1\nline2\r\nline3":         "line1 line2 line3",
		"\x1b[2J\x1b[31mred":            "[2J [31mred",
		"  [bold red]RED[/bold red]\t ": "[bold red]RED[/bold red]",
	} {
		if got := clean(in); got != want {
			t.Errorf("clean(%q) = %q, want %q", in, got, want)
		}
	}
	if got := clean(strings.Repeat("x", 3000)); len(got) != maxFieldLen {
		t.Errorf("clean bounded a long name to %d bytes, want %d", len(got), maxFieldLen)
	}
}
