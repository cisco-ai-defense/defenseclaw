// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package ideplugins

import (
	"archive/zip"
	"database/sql"
	"os"
	"path/filepath"
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
	if total != 2 || !partial {
		t.Fatalf("capped scan: total=%d partial=%v", total, partial)
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

	installs := Scan(home, "linux", Limits{})
	got := byID(installs, FamilyJetBrains, "pycharm", "")
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
