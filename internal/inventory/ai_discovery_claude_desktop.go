// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/claudedesktop"
	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
)

// Claude Desktop and Cowork discovery.
//
// Cowork is Claude Desktop's agent mode: the Claude Code engine Desktop
// bundles runs as the user and its shell commands run in a local VM. The
// claude_desktop detector reports, per scanned home that has a Claude Desktop
// data folder, what that folder shows. It only lists and stats a few known
// folders (every read is bounded and never follows a link) and reads two small
// JSON files and one Info.plist; it never starts the app, the engine or the VM.
// The VM bundle is several gigabytes, so its size is the sum of the sizes of
// the files the bundle holds, never a walk of its contents.
//
// Layouts (macOS measured on Claude Desktop 4.4212.0 and 4.16336.0, Windows
// MSIX and the Linux 1p data folder on 4.16336.0; the rest is "live check"):
//
//	data folder   one per deployment and install, internal/claudedesktop:
//	              macOS ~/Library/Application Support/Claude (1p), Claude-3p (3p)
//	              Windows %APPDATA%\Claude, the MSIX package's
//	              %LOCALAPPDATA%\Claude-Data\claude_<id> (1p),
//	              %LOCALAPPDATA%\Claude-3p (3p)
//	              Linux ~/.config/Claude (1p), ~/.config/Claude-3p (3p)
//	engine        <data>/claude-code/<version>[/<hash>/claude.app]
//	VM bundle     <data>/vm_bundles/claudevm.bundle
//	sessions      <data>/local-agent-mode-sessions/<account>/<org>/local_*.json
//	plugins       <data>/local-agent-mode-sessions/<account>/<org>/rpm/manifest.json
//	VM probe      <data>/vm-support-probe.json
//
// Connectors (the account's remote MCP servers) have no local file, so they
// are not reported.
const (
	claudeDesktopSignatureID = "claude-desktop"
	claudeDesktopDetector    = "claude_desktop"

	claudeDesktopMaxEntries       = 256 // entries read from any one folder
	claudeDesktopMaxAccountDirs   = 16  // account and organization folders per level
	claudeDesktopMaxBundleEntries = 512 // files and folders counted in the VM bundle
	claudeDesktopMaxPlugins       = 64
	claudeDesktopMaxJSONBytes     = 1 << 20
	claudeDesktopMaxPlistBytes    = 1 << 20
	claudeDesktopTextMax          = 96
	claudeDesktopVersionMax       = 32
)

// deployment values: the data folder's Claude Desktop deployment.
const (
	ClaudeDesktopFirstParty = string(claudedesktop.FirstParty) // signed in to Claude
	ClaudeDesktopThirdParty = string(claudedesktop.ThirdParty) // third-party inference (Bedrock, Vertex AI, Foundry)
)

// installed_source values.
const (
	ClaudeDesktopInstalledAppBundle     = "app_bundle"     // macOS Claude.app
	ClaudeDesktopInstalledInstallFolder = "install_folder" // Windows %LOCALAPPDATA%\AnthropicClaude
	ClaudeDesktopInstalledMSIXPackage   = "msix_package"   // Windows %LOCALAPPDATA%\Packages\Claude_*
	ClaudeDesktopInstalledDataFolder    = "data_folder"    // Linux: no install location is probed
)

// cowork_enabled_source values.
const (
	ClaudeDesktopCoworkSessions   = "cowork_sessions"  // local-agent-mode-sessions holds a session
	ClaudeDesktopCoworkVMBundle   = "vm_bundle"        // the VM bundle is on disk
	ClaudeDesktopCoworkVMProbeOff = "vm_support_probe" // Desktop recorded that this machine cannot run the VM
	claudeDesktopVirtUnsupported  = "unsupported"      // vm-support-probe.json virtSupport value that means off
	claudeDesktopVMBundleName     = "claudevm.bundle"  // live check on Windows and Linux
	claudeDesktopSessionsDirName  = "local-agent-mode-sessions"
	claudeDesktopSkillsPluginName = "skills-plugin" // Anthropic's own skills, next to the account folders
)

// ClaudeDesktopInfo is what discovery reports about Claude Desktop and Cowork
// for one data folder (AISignal.ClaudeDesktop, JSON "claude_desktop").
//
// CoworkEnabled is a pointer on purpose: null is "unknown", never a guess. It
// is true when this machine shows Cowork set up (CoworkEnabledSource names the
// evidence: a session on disk, or the VM bundle), false only when Claude
// Desktop itself recorded that the machine cannot run the VM, and null
// otherwise. It does not read the organization's server-side switch.
type ClaudeDesktopInfo struct {
	// Installed is true when the app (or, on Linux, which has no install
	// probe, its data folder) was found; InstalledSource says which.
	Installed       bool   `json:"installed"`
	InstalledSource string `json:"installed_source,omitempty"`
	// Version is the Claude Desktop app version (Info.plist
	// CFBundleShortVersionString, or the install folder name on Windows).
	Version             string `json:"version,omitempty"`
	CoworkEnabled       *bool  `json:"cowork_enabled"`
	CoworkEnabledSource string `json:"cowork_enabled_source,omitempty"`
	// EngineVersion is the newest Claude Code build Desktop bundles (the
	// folder name under <data>/claude-code).
	EngineVersion string `json:"engine_version,omitempty"`
	// VMBundlePresent reports the Cowork VM bundle folder; VMBundleBytes is
	// the apparent size of the files in it (zero when absent).
	VMBundlePresent bool  `json:"vm_bundle_present"`
	VMBundleBytes   int64 `json:"vm_bundle_bytes,omitempty"`
	// CoworkPlugins are the names of the plugins the user enabled in
	// Cowork, sorted, from the account's plugin manifest. Names only.
	CoworkPlugins []string `json:"cowork_plugins,omitempty"`
	// Deployment is the deployment whose data folder this is: "1p" (signed
	// in to Claude) or "3p" (third-party inference: Bedrock, Vertex AI,
	// Foundry). Claude Desktop keeps a separate data folder, engine and
	// Cowork sessions for each, so one account can report both.
	Deployment string `json:"deployment,omitempty"`
}

type claudeDesktopLayout struct {
	// dataRoots are Claude Desktop's data folders (claudedesktop.Roots).
	dataRoots []claudedesktop.Root
	// appBundles, installDirs and packageDirs are catalog-style candidates
	// (expandCandidatePathBounded); one "*" is globbed.
	appBundles  []string
	installDirs []string
	packageDirs []string
	// dataFolderIsInstall: no install location is probed, so the data folder
	// is the install evidence.
	dataFolderIsInstall bool
}

// claudeDesktopSystemAppRoots are the machine-wide macOS application folders;
// tests replace it.
var claudeDesktopSystemAppRoots = []string{"/Applications"}

func claudeDesktopLayoutFor(goos string) (claudeDesktopLayout, bool) {
	switch goos {
	case "darwin":
		bundles := []string{"~/Applications/Claude.app"}
		for _, root := range claudeDesktopSystemAppRoots {
			bundles = append(bundles, filepath.Join(root, "Claude.app"))
		}
		return claudeDesktopLayout{
			dataRoots:  claudedesktop.Roots(goos),
			appBundles: bundles,
		}, true
	case "windows":
		return claudeDesktopLayout{
			dataRoots: claudedesktop.Roots(goos),
			// Squirrel installs keep app-<version> folders here (live check).
			installDirs: []string{"$LOCALAPPDATA/AnthropicClaude"},
			packageDirs: []string{"$LOCALAPPDATA/Packages/Claude_*"},
		}, true
	case "linux":
		// Claude Desktop on Linux is a beta (live check).
		return claudeDesktopLayout{
			dataRoots:           claudedesktop.Roots(goos),
			dataFolderIsInstall: true,
		}, true
	}
	return claudeDesktopLayout{}, false
}

type claudeDesktopPath struct {
	path  string
	owner string // the scanned home holding path, "" for a machine-wide folder
	// deployment is the data folder's deployment ("" for an install path).
	deployment string
}

// claudeDesktopAcc remembers why a report is partial.
type claudeDesktopAcc struct{ reason string }

func (a *claudeDesktopAcc) note(reason string) {
	if a.reason == "" {
		a.reason = reason
	}
}

func (a *claudeDesktopAcc) noteErr(err error) {
	switch {
	case err == nil, errors.Is(err, fs.ErrNotExist):
	case errors.Is(err, fs.ErrPermission):
		a.note(CoverageReasonPermissionDenied)
	default:
		a.note(CoverageReasonReadError)
	}
}

var claudeDesktopPlistVersion = lazyregexp.New(`<key>CFBundleShortVersionString</key>\s*<string>([^<]{1,64})</string>`)
var claudeDesktopVersionPattern = lazyregexp.New(`^[0-9]{1,9}(\.[0-9]{1,9}){1,3}$`)

func validClaudeDesktopVersion(version string) bool {
	return len(version) <= claudeDesktopVersionMax && claudeDesktopVersionPattern.MatchString(version)
}

func compareClaudeDesktopVersions(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

var errClaudeDesktopLink = errors.New("a link or reparse point stands where a folder is expected")

// claudeDesktopRealDir is true for a folder that is not a symbolic link, a
// junction or another reparse point.
func claudeDesktopRealDir(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.IsDir() && info.Mode()&(os.ModeSymlink|os.ModeIrregular) == 0 && !claudeDesktopReparsePoint(path)
}

// claudeDesktopReadDir lists at most limit entries of dir; overflow reports
// more. It never follows a link: dir must itself be a real folder (a link
// there is errClaudeDesktopLink), the opened folder must be the one that was
// checked, and entries describe themselves. Every folder below the data
// folder is listed through here, so a link on any level is refused.
func claudeDesktopReadDir(dir string, limit int) (entries []os.DirEntry, overflow bool, err error) {
	before, err := os.Lstat(dir)
	if err != nil {
		return nil, false, err
	}
	if !claudeDesktopRealDir(dir) {
		return nil, false, fmt.Errorf("%w: %s", errClaudeDesktopLink, filepath.Base(dir))
	}
	f, err := os.Open(dir)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	// On Windows the Lstat identity is read lazily from the path, so the
	// opened handle is also checked against a no-follow handle of dir.
	if opened, err := f.Stat(); err != nil || !os.SameFile(before, opened) || !claudeDesktopOpenedIsChecked(dir, f) {
		return nil, false, fmt.Errorf("%w: %s", errClaudeDesktopLink, filepath.Base(dir))
	}
	entries, err = f.ReadDir(limit + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false, err
	}
	if len(entries) > limit {
		return entries[:limit], true, nil
	}
	return entries, false, nil
}

// claudeDesktopNewestVersion returns the highest dotted-numeric folder name
// directly under dir, or "" (also when dir is absent).
func claudeDesktopNewestVersion(dir, prefix string, acc *claudeDesktopAcc, limit int) string {
	entries, overflow, err := claudeDesktopReadDir(dir, limit)
	acc.noteErr(err)
	if overflow {
		acc.note(CoverageReasonCapExceeded)
	}
	best := ""
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() || !strings.HasPrefix(strings.ToLower(name), prefix) {
			continue
		}
		version := name[len(prefix):]
		if validClaudeDesktopVersion(version) && (best == "" || compareClaudeDesktopVersions(version, best) > 0) {
			best = version
		}
	}
	return best
}

func (s *ContinuousDiscoveryService) claudeDesktopOwner(path string) string {
	for _, home := range s.homesToScan() {
		rel, err := filepath.Rel(home, path)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return home
		}
	}
	return ""
}

// claudeDesktopPaths expands catalog-style candidates for every scanned home,
// each path once. overflowOwners are the scanned homes (the owner of a
// machine-wide pattern is "") where a "*" matched more paths than were kept.
func (s *ContinuousDiscoveryService) claudeDesktopPaths(candidates []string) (out []claudeDesktopPath, overflowOwners map[string]bool) {
	seen := map[string]bool{}
	for _, candidate := range candidates {
		paths, overflowed := s.expandCandidatePathBounded(candidate)
		for _, pattern := range overflowed {
			if overflowOwners == nil {
				overflowOwners = map[string]bool{}
			}
			overflowOwners[s.claudeDesktopOwner(pattern)] = true
		}
		for _, path := range paths {
			key := strings.ToLower(path)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, claudeDesktopPath{path: path, owner: s.claudeDesktopOwner(path)})
		}
	}
	return out, overflowOwners
}

// claudeDesktopDataPaths expands the data roots for every scanned home, each
// folder once, with its deployment, and the homes whose MSIX glob left a
// folder out (claudeDesktopPaths).
func (s *ContinuousDiscoveryService) claudeDesktopDataPaths(roots []claudedesktop.Root) ([]claudeDesktopPath, map[string]bool) {
	var out []claudeDesktopPath
	overflowOwners := map[string]bool{}
	seen := map[string]bool{}
	for _, root := range roots {
		paths, overflowed := s.claudeDesktopPaths([]string{root.Candidate()})
		for owner := range overflowed {
			overflowOwners[owner] = true
		}
		for _, data := range paths {
			if key := strings.ToLower(data.path); !seen[key] {
				seen[key] = true
				data.deployment = string(root.Deployment)
				out = append(out, data)
			}
		}
	}
	return out, overflowOwners
}

// claudeDesktopReachedWithoutLink is true for a data folder that is a real
// folder reached from its owner's home with no link, junction or other
// reparse point on the way (Library/Application Support or .config as a
// link, say). A service scan also refuses those paths through
// profileLinkRefused; a per-user scan reads only the user's own files, but
// must not report a folder elsewhere as this account's Claude Desktop.
func claudeDesktopReachedWithoutLink(data claudeDesktopPath) bool {
	if !claudeDesktopRealDir(data.path) {
		return false
	}
	if data.owner == "" {
		return true
	}
	rel, err := filepath.Rel(data.owner, data.path)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	parts := strings.Split(rel, string(filepath.Separator))
	current := data.owner
	for _, part := range parts[:len(parts)-1] {
		current = filepath.Join(current, part)
		if !claudeDesktopRealDir(current) {
			return false
		}
	}
	return true
}

// claudeDesktopMarkerOnly is true for a data folder whose only entries are
// MSIX migration markers (claudedesktop.MigrationMarkerPrefix): Claude
// Desktop moved that install's data to Claude-Data and left the marker
// behind (measured on 4.16336.0 in Packages\Claude_<id>\LocalCache\Roaming\Claude),
// so the folder is no deployment of its own. The listing is bounded.
func claudeDesktopMarkerOnly(dir string) bool {
	entries, overflow, err := claudeDesktopReadDir(dir, 8)
	if err != nil || overflow || len(entries) == 0 {
		return false
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), claudedesktop.MigrationMarkerPrefix) {
			return false
		}
	}
	return true
}

// detectClaudeDesktop emits one claude_desktop signal for each Claude Desktop
// data folder of a scanned home. A machine with the app but no data folder
// (never started) is reported by the application detector alone.
func (s *ContinuousDiscoveryService) detectClaudeDesktop() []AISignal {
	var base *AISignature
	for i := range s.catalog {
		if s.catalog[i].ID == claudeDesktopSignatureID {
			base = &s.catalog[i]
			break
		}
	}
	layout, ok := claudeDesktopLayoutFor(discoveryGOOS)
	if base == nil || !ok {
		return nil
	}
	var out []AISignal
	dataPaths, overflowOwners := s.claudeDesktopDataPaths(layout.dataRoots)
	for _, data := range dataPaths {
		if !claudeDesktopReachedWithoutLink(data) || s.profileLinkRefused(data.path) || claudeDesktopMarkerOnly(data.path) {
			continue
		}
		acc := &claudeDesktopAcc{}
		if overflowOwners[data.owner] {
			// More MSIX data folders than are read: one left out may be a
			// deployment of this account.
			acc.note(CoverageReasonCapExceeded)
		}
		info := s.readClaudeDesktop(layout, data, acc)
		ev := AIEvidence{Type: claudeDesktopDetector, Basename: filepath.Base(data.path), PathHash: hashPath(data.path)}
		if s.keepEvidencePath() {
			ev.RawPath = data.path
		}
		sig := s.signalFromEvidence(*base, SignalDesktopApp, claudeDesktopDetector, []AIEvidence{ev})
		sig.ClaudeDesktop = info
		sig.EvidenceHash = claudeDesktopEvidenceHash(sig.EvidenceHash, info)
		if acc.reason != "" {
			sig.Partial, sig.CoverageReason = true, acc.reason
		}
		s.stampHomeOwner(&sig, data.path)
		out = append(out, sig)
	}
	return out
}

func (s *ContinuousDiscoveryService) readClaudeDesktop(layout claudeDesktopLayout, data claudeDesktopPath, acc *claudeDesktopAcc) *ClaudeDesktopInfo {
	info := &ClaudeDesktopInfo{Deployment: data.deployment}
	s.claudeDesktopInstall(layout, data, info, acc)
	if !info.Installed && layout.dataFolderIsInstall {
		info.Installed, info.InstalledSource = true, ClaudeDesktopInstalledDataFolder
	}
	info.EngineVersion = claudeDesktopNewestVersion(filepath.Join(data.path, claudedesktop.EngineFolder), "", acc, claudeDesktopMaxEntries)
	info.VMBundlePresent, info.VMBundleBytes = claudeDesktopVMBundle(data.path, acc)
	sessions, plugins := claudeDesktopCowork(data.path, acc)
	info.CoworkPlugins = plugins
	switch {
	case sessions:
		yes := true
		info.CoworkEnabled, info.CoworkEnabledSource = &yes, ClaudeDesktopCoworkSessions
	case info.VMBundlePresent:
		yes := true
		info.CoworkEnabled, info.CoworkEnabledSource = &yes, ClaudeDesktopCoworkVMBundle
	case claudeDesktopVMSupport(data.path, acc) == claudeDesktopVirtUnsupported:
		no := false
		info.CoworkEnabled, info.CoworkEnabledSource = &no, ClaudeDesktopCoworkVMProbeOff
	}
	return info
}

// claudeDesktopInstall fills Installed, InstalledSource and Version from the
// install locations of the data folder's owner (a machine-wide one counts for
// every owner).
func (s *ContinuousDiscoveryService) claudeDesktopInstall(layout claudeDesktopLayout, data claudeDesktopPath, info *ClaudeDesktopInfo, acc *claudeDesktopAcc) {
	applies := func(p claudeDesktopPath) bool { return p.owner == "" || p.owner == data.owner }
	set := func(source string) {
		if !info.Installed {
			info.Installed, info.InstalledSource = true, source
		}
	}
	bundles, _ := s.claudeDesktopPaths(layout.appBundles)
	for _, bundle := range bundles {
		if !applies(bundle) || !claudeDesktopRealDir(bundle.path) {
			continue
		}
		set(ClaudeDesktopInstalledAppBundle)
		if info.Version == "" {
			info.Version = claudeDesktopBundleVersion(bundle.path)
		}
	}
	installDirs, _ := s.claudeDesktopPaths(layout.installDirs)
	for _, dir := range installDirs {
		if !applies(dir) || !claudeDesktopRealDir(dir.path) {
			continue
		}
		set(ClaudeDesktopInstalledInstallFolder)
		if info.Version == "" {
			info.Version = claudeDesktopNewestVersion(dir.path, "app-", acc, claudeDesktopMaxEntries)
		}
	}
	packageDirs, _ := s.claudeDesktopPaths(layout.packageDirs)
	for _, pkg := range packageDirs {
		if applies(pkg) && claudeDesktopRealDir(pkg.path) {
			set(ClaudeDesktopInstalledMSIXPackage)
		}
	}
	// An MSIX install has no version here: its folder name lives in the
	// machine-wide WindowsApps, which names every installed build and does not
	// say which one this account runs.
}

func claudeDesktopBundleVersion(bundle string) string {
	raw, err := readBoundedRegularFileNoFollow(filepath.Join(bundle, "Contents", "Info.plist"), claudeDesktopMaxPlistBytes)
	if err != nil {
		return ""
	}
	match := claudeDesktopPlistVersion.FindSubmatch(raw)
	if match == nil {
		return ""
	}
	if version := strings.TrimSpace(string(match[1])); validClaudeDesktopVersion(version) {
		return version
	}
	return ""
}

// claudeDesktopVMBundle reports the Cowork VM bundle and the apparent size of
// the files in it. The bundle holds a handful of large image files; counting
// stops at claudeDesktopMaxBundleEntries entries (the size is then a lower
// bound and the report partial).
func claudeDesktopVMBundle(dataDir string, acc *claudeDesktopAcc) (present bool, size int64) {
	root := filepath.Join(dataDir, "vm_bundles")
	bundle := filepath.Join(root, claudeDesktopVMBundleName)
	if _, err := os.Lstat(root); err == nil && !claudeDesktopRealDir(root) {
		// Lstat of the bundle would follow a linked vm_bundles folder.
		acc.noteErr(errClaudeDesktopLink)
		return false, 0
	}
	if !claudeDesktopRealDir(bundle) {
		// The bundle's name is a live check off macOS: take the first
		// *.bundle folder instead.
		bundle = ""
		entries, overflow, err := claudeDesktopReadDir(root, claudeDesktopMaxEntries)
		acc.noteErr(err)
		if overflow {
			acc.note(CoverageReasonCapExceeded)
		}
		names := make([]string, 0, 1)
		for _, entry := range entries {
			if entry.IsDir() && strings.HasSuffix(strings.ToLower(entry.Name()), ".bundle") {
				names = append(names, entry.Name())
			}
		}
		if len(names) == 0 {
			return false, 0
		}
		sort.Strings(names)
		bundle = filepath.Join(root, names[0])
	}
	budget := claudeDesktopMaxBundleEntries
	var sum func(dir string, depth int)
	sum = func(dir string, depth int) {
		entries, overflow, err := claudeDesktopReadDir(dir, budget)
		acc.noteErr(err)
		if overflow {
			acc.note(CoverageReasonCapExceeded)
		}
		budget -= len(entries)
		for _, entry := range entries {
			switch {
			case entry.Type().IsRegular():
				if info, err := entry.Info(); err == nil && info.Size() > 0 {
					size += info.Size()
				}
			case entry.IsDir() && depth < 2 && budget > 0:
				sum(filepath.Join(dir, entry.Name()), depth+1)
			case entry.IsDir():
				acc.note(CoverageReasonCapExceeded)
			}
		}
	}
	sum(bundle, 0)
	return true, size
}

// claudeDesktopCowork reports whether a Cowork session is on disk and the
// plugin names of the accounts' plugin manifests.
func claudeDesktopCowork(dataDir string, acc *claudeDesktopAcc) (sessions bool, plugins []string) {
	root := filepath.Join(dataDir, claudeDesktopSessionsDirName)
	names := map[string]bool{}
	for _, account := range claudeDesktopSubdirs(root, acc) {
		if account == claudeDesktopSkillsPluginName {
			continue
		}
		for _, org := range claudeDesktopSubdirs(filepath.Join(root, account), acc) {
			orgDir := filepath.Join(root, account, org)
			entries, overflow, err := claudeDesktopReadDir(orgDir, claudeDesktopMaxEntries)
			acc.noteErr(err)
			if overflow {
				acc.note(CoverageReasonCapExceeded)
			}
			for _, entry := range entries {
				name := entry.Name()
				switch {
				case entry.Type().IsRegular() && strings.HasPrefix(name, "local_") && strings.HasSuffix(name, ".json"):
					sessions = true
				case entry.IsDir() && name == "rpm" && claudeDesktopRealDir(filepath.Join(orgDir, name)):
					for _, plugin := range claudeDesktopPluginNames(filepath.Join(orgDir, name, "manifest.json"), acc) {
						names[plugin] = true
					}
				}
			}
		}
	}
	for name := range names {
		plugins = append(plugins, name)
	}
	sort.Strings(plugins)
	if len(plugins) > claudeDesktopMaxPlugins {
		plugins = plugins[:claudeDesktopMaxPlugins]
		acc.note(CoverageReasonCapExceeded)
	}
	return sessions, plugins
}

// claudeDesktopSubdirs lists up to claudeDesktopMaxAccountDirs real folders.
func claudeDesktopSubdirs(dir string, acc *claudeDesktopAcc) []string {
	entries, overflow, err := claudeDesktopReadDir(dir, claudeDesktopMaxEntries)
	acc.noteErr(err)
	if overflow {
		acc.note(CoverageReasonCapExceeded)
	}
	var out []string
	for _, entry := range entries {
		if entry.IsDir() {
			out = append(out, entry.Name())
		}
	}
	sort.Strings(out)
	if len(out) > claudeDesktopMaxAccountDirs {
		out = out[:claudeDesktopMaxAccountDirs]
		acc.note(CoverageReasonCapExceeded)
	}
	return out
}

func claudeDesktopPluginNames(manifest string, acc *claudeDesktopAcc) []string {
	raw, err := readBoundedRegularFileNoFollow(manifest, claudeDesktopMaxJSONBytes)
	if err != nil {
		acc.noteErr(err)
		return nil
	}
	var doc struct {
		Plugins []struct {
			Name string `json:"name"`
		} `json:"plugins"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		acc.note(CoverageReasonParseError)
		return nil
	}
	var out []string
	for _, plugin := range doc.Plugins {
		if name := claudeDesktopText(plugin.Name); name != "" {
			out = append(out, name)
		}
	}
	return out
}

// claudeDesktopText trims a name read from a user-writable file to a short
// printable string ("" drops it).
func claudeDesktopText(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || !utf8.ValidString(value) || containsUnicodeControl(value) {
		return ""
	}
	if utf8.RuneCountInString(value) > claudeDesktopTextMax {
		runes := []rune(value)
		value = string(runes[:claudeDesktopTextMax])
	}
	return value
}

// claudeDesktopVMSupport is the virtSupport value of vm-support-probe.json,
// the probe Claude Desktop writes about whether this machine can run the VM.
func claudeDesktopVMSupport(dataDir string, acc *claudeDesktopAcc) string {
	raw, err := readBoundedRegularFileNoFollow(filepath.Join(dataDir, "vm-support-probe.json"), 64<<10)
	if err != nil {
		acc.noteErr(err)
		return ""
	}
	var probe struct {
		VirtSupport string `json:"virtSupport"`
	}
	if json.Unmarshal(raw, &probe) != nil {
		acc.note(CoverageReasonParseError)
		return ""
	}
	return strings.ToLower(strings.TrimSpace(probe.VirtSupport))
}

// claudeDesktopEvidenceHash folds the reported facts into a signal's evidence
// hash, so a change in them (Cowork turned on, a new engine) is a "changed"
// signal while the fingerprint, which comes from the data folder alone, stays
// put. The VM size is left out: the image is sparse and its size moves.
func claudeDesktopEvidenceHash(base string, info *ClaudeDesktopInfo) string {
	if info == nil {
		return base
	}
	facts := *info
	facts.VMBundleBytes = 0
	raw, err := json.Marshal(facts)
	if err != nil {
		return base
	}
	return hashValue(base + "|claude_desktop:" + string(raw))
}

// validateClaudeDesktopInfo bounds the claude_desktop block of a report
// signal: it is only for claude_desktop signals, and its text is short,
// printable and one of the values discovery writes.
func validateClaudeDesktopInfo(sig AISignal) error {
	info := sig.ClaudeDesktop
	if info == nil {
		return nil
	}
	if sig.Detector != claudeDesktopDetector || sig.Category != SignalDesktopApp {
		return errors.New("claude_desktop metadata is only allowed on claude_desktop signals")
	}
	if info.Version != "" && !validClaudeDesktopVersion(info.Version) || info.EngineVersion != "" && !validClaudeDesktopVersion(info.EngineVersion) {
		return errors.New("claude_desktop versions must be dotted numbers")
	}
	switch info.Deployment {
	case "", ClaudeDesktopFirstParty, ClaudeDesktopThirdParty:
	default:
		return fmt.Errorf("unsupported claude_desktop deployment %q", info.Deployment)
	}
	switch info.InstalledSource {
	case "", ClaudeDesktopInstalledAppBundle, ClaudeDesktopInstalledInstallFolder, ClaudeDesktopInstalledMSIXPackage, ClaudeDesktopInstalledDataFolder:
	default:
		return fmt.Errorf("unsupported claude_desktop installed_source %q", info.InstalledSource)
	}
	switch info.CoworkEnabledSource {
	case "", ClaudeDesktopCoworkSessions, ClaudeDesktopCoworkVMBundle, ClaudeDesktopCoworkVMProbeOff:
	default:
		return fmt.Errorf("unsupported claude_desktop cowork_enabled_source %q", info.CoworkEnabledSource)
	}
	if info.InstalledSource != "" && !info.Installed || (info.CoworkEnabled == nil) != (info.CoworkEnabledSource == "") {
		return errors.New("claude_desktop sources must match installed and cowork_enabled")
	}
	if info.VMBundleBytes < 0 || info.VMBundleBytes > 0 && !info.VMBundlePresent {
		return errors.New("claude_desktop vm_bundle_bytes must be non-negative and need a bundle")
	}
	if len(info.CoworkPlugins) > claudeDesktopMaxPlugins {
		return errors.New("too many claude_desktop plugins")
	}
	for _, plugin := range info.CoworkPlugins {
		if plugin == "" || utf8.RuneCountInString(plugin) > claudeDesktopTextMax || containsUnicodeControl(plugin) {
			return errors.New("claude_desktop plugin names must be short printable text")
		}
	}
	return nil
}
