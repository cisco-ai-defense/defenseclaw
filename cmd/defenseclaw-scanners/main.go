// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Command defenseclaw-scanners runs the Python scanners the standalone
// Windows enterprise payload ships: skill-scanner, the MCP scan and
// DefenseClaw's plugin scanner. The CPython runtime and the locked
// site-packages tree (the same pins the per-user Windows install resolves)
// are embedded in this executable, so the payload stays one signed file per
// component. The standalone Windows lifecycle copies it into its own
// administrator-owned root (<ProgramData>\Cisco\DefenseClaw-ScannerRuntime)
// and runs "prepare", which unpacks the runtime under a folder named for its
// SHA-256 and compiles it; the gateway service then runs it read-only.
//
//	defenseclaw-scanners skill-scanner <skill-scanner arguments>
//	defenseclaw-scanners mcp-scan --json [--analyzers a,b] [--scan-prompts] [--scan-resources] [--scan-instructions] <url>
//	defenseclaw-scanners plugin-scan <plugin dir> [--policy p] [--profile p] [--include-self]
//	defenseclaw-scanners versions | --version | prepare | prune
package main

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

//go:embed all:payload
var payload embed.FS

const (
	runtimeArchiveName  = "payload/runtime.zip"
	runtimeManifestName = "payload/runtime.json"
	completeMarker      = ".complete"
	// maxRuntimeBytes bounds what the embedded archive may expand to.
	maxRuntimeBytes = 2 << 30
)

// runtimeManifest describes the embedded runtime (written by
// packaging/windows/standalone/build-scanner-runtime.sh).
type runtimeManifest struct {
	SchemaVersion int               `json:"schema_version"`
	SHA256        string            `json:"runtime_sha256"`
	Versions      map[string]string `json:"versions"`
}

// The Python programs each tool runs. Arguments after the program reach it
// as sys.argv[1:].
const (
	consoleEntryPointScript = `import importlib.metadata as m,sys; name=sys.argv[1]; sys.argv=[name,*sys.argv[2:]]; matches=[e for e in m.entry_points(group="console_scripts") if e.name==name]; sys.exit(matches[0].load()() if len(matches)==1 else 1)`

	pluginScanScript = `import json,sys
from defenseclaw.scanner.plugin_scanner import scan_plugin
from defenseclaw.scanner.plugin_scanner.types import PluginScanOptions
a=sys.argv[1:]; o=PluginScanOptions(); t=None; i=0
while i<len(a):
    x=a[i]
    if x in ("--policy","--profile") and i+1<len(a):
        setattr(o,x[2:],a[i+1]); i+=2
    elif x=="--include-self":
        o.include_self=True; i+=1
    elif t is None and not x.startswith("--"):
        t=x; i+=1
    else:
        sys.exit("plugin-scan: unexpected argument "+x)
if t is None:
    sys.exit("plugin-scan: a plugin directory is required")
print(json.dumps(scan_plugin(t,o).to_dict()))`

	// mcpScanScript is the gateway's "mcp scan --json" for a remote server:
	// the scanner settings come as arguments, and the judge and AI Defense
	// settings come from the environment that internal/scanner runtimeEnv
	// derives from config.
	mcpScanScript = `import os,sys
from defenseclaw.config import CiscoAIDefenseConfig, LLMConfig, MCPScannerConfig
from defenseclaw.scanner.mcp import MCPScannerWrapper
a=sys.argv[1:]; c=MCPScannerConfig(); t=None; i=0
while i<len(a):
    x=a[i]
    if x=="--json":
        i+=1
    elif x=="--analyzers" and i+1<len(a):
        c.analyzers=a[i+1]; i+=2
    elif x in ("--scan-prompts","--scan-resources","--scan-instructions"):
        setattr(c,x[2:].replace("-","_"),True); i+=1
    elif t is None and not x.startswith("--"):
        t=x; i+=1
    else:
        sys.exit("mcp-scan: unexpected argument "+x)
if t is None:
    sys.exit("mcp-scan: a server URL is required")
e=os.environ.get
llm=LLMConfig(model=e("DEFENSECLAW_SCANNER_LLM_MODEL",""), provider=e("DEFENSECLAW_SCANNER_LLM_PROVIDER",""), api_key=e("DEFENSECLAW_SCANNER_LLM_API_KEY",""), base_url=e("DEFENSECLAW_SCANNER_LLM_BASE_URL",""), region=e("DEFENSECLAW_SCANNER_LLM_REGION",""))
aid=CiscoAIDefenseConfig(api_key=e("DEFENSECLAW_SCANNER_AID_API_KEY",""), endpoint=e("DEFENSECLAW_SCANNER_AID_ENDPOINT","") or CiscoAIDefenseConfig().endpoint)
print(MCPScannerWrapper(c, None, aid, llm=llm).scan(t).to_json())`
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: defenseclaw-scanners skill-scanner|mcp-scan|plugin-scan|versions|prepare [arguments]")
		return 2
	}
	manifest, err := loadManifest()
	if err != nil {
		fmt.Fprintf(stderr, "defenseclaw-scanners: %v\n", err)
		return 1
	}
	switch args[0] {
	case "versions":
		prepared := false
		if root, err := runtimeRoot(); err == nil {
			prepared = runtimeComplete(filepath.Join(root, manifest.SHA256[:16]), manifest.SHA256)
		}
		encoded, _ := json.MarshalIndent(map[string]any{
			"versions": manifest.Versions, "runtime_sha256": manifest.SHA256, "prepared": prepared,
		}, "", "  ")
		fmt.Fprintln(stdout, string(encoded))
		return 0
	case "--version":
		fmt.Fprintln(stdout, versionLine(manifest))
		return 0
	}
	if runtime.GOOS != "windows" {
		fmt.Fprintln(stderr, "defenseclaw-scanners: the embedded scanner runtime runs only on Windows")
		return 1
	}
	var script string
	var scriptArgs []string
	switch args[0] {
	case "prepare":
		dir, err := prepareRuntime(manifest)
		if err != nil {
			fmt.Fprintf(stderr, "defenseclaw-scanners: %v\n", err)
			return 1
		}
		compileRuntime(dir, stderr)
		fmt.Fprintln(stdout, dir)
		return 0
	case "prune":
		// After the lifecycle put this runtime in place: remove the ones
		// earlier builds unpacked (a scan still running keeps its own).
		root, err := runtimeRoot()
		if err != nil {
			fmt.Fprintf(stderr, "defenseclaw-scanners: %v\n", err)
			return 1
		}
		pruneOtherRuntimes(root, manifest.SHA256[:16])
		return 0
	case "skill-scanner":
		script, scriptArgs = consoleEntryPointScript, append([]string{"skill-scanner"}, args[1:]...)
	case "plugin-scan":
		script, scriptArgs = pluginScanScript, args[1:]
	case "mcp-scan":
		script, scriptArgs = mcpScanScript, args[1:]
	default:
		fmt.Fprintf(stderr, "defenseclaw-scanners: unknown tool %q\n", args[0])
		return 2
	}
	dir, err := ensureRuntime(manifest)
	if err != nil {
		fmt.Fprintf(stderr, "defenseclaw-scanners: %v\n", err)
		return 1
	}
	pythonDir := filepath.Join(dir, "python")
	// -B: the gateway runs the runtime read-only; prepare compiled it.
	cmd := exec.Command(filepath.Join(pythonDir, "python.exe"), append([]string{"-I", "-B", "-c", script}, scriptArgs...)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Env = pythonEnv(os.Environ(), pythonDir)
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		fmt.Fprintf(stderr, "defenseclaw-scanners: run %s: %v\n", args[0], err)
		return 1
	}
	return 0
}

// compileRuntime byte-compiles the unpacked runtime so the read-only scans
// start fast. A file that does not compile only costs its own speed-up.
func compileRuntime(dir string, stderr io.Writer) {
	pythonDir := filepath.Join(dir, "python")
	cmd := exec.Command(filepath.Join(pythonDir, "python.exe"), "-I", "-m", "compileall", "-q", "-j", "0",
		filepath.Join(pythonDir, "Lib", "site-packages"))
	cmd.Env = pythonEnv(os.Environ(), pythonDir)
	if out, err := cmd.CombinedOutput(); err != nil && len(out) > 0 {
		fmt.Fprintf(stderr, "defenseclaw-scanners: compile: %d bytes of warnings\n", len(out))
	}
}

func loadManifest() (runtimeManifest, error) {
	var manifest runtimeManifest
	raw, err := payload.ReadFile(runtimeManifestName)
	if err != nil {
		return manifest, errors.New("this build carries no scanner runtime (build it with packaging/windows/standalone/build-setup.sh)")
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return manifest, fmt.Errorf("scanner runtime manifest: %w", err)
	}
	if manifest.SchemaVersion != 1 || len(manifest.SHA256) != 64 {
		return manifest, errors.New("scanner runtime manifest is not schema 1 with a SHA-256")
	}
	return manifest, nil
}

// versionLine is what --version prints: every pinned component, so a
// changed runtime changes the scanners' cache key.
func versionLine(manifest runtimeManifest) string {
	names := make([]string, 0, len(manifest.Versions))
	for name := range manifest.Versions {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := []string{"defenseclaw-scanners"}
	for _, name := range names {
		parts = append(parts, name+" "+manifest.Versions[name])
	}
	return strings.Join(parts, " ") + " runtime " + manifest.SHA256[:12]
}

// pythonEnv is the caller's environment (the gateway already reduced it to
// the scanner allowlist) with the runtime first on PATH and no PYTHONHOME or
// PYTHONPATH.
func pythonEnv(base []string, pythonDir string) []string {
	env := make([]string, 0, len(base)+1)
	sawPath := false
	for _, entry := range base {
		name, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		switch strings.ToUpper(name) {
		case "PYTHONHOME", "PYTHONPATH":
			continue
		case "PATH":
			sawPath = true
			if value != "" {
				value = string(os.PathListSeparator) + value
			}
			env = append(env, "PATH="+pythonDir+value)
		default:
			env = append(env, entry)
		}
	}
	if !sawPath {
		env = append(env, "PATH="+pythonDir)
	}
	return env
}

// ensureRuntime returns the unpacked runtime folder, unpacking the embedded
// archive on first use. A folder is used only once its completion marker
// names the archive's SHA-256; a partial unpack is never renamed into place.
func ensureRuntime(manifest runtimeManifest) (string, error) {
	root, err := runtimeRoot()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(root, manifest.SHA256[:16])
	if runtimeComplete(dir, manifest.SHA256) {
		return dir, nil
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return "", fmt.Errorf("create scanner runtime root: %w", err)
	}
	if info, err := os.Lstat(root); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("scanner runtime root %s is not a plain folder", root)
	}
	archive, err := payload.ReadFile(runtimeArchiveName)
	if err != nil {
		return "", errors.New("this build carries no scanner runtime archive")
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return "", err
	}
	staging := filepath.Join(root, ".unpack-"+hex.EncodeToString(suffix))
	if err := unpack(archive, staging); err != nil {
		_ = os.RemoveAll(staging)
		return "", err
	}
	if err := os.WriteFile(filepath.Join(staging, completeMarker), []byte(manifest.SHA256), 0o644); err != nil {
		_ = os.RemoveAll(staging)
		return "", err
	}
	if err := os.Rename(staging, dir); err != nil {
		_ = os.RemoveAll(staging)
		if runtimeComplete(dir, manifest.SHA256) {
			return dir, nil // another scan unpacked it first
		}
		return "", fmt.Errorf("publish scanner runtime: %w", err)
	}
	return dir, nil
}

// prepareRuntime is ensureRuntime plus a check that the unpacked tree is the
// embedded archive. The completion marker names a public SHA-256, so a folder
// somebody else created could carry it: prepare, which runs elevated and
// executes the folder's python.exe, never trusts the marker alone. A tree that
// differs is removed and unpacked again.
func prepareRuntime(manifest runtimeManifest) (string, error) {
	dir, err := ensureRuntime(manifest)
	if err != nil {
		return "", err
	}
	archive, err := payload.ReadFile(runtimeArchiveName)
	if err != nil {
		return "", errors.New("this build carries no scanner runtime archive")
	}
	if verifyRuntime(dir, archive) == nil {
		return dir, nil
	}
	if err := os.RemoveAll(dir); err != nil {
		return "", fmt.Errorf("remove the scanner runtime that does not match this build: %w", err)
	}
	if dir, err = ensureRuntime(manifest); err != nil {
		return "", err
	}
	if err := verifyRuntime(dir, archive); err != nil {
		return "", fmt.Errorf("the unpacked scanner runtime does not match this build: %w", err)
	}
	return dir, nil
}

// verifyRuntime checks that every file of archive exists under dir as a
// regular file with the archived size and SHA-256. Files prepare adds (the
// byte-compiled caches) are not in the archive and are not checked.
func verifyRuntime(dir string, archive []byte) error {
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return err
	}
	for _, file := range reader.File {
		if file.FileInfo().IsDir() {
			continue
		}
		path := filepath.Join(dir, filepath.FromSlash(file.Name))
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || uint64(info.Size()) != file.UncompressedSize64 {
			return fmt.Errorf("%s is missing or changed", file.Name)
		}
		want, err := entrySHA256(file)
		if err != nil {
			return err
		}
		if got, err := fileSHA256(path); err != nil || got != want {
			return fmt.Errorf("%s is missing or changed", file.Name)
		}
	}
	return nil
}

func entrySHA256(file *zip.File) ([sha256.Size]byte, error) {
	in, err := file.Open()
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	defer in.Close()
	return readerSHA256(in)
}

func fileSHA256(path string) ([sha256.Size]byte, error) {
	in, err := os.Open(path)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	defer in.Close()
	return readerSHA256(in)
}

func readerSHA256(r io.Reader) ([sha256.Size]byte, error) {
	var sum [sha256.Size]byte
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return sum, err
	}
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

func runtimeComplete(dir, sha string) bool {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	marker, err := os.ReadFile(filepath.Join(dir, completeMarker))
	return err == nil && strings.TrimSpace(string(marker)) == sha
}

// pruneOtherRuntimes removes runtimes an earlier build unpacked. Failures
// (a scan still running from one) are left for the next upgrade.
func pruneOtherRuntimes(root, keep string) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.Name() == keep || !entry.IsDir() {
			continue
		}
		_ = os.RemoveAll(filepath.Join(root, entry.Name()))
	}
}

// unpack expands archive into dest, refusing absolute paths, parent
// references, links and an expanded size above maxRuntimeBytes.
func unpack(archive []byte, dest string) error {
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return fmt.Errorf("open scanner runtime archive: %w", err)
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	var total uint64
	for _, file := range reader.File {
		name := filepath.FromSlash(file.Name)
		if name == "" || filepath.IsAbs(name) || filepath.VolumeName(name) != "" ||
			strings.Contains(file.Name, `\`) || !fs.ValidPath(strings.TrimSuffix(file.Name, "/")) {
			return fmt.Errorf("scanner runtime archive entry %q is not a relative path", file.Name)
		}
		mode := file.Mode()
		if mode&os.ModeSymlink != 0 || (!mode.IsDir() && !mode.IsRegular()) {
			return fmt.Errorf("scanner runtime archive entry %q is not a file or folder", file.Name)
		}
		target := filepath.Join(dest, name)
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		total += file.UncompressedSize64
		if total > maxRuntimeBytes {
			return errors.New("scanner runtime archive expands beyond its bound")
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := writeEntry(file, target); err != nil {
			return err
		}
	}
	return nil
}

func writeEntry(file *zip.File, target string) error {
	in, err := file.Open()
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	written, copyErr := io.Copy(out, io.LimitReader(in, int64(file.UncompressedSize64)+1))
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if uint64(written) != file.UncompressedSize64 {
		return fmt.Errorf("scanner runtime archive entry %q has the wrong size", file.Name)
	}
	return nil
}
