// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package openshell

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// Discovery errors. Callers match them with errors.Is; the returned errors
// carry the offending path or name.
var (
	// ErrNoGateway means no gateway registration exists: OpenShell is not
	// installed, or its gateway was never registered with the CLI.
	ErrNoGateway = errors.New("openshell: no gateway registration found")
	// ErrGatewayNotFound means the chosen gateway has no registration: a
	// pinned name without one, or a directory without metadata.json.
	ErrGatewayNotFound = errors.New("openshell: gateway registration not found")
	// ErrRemoteGateway means the registration points at a remote gateway,
	// which DefenseClaw does not drive.
	ErrRemoteGateway = errors.New("openshell: remote gateways are not supported")
	// ErrUnsupportedAuthMode means the registration uses an auth mode other
	// than mTLS (OIDC, Cloudflare JWT, or one this release does not know).
	ErrUnsupportedAuthMode = errors.New("openshell: unsupported gateway auth mode")
	// ErrUnauthenticatedGateway means the registration reaches the gateway
	// without a client certificate (auth mode plaintext or none). Anyone
	// who can reach such a gateway's port can drive its sandboxes and the
	// credentials DefenseClaw hands them, and on the docker driver create
	// sandboxes with host bind mounts through its root Docker daemon, so
	// DefenseClaw drives only mTLS gateways.
	ErrUnauthenticatedGateway = errors.New("openshell: gateway accepts unauthenticated calls")
	// ErrInsecureCredentials means the mTLS material is readable or
	// writable by other users, or is not a plain file owned by the caller.
	ErrInsecureCredentials = errors.New("openshell: gateway mTLS credentials are not private")
	// ErrInsecureRegistration means another user could change the
	// registration itself (the config directory, gateways/<name>,
	// metadata.json or active_gateway) and so choose the endpoint that
	// DefenseClaw sends provider credentials to.
	ErrInsecureRegistration = errors.New("openshell: gateway registration is not private")
	// ErrUnsupportedPlatform means OpenShell sandboxes are not available on
	// this operating system.
	ErrUnsupportedPlatform = errors.New("openshell: sandboxes are supported on Linux and macOS only")
)

// AuthMode is the gateway auth mode recorded in metadata.json.
type AuthMode string

// Auth modes the upstream CLI writes. DefenseClaw drives only mtls, the
// package-managed local gateway's mode.
const (
	AuthModeMTLS          AuthMode = "mtls"
	AuthModePlaintext     AuthMode = "plaintext"
	AuthModeNone          AuthMode = "none"
	AuthModeOIDC          AuthMode = "oidc"
	AuthModeCloudflareJWT AuthMode = "cloudflare_jwt"
)

// RegistrationSource says where a registration was found.
type RegistrationSource string

// Registration sources, in lookup order.
const (
	SourceUser   RegistrationSource = "user"
	SourceSystem RegistrationSource = "system"
)

// TLSFiles are the client mTLS files of a registration.
type TLSFiles struct {
	CA   string `json:"ca"`
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

// Registration is the openshell CLI's record of one gateway
// (gateways/<name>/metadata.json plus its mtls directory).
type Registration struct {
	Name     string             `json:"name"`
	Endpoint string             `json:"endpoint"`
	AuthMode AuthMode           `json:"auth_mode"`
	Remote   bool               `json:"remote"`
	Dir      string             `json:"dir"`
	Source   RegistrationSource `json:"source"`
	// TLS is set for mtls registrations.
	TLS *TLSFiles `json:"tls,omitempty"`
	// ActiveGatewayFile is the active_gateway file that selected this
	// registration (empty when the name was pinned or defaulted).
	ActiveGatewayFile string `json:"active_gateway_file,omitempty"`
	// Warnings are non-fatal findings (e.g. group-writable certificates or
	// metadata) that doctor surfaces.
	Warnings []string `json:"warnings,omitempty"`
}

// Local reports whether the registration is a loopback gateway.
func (r *Registration) Local() bool { return r != nil && !r.Remote }

// Target returns the gRPC dial target (host:port without a scheme).
func (r *Registration) Target() string {
	u, err := url.Parse(r.Endpoint)
	if err != nil || u.Host == "" {
		return strings.TrimPrefix(strings.TrimPrefix(r.Endpoint, "https://"), "http://")
	}
	return u.Host
}

// DiscoverOptions selects and locates a registration.
type DiscoverOptions struct {
	// ConfigDir overrides the OpenShell user config directory
	// ($XDG_CONFIG_HOME/openshell, else ~/.config/openshell).
	ConfigDir string
	// SystemDir overrides the system config directory (/etc/openshell).
	SystemDir string
	// Gateway pins a registration by name. When empty the CLI's
	// active_gateway is used, then the package default "openshell", then
	// the only registration if exactly one exists.
	Gateway string
}

// metadata is the on-disk metadata.json. Unknown keys are ignored.
type metadata struct {
	Name     string `json:"name"`
	Endpoint string `json:"gateway_endpoint"`
	IsRemote bool   `json:"is_remote"`
	Port     int    `json:"gateway_port"`
	AuthMode string `json:"auth_mode"`
}

const (
	gatewaysSubdir    = "gateways"
	activeGatewayFile = "active_gateway"
	metadataFile      = "metadata.json"
	mtlsSubdir        = "mtls"
	defaultSystemDir  = "/etc/openshell"
	maxMetadataBytes  = 64 << 10
	maxActiveBytes    = 4 << 10
)

// UserConfigDir returns the OpenShell user config directory, following the
// same XDG rules as the upstream CLI.
func UserConfigDir() (string, error) {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		if !filepath.IsAbs(xdg) {
			return "", fmt.Errorf("openshell: XDG_CONFIG_HOME must be absolute, got %q", xdg)
		}
		return filepath.Join(xdg, "openshell"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("openshell: resolve home directory: %w", err)
	}
	return filepath.Join(home, ".config", "openshell"), nil
}

// resolveConfigDir returns dir, made absolute, with its symbolic links
// resolved: a dotfile manager may link ~/.config/openshell elsewhere.
// Every file below it is then read and written through the real
// directory, which safefile requires (it refuses a file whose parent is a
// link), and one resolution keeps an operation on one directory even if
// the link changes. When dir does not exist yet, its deepest existing
// ancestor is resolved, so the result stays the same once it is created.
func resolveConfigDir(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("openshell: config directory %q: %w", dir, err)
	}
	missing := ""
	for p := abs; ; {
		real, err := filepath.EvalSymlinks(p)
		if err == nil {
			return filepath.Join(real, missing), nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("openshell: resolve config directory %s: %w", abs, err)
		}
		parent := filepath.Dir(p)
		if parent == p {
			return abs, nil
		}
		missing = filepath.Join(filepath.Base(p), missing)
		p = parent
	}
}

// CheckPlatform returns ErrUnsupportedPlatform for operating systems
// OpenShell sandboxes do not run on.
func CheckPlatform(goos string) error {
	switch goos {
	case "linux", "darwin":
		return nil
	default:
		return fmt.Errorf("%w (running on %s)", ErrUnsupportedPlatform, goos)
	}
}

// CheckHost is CheckPlatform for a machine: it also refuses a Mac that is
// not Apple silicon, where OpenShell's MicroVM driver, which a Mac runs
// sandboxes with, does not run. An Intel build of DefenseClaw that
// Rosetta runs on Apple silicon is told to install the arm64 build.
func CheckHost(goos, goarch string) error {
	if err := CheckPlatform(goos); err != nil {
		return err
	}
	if goos == "darwin" && goarch != "arm64" {
		if translated(goos, goarch) {
			return fmt.Errorf("%w (this is the Intel build of DefenseClaw running under Rosetta on Apple silicon: install the arm64 build)", ErrUnsupportedPlatform)
		}
		return fmt.Errorf("%w (on a Mac, Apple silicon only: OpenShell's MicroVM driver does not run on %s/%s)", ErrUnsupportedPlatform, goos, goarch)
	}
	return nil
}

// processTranslated reports whether goos/goarch is this process running
// under Rosetta (tests replace it).
var processTranslated = func(goos, goarch string) bool {
	return goos == runtime.GOOS && goarch == runtime.GOARCH && rosetta()
}

// translated reports an Intel macOS build running on Apple silicon.
func translated(goos, goarch string) bool {
	return goos == "darwin" && goarch == "amd64" && processTranslated(goos, goarch)
}

// Discover resolves a gateway registration and validates it for use by
// DefenseClaw: its files must be the caller's (CheckRegistrationFiles),
// the gateway must be local and use mtls, and its private key must be
// owner-only. A symlinked config directory is followed; the registration's
// paths are built from the directory it resolves to.
//
// When the registration exists but is unusable, Discover returns it
// together with the error, so doctor can report what it found.
func Discover(opts DiscoverOptions) (*Registration, error) {
	if err := CheckHost(runtime.GOOS, runtime.GOARCH); err != nil {
		return nil, err
	}
	userDir := opts.ConfigDir
	if userDir == "" {
		dir, err := UserConfigDir()
		if err != nil {
			return nil, err
		}
		userDir = dir
	}
	systemDir := opts.SystemDir
	if systemDir == "" {
		systemDir = defaultSystemDir
	}
	userDir, err := resolveConfigDir(userDir)
	if err != nil {
		return nil, err
	}
	if systemDir, err = resolveConfigDir(systemDir); err != nil {
		return nil, err
	}

	name, activeFile, err := selectGateway(userDir, systemDir, opts.Gateway)
	if err != nil {
		return nil, err
	}
	dir, source, err := findRegistration(userDir, systemDir, name)
	if err != nil {
		return nil, err
	}
	reg, err := loadRegistration(dir, name, source)
	if reg != nil {
		reg.ActiveGatewayFile = activeFile
	}
	if err != nil {
		return reg, err
	}
	return reg, validateRegistration(reg)
}

// ValidGatewayName reports whether name is safe to use as a registration
// directory name and as a CLI flag value: ASCII letters, digits, '-' and
// '_', starting with a letter or digit.
func ValidGatewayName(name string) bool {
	if name == "" || len(name) > 128 || name[0] == '-' || name[0] == '_' {
		return false
	}
	for _, r := range name {
		ok := r == '-' || r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if !ok {
			return false
		}
	}
	return true
}

// selectGateway returns the registration name and, when active_gateway
// chose it, that file's path.
func selectGateway(userDir, systemDir, pinned string) (string, string, error) {
	if pinned != "" {
		if !ValidGatewayName(pinned) {
			return "", "", fmt.Errorf("openshell: invalid gateway name %q", pinned)
		}
		return pinned, "", nil
	}
	active := filepath.Join(userDir, activeGatewayFile)
	name, err := readActiveGateway(active)
	if err != nil {
		return "", "", err
	}
	if name != "" {
		return name, active, nil
	}
	names := listRegistrations(userDir, systemDir)
	for _, n := range names {
		if n == DefaultGatewayName {
			return n, "", nil
		}
	}
	if len(names) == 1 {
		return names[0], "", nil
	}
	if len(names) > 1 {
		return "", "", fmt.Errorf("%w: several gateways are registered (%s) and none is active; pin one with openshell.gateway.name", ErrNoGateway, strings.Join(names, ", "))
	}
	return "", "", fmt.Errorf("%w under %s (is OpenShell installed?)", ErrNoGateway, userDir)
}

// readActiveGateway returns the gateway the CLI's active_gateway file
// names, or "" when there is no such file or it is empty. Any other
// problem is an error: ignoring an unreadable file would drive a
// different gateway than the operator's CLI does.
func readActiveGateway(path string) (string, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("openshell: %s: %w", path, err)
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return "", &PermissionError{Path: path, Mode: info.Mode(), Reason: "is a symbolic link", Kind: ErrInsecureRegistration}
	}
	data, err := safefile.ReadRegularFileBounded(path, maxActiveBytes)
	if err != nil {
		return "", fmt.Errorf("openshell: read %s: %w", path, err)
	}
	name := strings.TrimSpace(string(data))
	if name != "" && !ValidGatewayName(name) {
		return "", fmt.Errorf("openshell: %s names an invalid gateway %q", path, name)
	}
	return name, nil
}

func listRegistrations(dirs ...string) []string {
	seen := map[string]bool{}
	var names []string
	for _, base := range dirs {
		entries, err := os.ReadDir(filepath.Join(base, gatewaysSubdir))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() && ValidGatewayName(e.Name()) && !seen[e.Name()] {
				seen[e.Name()] = true
				names = append(names, e.Name())
			}
		}
	}
	sort.Strings(names)
	return names
}

func findRegistration(userDir, systemDir, name string) (string, RegistrationSource, error) {
	for _, c := range []struct {
		base   string
		source RegistrationSource
	}{{userDir, SourceUser}, {systemDir, SourceSystem}} {
		dir := filepath.Join(c.base, gatewaysSubdir, name)
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			return dir, c.source, nil
		}
	}
	return "", "", fmt.Errorf("%w: %q", ErrGatewayNotFound, name)
}

func loadRegistration(dir, name string, source RegistrationSource) (*Registration, error) {
	path := filepath.Join(dir, metadataFile)
	data, err := safefile.ReadRegularFileBounded(path, maxMetadataBytes)
	if errors.Is(err, fs.ErrNotExist) {
		// A gateway that has started writes its client certificates here
		// before anything registers it.
		return nil, fmt.Errorf("%w: %q has no %s in %s", ErrGatewayNotFound, name, metadataFile, dir)
	}
	if err != nil {
		return nil, fmt.Errorf("openshell: read %s: %w", path, err)
	}
	var meta metadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("openshell: parse %s: %w", path, err)
	}
	if meta.Endpoint == "" {
		return nil, fmt.Errorf("openshell: %s has no gateway_endpoint", path)
	}
	mode := AuthMode(meta.AuthMode)
	if mode == "" {
		mode = AuthModeNone
	}
	reg := &Registration{
		Name:     name,
		Endpoint: meta.Endpoint,
		AuthMode: mode,
		Dir:      dir,
		Source:   source,
		Remote:   meta.IsRemote,
	}
	u, err := url.Parse(meta.Endpoint)
	if err != nil || u.Hostname() == "" {
		return reg, fmt.Errorf("openshell: %s has an invalid gateway_endpoint %q", path, meta.Endpoint)
	}
	if !isLoopbackHost(u.Hostname()) {
		reg.Remote = true
	}
	if mode == AuthModeMTLS {
		mtls := filepath.Join(dir, mtlsSubdir)
		reg.TLS = &TLSFiles{
			CA:   filepath.Join(mtls, "ca.crt"),
			Cert: filepath.Join(mtls, "tls.crt"),
			Key:  filepath.Join(mtls, "tls.key"),
		}
	}
	return reg, nil
}

func validateRegistration(reg *Registration) error {
	warnings, err := CheckRegistrationFiles(reg)
	reg.Warnings = append(reg.Warnings, warnings...)
	if err != nil {
		return err
	}
	if reg.Remote {
		return fmt.Errorf("%w: %s points at %s; DefenseClaw drives only the local gateway", ErrRemoteGateway, reg.Name, reg.Endpoint)
	}
	u, _ := url.Parse(reg.Endpoint)
	switch reg.AuthMode {
	case AuthModeMTLS:
		if u.Scheme != "https" {
			return fmt.Errorf("%w: mtls registration %s uses %s", ErrUnsupportedAuthMode, reg.Name, reg.Endpoint)
		}
		warnings, err := CheckTLSFiles(reg.TLS)
		reg.Warnings = append(reg.Warnings, warnings...)
		return err
	case AuthModePlaintext, AuthModeNone:
		return unauthenticatedError(reg)
	default:
		return fmt.Errorf("%w: %s uses %q", ErrUnsupportedAuthMode, reg.Name, reg.AuthMode)
	}
}

func unauthenticatedError(reg *Registration) error {
	return fmt.Errorf("%w: registration %s reaches %s with auth mode %s, so any local user could create sandboxes with host bind mounts through it; DefenseClaw drives only mTLS gateways",
		ErrUnauthenticatedGateway, reg.Name, reg.Endpoint, reg.AuthMode)
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// PermissionError reports gateway credentials or registration files that
// other users could read or replace.
type PermissionError struct {
	Path   string
	Mode   fs.FileMode
	Reason string
	// Fix is a shell command that repairs the problem, when one exists.
	Fix string
	// FixMode is the mode Fix sets (zero when there is no mode fix).
	FixMode fs.FileMode
	// Kind is ErrInsecureCredentials (the default) or
	// ErrInsecureRegistration.
	Kind error
}

func (e *PermissionError) Error() string {
	return fmt.Sprintf("openshell: %s: %s (mode %04o)", e.Path, e.Reason, e.Mode.Perm())
}

// Unwrap lets errors.Is(err, ErrInsecureCredentials) or
// errors.Is(err, ErrInsecureRegistration) match.
func (e *PermissionError) Unwrap() error {
	if e.Kind != nil {
		return e.Kind
	}
	return ErrInsecureCredentials
}

// modeWarning is a group-writable registration entry.
type modeWarning struct {
	path string
	mode fs.FileMode
	// fixMode drops group and other write access; zero when the entry
	// belongs to root and the caller cannot change it.
	fixMode fs.FileMode
}

func (w modeWarning) String() string {
	fix := "chmod go-w " + shellQuote(w.path)
	if w.fixMode == 0 {
		fix = "sudo " + fix
	}
	return fmt.Sprintf("%s is group-writable (mode %04o); run %s", w.path, w.mode.Perm(), fix)
}

// CheckRegistrationFiles validates the entries a registration is read
// from: the OpenShell config directory, gateways/, gateways/<name>/,
// metadata.json and, when it chose the gateway, active_gateway (and its
// directory). Whoever can change them picks the endpoint and trust anchor
// DefenseClaw uses, so each must belong to the caller (or root, for the
// system directory), must not be writable by every user, and, below the
// config directory, must not be a symlink. A group-writable entry (the
// 0.1.1 CLI writes its files 0664 under umask 002) only warns, and only
// when group members can reach it: inside the CLI's own 0700 directories
// they cannot.
func CheckRegistrationFiles(reg *Registration) ([]string, error) {
	warnings, err := registrationIssues(reg)
	out := make([]string, len(warnings))
	for i, w := range warnings {
		out[i] = w.String()
	}
	return out, err
}

func registrationIssues(reg *Registration) ([]modeWarning, error) {
	if reg == nil || reg.Dir == "" {
		return nil, fmt.Errorf("%w: registration has no directory", ErrInsecureRegistration)
	}
	type entry struct {
		path string
		dir  bool
		// follow permits a symlinked config directory (dotfile managers).
		follow bool
	}
	// Each chain runs from a config directory down to a file, so a
	// directory without group search access shields what lies below it.
	gateways := filepath.Dir(reg.Dir)
	chains := [][]entry{{
		{filepath.Dir(gateways), true, true},
		{gateways, true, false},
		{reg.Dir, true, false},
		{filepath.Join(reg.Dir, metadataFile), false, false},
	}}
	if reg.ActiveGatewayFile != "" {
		// A user's active_gateway can name a system registration.
		chains = append(chains, []entry{{filepath.Dir(reg.ActiveGatewayFile), true, true}, {reg.ActiveGatewayFile, false, false}})
	}
	var warnings []modeWarning
	checked := map[string]fs.FileMode{}
	for _, chain := range chains {
		groupReach := true
		for _, e := range chain {
			mode, seen := checked[e.path]
			if !seen {
				var err error
				if mode, err = checkRegistrationEntry(e.path, e.dir, e.follow, groupReach, &warnings); err != nil {
					return warnings, err
				}
				checked[e.path] = mode
			}
			if e.dir && mode.Perm()&0o010 == 0 {
				groupReach = false
			}
		}
	}
	return warnings, nil
}

// checkRegistrationEntry refuses an entry another user could replace and
// records a warning for a group-writable one that group members reach.
func checkRegistrationEntry(path string, dir, follow, groupReach bool, warnings *[]modeWarning) (fs.FileMode, error) {
	stat := os.Lstat
	if follow {
		stat = os.Stat
	}
	info, err := stat(path)
	if err != nil {
		return 0, fmt.Errorf("openshell: gateway registration: %w", err)
	}
	mode := info.Mode()
	refuse := func(reason, fix string, fixMode fs.FileMode) error {
		return &PermissionError{Path: path, Mode: mode, Reason: reason, Fix: fix, FixMode: fixMode, Kind: ErrInsecureRegistration}
	}
	fixMode, fix := mode.Perm()&^0o022, "chmod go-w "+shellQuote(path)
	if !ownedByCaller(info) {
		fixMode, fix = 0, "sudo "+fix
	}
	switch {
	case mode&fs.ModeSymlink != 0:
		return mode, refuse("is a symbolic link", "", 0)
	case dir && !mode.IsDir():
		return mode, refuse("is not a directory", "", 0)
	case !dir && !mode.IsRegular():
		return mode, refuse("is not a regular file", "", 0)
	case !ownedByCallerOrRoot(info):
		return mode, refuse("is owned by another user", "", 0)
	case mode.Perm()&0o002 != 0:
		return mode, refuse("is writable by every user", fix, fixMode)
	case mode.Perm()&0o020 != 0 && groupReach:
		*warnings = append(*warnings, modeWarning{path: path, mode: mode, fixMode: fixMode})
	}
	return mode, nil
}

// CheckTLSFiles validates mTLS material. The private key must be a regular
// file owned by the caller with no group or other access. The CA and
// client certificate are public, so group-writable modes (the 0.1.1 CLI
// writes them 0664) only warn; world-writable ones, symlinks and foreign
// owners are refused because they would let another user swap the trust
// anchor.
func CheckTLSFiles(files *TLSFiles) ([]string, error) {
	if files == nil {
		return nil, fmt.Errorf("%w: mtls registration has no credential files", ErrInsecureCredentials)
	}
	var warnings []string
	dir := filepath.Dir(files.Key)
	dinfo, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("openshell: mtls directory: %w", err)
	}
	if !dinfo.IsDir() {
		return nil, &PermissionError{Path: dir, Mode: dinfo.Mode(), Reason: "is not a directory"}
	}
	if dinfo.Mode().Perm()&0o002 != 0 && dinfo.Mode()&fs.ModeSticky == 0 {
		return nil, &PermissionError{Path: dir, Mode: dinfo.Mode(), Reason: "is writable by every user", Fix: "chmod 700 " + shellQuote(dir), FixMode: 0o700}
	}
	if dinfo.Mode().Perm()&0o020 != 0 {
		warnings = append(warnings, fmt.Sprintf("%s is group-writable (mode %04o); run chmod 700 %s", dir, dinfo.Mode().Perm(), shellQuote(dir)))
	}

	key, err := os.Lstat(files.Key)
	if err != nil {
		return warnings, fmt.Errorf("openshell: mtls key: %w", err)
	}
	if !key.Mode().IsRegular() {
		return warnings, &PermissionError{Path: files.Key, Mode: key.Mode(), Reason: "is not a regular file"}
	}
	if key.Mode().Perm()&0o077 != 0 {
		return warnings, &PermissionError{Path: files.Key, Mode: key.Mode(), Reason: "private key is accessible to other users", Fix: "chmod 600 " + shellQuote(files.Key), FixMode: 0o600}
	}
	if !ownedByCaller(key) {
		return warnings, &PermissionError{Path: files.Key, Mode: key.Mode(), Reason: "private key is owned by another user"}
	}

	for _, path := range []string{files.CA, files.Cert} {
		info, err := os.Lstat(path)
		if err != nil {
			return warnings, fmt.Errorf("openshell: mtls certificate: %w", err)
		}
		if !info.Mode().IsRegular() {
			return warnings, &PermissionError{Path: path, Mode: info.Mode(), Reason: "is not a regular file"}
		}
		if info.Mode().Perm()&0o002 != 0 {
			return warnings, &PermissionError{Path: path, Mode: info.Mode(), Reason: "certificate is writable by every user", Fix: "chmod 644 " + shellQuote(path), FixMode: 0o644}
		}
		if !ownedByCaller(info) {
			return warnings, &PermissionError{Path: path, Mode: info.Mode(), Reason: "certificate is owned by another user"}
		}
		if info.Mode().Perm()&0o020 != 0 {
			warnings = append(warnings, fmt.Sprintf("%s is group-writable (mode %04o); run chmod 644 %s", path, info.Mode().Perm(), shellQuote(path)))
		}
	}
	return warnings, nil
}

// shellQuote quotes a path for a copy-pasteable fix command.
func shellQuote(s string) string {
	if s != "" && strings.IndexFunc(s, func(r rune) bool {
		return !(r == '/' || r == '.' || r == '-' || r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'))
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
