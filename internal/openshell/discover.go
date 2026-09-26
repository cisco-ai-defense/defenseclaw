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
	// ErrGatewayNotFound means a pinned gateway name has no registration.
	ErrGatewayNotFound = errors.New("openshell: gateway registration not found")
	// ErrRemoteGateway means the registration points at a remote gateway,
	// which DefenseClaw does not drive.
	ErrRemoteGateway = errors.New("openshell: remote gateways are not supported")
	// ErrUnsupportedAuthMode means the registration uses an auth mode other
	// than local mTLS or loopback plaintext.
	ErrUnsupportedAuthMode = errors.New("openshell: unsupported gateway auth mode")
	// ErrInsecureCredentials means the mTLS material is readable or
	// writable by other users, or is not a plain file owned by the caller.
	ErrInsecureCredentials = errors.New("openshell: gateway mTLS credentials are not private")
	// ErrUnsupportedPlatform means OpenShell sandboxes are not available on
	// this operating system.
	ErrUnsupportedPlatform = errors.New("openshell: sandboxes are supported on Linux and macOS only")
)

// AuthMode is the gateway auth mode recorded in metadata.json.
type AuthMode string

// Auth modes the upstream CLI writes. DefenseClaw drives mtls (the
// package-managed local gateway) and loopback plaintext.
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
	// Warnings are non-fatal findings (e.g. group-writable certificates)
	// that doctor surfaces.
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

// Discover resolves a gateway registration and validates it for use by
// DefenseClaw: the gateway must be local, use mtls or loopback plaintext,
// and keep its private key owner-only.
//
// When the registration exists but is unusable, Discover returns it
// together with the error, so doctor can report what it found.
func Discover(opts DiscoverOptions) (*Registration, error) {
	if err := CheckPlatform(runtime.GOOS); err != nil {
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

	name, err := selectGateway(userDir, systemDir, opts.Gateway)
	if err != nil {
		return nil, err
	}
	dir, source, err := findRegistration(userDir, systemDir, name)
	if err != nil {
		return nil, err
	}
	reg, err := loadRegistration(dir, name, source)
	if err != nil {
		return reg, err
	}
	return reg, validateRegistration(reg)
}

// ValidGatewayName reports whether name is safe to use as a registration
// directory name (ASCII letters, digits, '-' and '_').
func ValidGatewayName(name string) bool {
	if name == "" || len(name) > 128 {
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

func selectGateway(userDir, systemDir, pinned string) (string, error) {
	if pinned != "" {
		if !ValidGatewayName(pinned) {
			return "", fmt.Errorf("openshell: invalid gateway name %q", pinned)
		}
		return pinned, nil
	}
	if data, err := safefile.ReadRegularFileBounded(filepath.Join(userDir, activeGatewayFile), 4096); err == nil {
		if name := strings.TrimSpace(string(data)); name != "" {
			if !ValidGatewayName(name) {
				return "", fmt.Errorf("openshell: %s names an invalid gateway %q", filepath.Join(userDir, activeGatewayFile), name)
			}
			return name, nil
		}
	}
	names := listRegistrations(userDir, systemDir)
	for _, n := range names {
		if n == DefaultGatewayName {
			return n, nil
		}
	}
	if len(names) == 1 {
		return names[0], nil
	}
	if len(names) > 1 {
		return "", fmt.Errorf("%w: several gateways are registered (%s) and none is active; pin one with openshell.gateway.name", ErrNoGateway, strings.Join(names, ", "))
	}
	return "", fmt.Errorf("%w under %s (is OpenShell installed?)", ErrNoGateway, userDir)
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
		if u.Scheme != "http" {
			return fmt.Errorf("%w: %s registration %s over %s", ErrUnsupportedAuthMode, reg.AuthMode, reg.Name, u.Scheme)
		}
		reg.Warnings = append(reg.Warnings, fmt.Sprintf("gateway %s accepts unauthenticated plaintext calls on %s; any local user can drive it", reg.Name, reg.Endpoint))
		return nil
	default:
		return fmt.Errorf("%w: %s uses %q", ErrUnsupportedAuthMode, reg.Name, reg.AuthMode)
	}
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// PermissionError reports mTLS material that other users could read or
// replace.
type PermissionError struct {
	Path   string
	Mode   fs.FileMode
	Reason string
	// Fix is a shell command that repairs the problem, when one exists.
	Fix string
}

func (e *PermissionError) Error() string {
	return fmt.Sprintf("openshell: %s: %s (mode %04o)", e.Path, e.Reason, e.Mode.Perm())
}

// Unwrap lets errors.Is(err, ErrInsecureCredentials) match.
func (e *PermissionError) Unwrap() error { return ErrInsecureCredentials }

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
		return nil, &PermissionError{Path: dir, Mode: dinfo.Mode(), Reason: "is writable by every user", Fix: "chmod 700 " + shellQuote(dir)}
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
		return warnings, &PermissionError{Path: files.Key, Mode: key.Mode(), Reason: "private key is accessible to other users", Fix: "chmod 600 " + shellQuote(files.Key)}
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
			return warnings, &PermissionError{Path: path, Mode: info.Mode(), Reason: "certificate is writable by every user", Fix: "chmod 644 " + shellQuote(path)}
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
