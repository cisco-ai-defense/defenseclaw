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

package sandboxfeed

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

// Installed locations. The feed is a root service, so it runs a root-owned
// copy of the helper, never the per-user install's file.
const (
	HelperName      = "defenseclaw-sensor-helper"
	InstallDir      = "/usr/local/libexec/defenseclaw"
	InstalledBinary = InstallDir + "/" + HelperName
	UnitName        = "defenseclaw-sandbox-feed.service"
	UnitPath        = "/etc/systemd/system/" + UnitName
)

// helperLimit bounds the helper binary copied (it is about 30 MB).
const helperLimit = 512 << 20

// UnitFile is the feed's systemd unit. The service needs CAP_CHOWN only (to
// give its socket the docker group); it reads Tetragon's and Docker's
// root-owned sockets and the world-readable /proc status of processes as
// uid 0, writes only its runtime directory, and has no network family but
// AF_UNIX.
func UnitFile() string {
	return `# DefenseClaw sandbox kernel feed: the exec and exit of the processes in
# OpenShell docker sandboxes, read from this host's Tetragon and streamed to
# the DefenseClaw gateway of each sandbox's owner. Written by
# "defenseclaw-gateway sandbox kernel-feed install" and removed by
# "defenseclaw-gateway sandbox kernel-feed uninstall"; do not edit.
#
# No MemoryDenyWriteExecute: the helper links bytedance/sonic, which maps
# executable memory at start on x86_64 (see the managed sensor helper unit).

[Unit]
Description=DefenseClaw sandbox kernel feed (Tetragon exec records for OpenShell sandboxes)
Documentation=https://cisco-ai-defense.github.io/defenseclaw/docs/sandboxes/
After=tetragon.service docker.service
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
Group=root
ExecStart=` + InstalledBinary + ` --sandbox-feed
Restart=always
RestartSec=5s
RuntimeDirectory=defenseclaw-sandbox-feed
RuntimeDirectoryMode=0750
WorkingDirectory=/
UMask=0007

NoNewPrivileges=true
CapabilityBoundingSet=CAP_CHOWN
PrivateTmp=true
PrivateDevices=true
ProtectHome=true
ProtectSystem=strict
ProtectClock=true
ProtectControlGroups=true
ProtectHostname=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
RemoveIPC=true
RestrictAddressFamilies=AF_UNIX
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@clock @cpu-emulation @module @mount @obsolete @raw-io @reboot @swap
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
`
}

// Lifecycle installs, removes and reports the feed service. Its fields are
// seams for tests; the zero value acts on the real host.
type Lifecycle struct {
	// Root prefixes every path written or removed ("" is /).
	Root string
	// Run runs a command and returns its combined output.
	Run func(ctx context.Context, name string, args ...string) (string, error)
	// Geteuid is the caller's effective uid.
	Geteuid func() int
	// Dial opens the feed (Dial) to read its header.
	Dial func(ctx context.Context, path string) (FeedHeader, error)
	// Wait bounds how long Install waits for the new service to answer.
	Wait time.Duration
}

func (l *Lifecycle) defaults() {
	if l.Run == nil {
		l.Run = func(ctx context.Context, name string, args ...string) (string, error) {
			out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
			return strings.TrimSpace(string(out)), err
		}
	}
	if l.Geteuid == nil {
		l.Geteuid = os.Geteuid
	}
	if l.Dial == nil {
		l.Dial = func(ctx context.Context, path string) (FeedHeader, error) {
			conn, err := Dial(ctx, path)
			if err != nil {
				return nil, err
			}
			return conn, nil
		}
	}
	if l.Wait <= 0 {
		l.Wait = 15 * time.Second
	}
}

func (l *Lifecycle) path(p string) string { return filepath.Join(l.Root, p) }

// FeedHeader is an open feed whose header was read (*Conn).
type FeedHeader interface {
	Header() Header
	Close() error
}

// InstallResult is what Install did.
type InstallResult struct {
	Version  string `json:"version"`
	Check    string `json:"check"`
	Updated  bool   `json:"updated"`
	Protocol int    `json:"protocol"`
	Tetragon string `json:"tetragon"`
}

// ErrNotRoot refuses an install or uninstall by anyone but root.
var ErrNotRoot = errors.New("the sandbox kernel feed is a root service: run this with sudo")

// versionPattern reads `defenseclaw-sensor-helper version X (commit=...)`.
var versionPattern = regexp.MustCompile(`version (\S+)`)

// Install copies helper (the defenseclaw-sensor-helper of this install) to
// InstalledBinary, checks the copy is the release wantVersion names (unless
// that is empty or dev) and that this host passes the feed's checks (it runs
// the copy's --sandbox-feed --check: a unix-socket Tetragon passing the
// trust checks, and Docker), then writes the unit and (re)starts the
// service. A check that fails leaves the previous install as it was.
func (l *Lifecycle) Install(ctx context.Context, helper, wantVersion string) (InstallResult, error) {
	l.defaults()
	if l.Geteuid() != 0 {
		return InstallResult{}, ErrNotRoot
	}
	data, err := readHelper(helper)
	if err != nil {
		return InstallResult{}, err
	}
	dir := l.path(InstallDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return InstallResult{}, err
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		return InstallResult{}, err
	}
	staged := filepath.Join(dir, "."+HelperName+".new")
	if err := writeFileSync(staged, data, 0o755); err != nil {
		return InstallResult{}, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(staged)
		}
	}()
	versionOut, err := l.Run(ctx, staged, "--version")
	if err != nil {
		return InstallResult{}, fmt.Errorf("the helper %s does not start: %v: %s", helper, err, versionOut)
	}
	version := ""
	if match := versionPattern.FindStringSubmatch(versionOut); match != nil {
		version = match[1]
	}
	if wantVersion != "" && wantVersion != "dev" && version != wantVersion {
		return InstallResult{}, fmt.Errorf("%s is version %q, not this gateway's %s; reinstall or upgrade DefenseClaw so both match", helper, version, wantVersion)
	}
	check, err := l.Run(ctx, staged, "--sandbox-feed", "--check")
	if err != nil {
		return InstallResult{}, fmt.Errorf("this host cannot run the sandbox kernel feed: %s", firstNonEmpty(check, err.Error()))
	}
	result := InstallResult{Version: version, Check: check}
	if _, err := os.Stat(l.path(InstalledBinary)); err == nil {
		result.Updated = true
	}
	if err := os.Rename(staged, l.path(InstalledBinary)); err != nil {
		return InstallResult{}, err
	}
	keep = true
	if err := writeIfChanged(l.path(UnitPath), []byte(UnitFile()), 0o644); err != nil {
		return InstallResult{}, err
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", UnitName}, {"restart", UnitName}} {
		if out, err := l.Run(ctx, "systemctl", args...); err != nil {
			return result, fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	// The service answers once it listens.
	deadline := time.Now().Add(l.Wait)
	for {
		conn, err := l.Dial(ctx, l.path(DefaultSocketPath))
		if err == nil {
			header := conn.Header()
			_ = conn.Close()
			result.Protocol, result.Tetragon = header.Protocol, firstNonEmpty(header.Tetragon, TetragonUnavailable)
			return result, nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return result, fmt.Errorf("the service is installed but does not answer on %s: %v (see journalctl -u %s)", DefaultSocketPath, err, UnitName)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// Uninstall stops and disables the service and removes what Install wrote.
// It is safe to run twice, and on a host where it was never installed.
func (l *Lifecycle) Uninstall(ctx context.Context) ([]string, error) {
	l.defaults()
	if l.Geteuid() != 0 {
		return nil, ErrNotRoot
	}
	var removed []string
	if _, err := os.Stat(l.path(UnitPath)); err == nil {
		// A unit systemd no longer knows answers an error here; the files
		// still go.
		_, _ = l.Run(ctx, "systemctl", "disable", "--now", UnitName)
	}
	for _, p := range []string{UnitPath, InstalledBinary, filepath.Join(InstallDir, "."+HelperName+".new")} {
		switch err := os.Remove(l.path(p)); {
		case err == nil:
			removed = append(removed, p)
		case !errors.Is(err, os.ErrNotExist):
			return removed, err
		}
	}
	_ = os.Remove(l.path(InstallDir)) // only when empty
	if len(removed) > 0 {
		if out, err := l.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return removed, fmt.Errorf("systemctl daemon-reload: %v: %s", err, out)
		}
	}
	return removed, nil
}

// Status is the feed as this host and this gateway see it.
type Status struct {
	Installed bool   `json:"installed"`
	Active    string `json:"active,omitempty"`
	Binary    string `json:"binary,omitempty"`
	Version   string `json:"version,omitempty"`
	// Reachable: this account opened the feed; Protocol and Build are its
	// header, Tetragon its stream's state.
	Reachable      bool   `json:"reachable"`
	Protocol       int    `json:"protocol,omitempty"`
	Build          string `json:"build,omitempty"`
	Tetragon       string `json:"tetragon,omitempty"`
	TetragonReason string `json:"tetragon_reason,omitempty"`
	// Reason is why it was not reachable (a Reason* code), Detail the error.
	Reason string `json:"reason,omitempty"`
	Detail string `json:"detail,omitempty"`
	// GatewayVersion and GatewayProtocol are this gateway's; UpdateNeeded
	// says the feed is older than the gateway or speaks a protocol it does
	// not read.
	GatewayVersion  string `json:"gateway_version"`
	GatewayProtocol int    `json:"gateway_protocol"`
	UpdateNeeded    bool   `json:"update_needed"`
}

// Status reports the feed. Anyone may ask; the stream is opened only to
// read its header.
func (l *Lifecycle) Status(ctx context.Context, gatewayVersion string) Status {
	l.defaults()
	out := Status{GatewayVersion: gatewayVersion, GatewayProtocol: ProtocolVersion}
	if _, err := os.Stat(l.path(UnitPath)); err == nil {
		out.Installed = true
		out.Binary = InstalledBinary
		active, _ := l.Run(ctx, "systemctl", "is-active", UnitName)
		out.Active = firstLine(active)
		if version, err := l.Run(ctx, l.path(InstalledBinary), "--version"); err == nil {
			if match := versionPattern.FindStringSubmatch(version); match != nil {
				out.Version = match[1]
			}
		}
	}
	conn, err := l.Dial(ctx, l.path(DefaultSocketPath))
	if err != nil {
		out.Reason, out.Detail = ReasonFor(err), err.Error()
		var skew *SkewError
		if errors.As(err, &skew) {
			out.Protocol, out.Build = skew.Server, skew.Build
		}
	} else {
		header := conn.Header()
		_ = conn.Close()
		out.Reachable, out.Protocol, out.Build = true, header.Protocol, header.Build
		out.Tetragon, out.TetragonReason = header.Tetragon, header.Reason
	}
	feedVersion := firstNonEmpty(out.Build, out.Version)
	out.UpdateNeeded = out.Reason == ReasonVersionSkew || (out.Installed && Older(feedVersion, gatewayVersion))
	return out
}

// Older reports whether release a is older than release b; false when
// either is not a release version (dev builds).
func Older(a, b string) bool {
	va, vb := "v"+strings.TrimPrefix(a, "v"), "v"+strings.TrimPrefix(b, "v")
	if !semver.IsValid(va) || !semver.IsValid(vb) {
		return false
	}
	return semver.Compare(va, vb) < 0
}

// readHelper reads the helper binary to install: a regular file, at most
// helperLimit bytes. It is read once and the copy is what gets checked, so
// the per-user file changing afterwards changes nothing.
func readHelper(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("no %s next to this gateway (%v); upgrade DefenseClaw to a release that ships it (Linux)", HelperName, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > helperLimit {
		return nil, fmt.Errorf("%s is not a regular file of at most %d bytes", path, helperLimit)
	}
	return io.ReadAll(io.LimitReader(file, helperLimit+1))
}

// writeFileSync writes data to path (replacing it), synced, with mode.
func writeFileSync(path string, data []byte, mode os.FileMode) error {
	_ = os.Remove(path)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

// writeIfChanged replaces path with data through a temporary file, unless it
// already holds exactly that.
func writeIfChanged(path string, data []byte, mode os.FileMode) error {
	if current, err := os.ReadFile(path); err == nil && bytes.Equal(current, data) {
		return os.Chmod(path, mode)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	staged := path + ".defenseclaw-new"
	if err := writeFileSync(staged, data, mode); err != nil {
		return err
	}
	return os.Rename(staged, path)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return line
}
