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
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/netguard"
)

// The per-user tarball install is the managed-enterprise "setup" install
// mode (enterprise.openshell.install: setup). The user's sandbox daemon, a
// process of that user, installs NVIDIA's release tarballs into the user's
// own ~/.local at first use: the CLI and the gateway in ~/.local/bin and the
// MicroVM driver in ~/.local/libexec/openshell. It needs no administrator
// rights and writes nothing outside the user's home. DefenseClaw ships no
// OpenShell: every byte comes from NVIDIA's release server and has to match
// both NVIDIA's own checksum file and the digest pinned in TarballPins.

// Tarball install errors.
var (
	// ErrTarballOffline means NVIDIA's release server could not be reached.
	// Nothing was installed.
	ErrTarballOffline = errors.New("openshell: cannot reach NVIDIA's release server")
	// ErrTarballNotPinned means the release has no pinned digests in this
	// DefenseClaw build, so it cannot be installed.
	ErrTarballNotPinned = errors.New("openshell: this DefenseClaw build pins no digests for that OpenShell release")
	// ErrTarballPlatform means NVIDIA publishes no tarballs for the platform.
	ErrTarballPlatform = errors.New("openshell: NVIDIA publishes no OpenShell tarballs for this platform")
	// ErrTarballChecksum means a tarball does not match the checksum NVIDIA
	// publishes or the digest this build pins. Nothing was installed.
	ErrTarballChecksum = errors.New("openshell: a release tarball does not match its checksum")
	// ErrTarballContent means a tarball holds more or other than its one
	// binary. Nothing was installed.
	ErrTarballContent = errors.New("openshell: a release tarball has unexpected content")
)

const (
	// TarballManifestName is the record of what the tarball install put in
	// the user's home, in TarballStateDir.
	TarballManifestName = "openshell-install.json"
	// TarballStateDir is below the home: the manifest and the downloads in
	// progress.
	TarballStateDir = ".local/share/defenseclaw-sandbox"

	tarballMaxAssetBytes  = 512 << 20
	tarballMaxBinaryBytes = 1 << 30
	tarballMaxChecksums   = 1 << 20
	tarballDefaultTimeout = 20 * time.Minute
)

// tarballComponent is one NVIDIA tarball and the one binary it holds.
type tarballComponent struct {
	// Name is the asset stem (openshell, openshell-gateway,
	// openshell-driver-vm) and the binary's file name.
	Name string
	// Libexec puts the binary in ~/.local/libexec/openshell instead of
	// ~/.local/bin.
	Libexec bool
	// Checksums is the name of the checksum file that lists the tarball.
	Checksums string
}

var tarballComponents = []tarballComponent{
	{Name: "openshell", Checksums: "openshell-checksums-sha256.txt"},
	{Name: "openshell-gateway", Checksums: "openshell-gateway-checksums-sha256.txt"},
	// The driver's digest is in the CLI's checksum file.
	{Name: "openshell-driver-vm", Libexec: true, Checksums: "openshell-checksums-sha256.txt"},
}

// tarballTriples are the platform names of NVIDIA's assets: the CLI is a
// static musl build on Linux, the gateway and the driver link glibc.
func tarballTriples(goos, goarch string) (cli, gnu string, err error) {
	switch goos + "/" + goarch {
	case "linux/amd64":
		return "x86_64-unknown-linux-musl", "x86_64-unknown-linux-gnu", nil
	case "linux/arm64":
		return "aarch64-unknown-linux-musl", "aarch64-unknown-linux-gnu", nil
	case "darwin/arm64":
		return "aarch64-apple-darwin", "aarch64-apple-darwin", nil
	}
	return "", "", fmt.Errorf("%w: %s/%s (Linux amd64 and arm64 and macOS on Apple silicon are published)", ErrTarballPlatform, goos, goarch)
}

// assetName is the tarball file name of c on a platform.
func (c tarballComponent) assetName(cliTriple, gnuTriple string) string {
	if c.Name == "openshell" {
		return c.Name + "-" + cliTriple + ".tar.gz"
	}
	return c.Name + "-" + gnuTriple + ".tar.gz"
}

// InstalledFile is one file the tarball install placed.
type InstalledFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// InstalledRelease is the manifest of a tarball install: the record that
// the files below are DefenseClaw's to replace and remove.
type InstalledRelease struct {
	Version     string          `json:"version"`
	InstalledAt time.Time       `json:"installed_at"`
	Source      string          `json:"source"`
	Files       []InstalledFile `json:"files"`
}

// TarballResult is what Install did.
type TarballResult struct {
	Version string
	// Already is set when the pinned release was installed before and its
	// files are intact: nothing was downloaded.
	Already bool
	Files   []InstalledFile
}

// TarballInstaller installs one pinned OpenShell release from NVIDIA's
// tarballs into a user's home.
type TarballInstaller struct {
	// Version is the exact release (setup mode needs an exact pin).
	Version string
	// Home is the absolute home directory to install into.
	Home string
	// GOOS and GOARCH select the assets (default runtime).
	GOOS, GOARCH string
	// BaseURL is TarballBaseURL (tests substitute their own server).
	BaseURL string
	// Pins are the pinned digests (default TarballPins[Version]).
	Pins map[string]string
	// Proxy is enterprise.network: the administrator's proxy. The zero
	// value keeps the process environment's proxy variables.
	Proxy netguard.EgressProxy
	// HTTPClient overrides the client built from Proxy (tests).
	HTTPClient *http.Client
	// Runner runs the installed CLI's --version.
	Runner Runner
	// Now stamps the manifest.
	Now func() time.Time
}

func (t *TarballInstaller) defaults() error {
	if t.Version == "" {
		return errors.New("openshell: setup mode needs an exact OpenShell version")
	}
	if _, err := ParseVersion(t.Version); err != nil || strings.ContainsAny(t.Version, " <>=~^*,") {
		return fmt.Errorf("openshell: setup mode needs an exact OpenShell version, not %q", t.Version)
	}
	if !filepath.IsAbs(t.Home) || filepath.Clean(t.Home) == "/" {
		return fmt.Errorf("openshell: the install home %q is not an absolute directory", t.Home)
	}
	if t.GOOS == "" {
		t.GOOS = runtime.GOOS
	}
	if t.GOARCH == "" {
		t.GOARCH = runtime.GOARCH
	}
	if t.BaseURL == "" {
		t.BaseURL = TarballBaseURL
	}
	if t.Pins == nil {
		t.Pins = TarballPins[t.Version]
	}
	if len(t.Pins) == 0 {
		return fmt.Errorf("%w: %s (pinned: %s)", ErrTarballNotPinned, t.Version, strings.Join(PinnedTarballReleases(), ", "))
	}
	if t.Runner == nil {
		t.Runner = ExecRunner{}
	}
	if t.Now == nil {
		t.Now = time.Now
	}
	return nil
}

// PinnedTarballReleases lists the releases the tarball install can install.
func PinnedTarballReleases() []string {
	releases := make([]string, 0, len(TarballPins))
	for release := range TarballPins {
		releases = append(releases, release)
	}
	sort.Strings(releases)
	return releases
}

func (t *TarballInstaller) binDir() string { return filepath.Join(t.Home, ".local", "bin") }
func (t *TarballInstaller) libexecDir() string {
	return filepath.Join(t.Home, ".local", "libexec", "openshell")
}
func (t *TarballInstaller) stateDir() string {
	return filepath.Join(t.Home, filepath.FromSlash(TarballStateDir))
}
func (t *TarballInstaller) manifestPath() string {
	return filepath.Join(t.stateDir(), TarballManifestName)
}

// targetPath is where c's binary goes.
func (t *TarballInstaller) targetPath(c tarballComponent) string {
	if c.Libexec {
		return filepath.Join(t.libexecDir(), c.Name)
	}
	return filepath.Join(t.binDir(), c.Name)
}

// Installed reads the manifest and checks every file it lists. The release
// is "" when nothing DefenseClaw installed is there; intact is false when a
// listed file is missing or was changed.
func (t *TarballInstaller) Installed() (release InstalledRelease, intact bool, err error) {
	data, err := readSmallFile(t.manifestPath(), 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		return InstalledRelease{}, false, nil
	}
	if err != nil {
		return InstalledRelease{}, false, err
	}
	if err := json.Unmarshal(data, &release); err != nil {
		return InstalledRelease{}, false, fmt.Errorf("openshell: %s is not a tarball install manifest: %w", t.manifestPath(), err)
	}
	intact = len(release.Files) > 0
	for _, file := range release.Files {
		if !t.ownsPath(file.Path) {
			return release, false, fmt.Errorf("openshell: %s lists %s, which is outside the install directories", t.manifestPath(), file.Path)
		}
		sum, err := fileSHA256(file.Path)
		if err != nil || sum != file.SHA256 {
			intact = false
		}
	}
	return release, intact, nil
}

// ownsPath reports whether p is one of the files the install may list.
func (t *TarballInstaller) ownsPath(p string) bool {
	for _, c := range tarballComponents {
		if p == t.targetPath(c) {
			return true
		}
	}
	return false
}

// Install downloads and installs the pinned release. It is safe to run
// again: an intact install of the same release downloads nothing.
func (t *TarballInstaller) Install(ctx context.Context) (*TarballResult, error) {
	if err := t.defaults(); err != nil {
		return nil, err
	}
	cliTriple, gnuTriple, err := tarballTriples(t.GOOS, t.GOARCH)
	if err != nil {
		return nil, err
	}
	for _, c := range tarballComponents {
		if t.Pins[c.assetName(cliTriple, gnuTriple)] == "" {
			return nil, fmt.Errorf("%w: %s has no pinned digest for %s", ErrTarballNotPinned, t.Version, c.assetName(cliTriple, gnuTriple))
		}
	}
	if have, intact, err := t.Installed(); err == nil && intact && have.Version == t.Version {
		return &TarballResult{Version: t.Version, Already: true, Files: have.Files}, nil
	}
	if _, has := ctx.Deadline(); !has {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, tarballDefaultTimeout)
		defer cancel()
	}
	client, err := t.client()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(t.stateDir(), 0o700); err != nil {
		return nil, fmt.Errorf("openshell: create %s: %w", t.stateDir(), err)
	}
	work, err := os.MkdirTemp(t.stateDir(), "download-")
	if err != nil {
		return nil, fmt.Errorf("openshell: create a download folder: %w", err)
	}
	defer os.RemoveAll(work)

	published, err := t.fetchChecksums(ctx, client)
	if err != nil {
		return nil, err
	}
	// Every tarball is downloaded and checked before anything is installed,
	// so a bad one leaves the user's home as it was.
	type staged struct {
		component tarballComponent
		archive   string
	}
	var downloads []staged
	for _, c := range tarballComponents {
		asset := c.assetName(cliTriple, gnuTriple)
		want := strings.ToLower(t.Pins[asset])
		if listed := published[asset]; listed == "" {
			return nil, fmt.Errorf("%w: NVIDIA's checksum file for %s does not list %s", ErrTarballChecksum, t.Version, asset)
		} else if listed != want {
			return nil, fmt.Errorf("%w: %s is listed with sha256 %s by NVIDIA but pinned as %s in this DefenseClaw build; refusing to install it",
				ErrTarballChecksum, asset, listed, want)
		}
		archive := filepath.Join(work, asset)
		got, err := t.download(ctx, client, t.releaseURL(asset), archive)
		if err != nil {
			return nil, err
		}
		if got != want {
			return nil, fmt.Errorf("%w: %s has sha256 %s, want %s", ErrTarballChecksum, asset, got, want)
		}
		downloads = append(downloads, staged{component: c, archive: archive})
	}

	result := &TarballResult{Version: t.Version}
	for _, dir := range []string{t.binDir(), t.libexecDir()} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("openshell: create %s: %w", dir, err)
		}
	}
	for _, d := range downloads {
		target := t.targetPath(d.component)
		if err := extractSingleBinary(d.archive, d.component.Name, target); err != nil {
			return nil, err
		}
		sum, err := fileSHA256(target)
		if err != nil {
			return nil, err
		}
		result.Files = append(result.Files, InstalledFile{Path: target, SHA256: sum})
	}
	if err := t.checkInstalledVersion(ctx); err != nil {
		return nil, err
	}
	manifest := InstalledRelease{Version: t.Version, InstalledAt: t.Now().UTC(), Source: t.BaseURL, Files: result.Files}
	if err := writeJSONAtomic(t.manifestPath(), manifest, 0o644); err != nil {
		return nil, err
	}
	return result, nil
}

// client builds the HTTP client: the administrator's proxy when one is
// configured, the process environment's otherwise; redirects stay on
// GitHub's own hosts over HTTPS (release assets are served from a CDN).
func (t *TarballInstaller) client() (*http.Client, error) {
	if t.HTTPClient != nil {
		return t.HTTPClient, nil
	}
	transport, err := t.Proxy.Transport()
	if err != nil {
		return nil, fmt.Errorf("openshell: the enterprise.network proxy: %w", err)
	}
	transport.TLSHandshakeTimeout = 15 * time.Second
	transport.ResponseHeaderTimeout = 60 * time.Second
	base, _ := url.Parse(t.BaseURL)
	return &http.Client{Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		if req.URL.Scheme != "https" {
			return fmt.Errorf("refusing a redirect to %s", req.URL.Redacted())
		}
		host := strings.ToLower(req.URL.Hostname())
		if base != nil && host == strings.ToLower(base.Hostname()) {
			return nil
		}
		if host == "github.com" || strings.HasSuffix(host, ".github.com") || strings.HasSuffix(host, ".githubusercontent.com") {
			return nil
		}
		return fmt.Errorf("refusing a redirect to %s", host)
	}}, nil
}

func (t *TarballInstaller) releaseURL(asset string) string {
	return strings.TrimRight(t.BaseURL, "/") + "/v" + t.Version + "/" + asset
}

// fetchChecksums reads NVIDIA's checksum files of the release and returns
// asset name to lowercase digest.
func (t *TarballInstaller) fetchChecksums(ctx context.Context, client *http.Client) (map[string]string, error) {
	published := map[string]string{}
	seen := map[string]bool{}
	for _, c := range tarballComponents {
		if seen[c.Checksums] {
			continue
		}
		seen[c.Checksums] = true
		body, err := t.fetchSmall(ctx, client, t.releaseURL(c.Checksums), tarballMaxChecksums)
		if err != nil {
			return nil, err
		}
		scanner := bufio.NewScanner(strings.NewReader(string(body)))
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) != 2 || len(fields[0]) != 64 {
				continue
			}
			if _, err := hex.DecodeString(fields[0]); err != nil {
				continue
			}
			published[strings.TrimPrefix(fields[1], "*")] = strings.ToLower(fields[0])
		}
	}
	return published, nil
}

func (t *TarballInstaller) fetchSmall(ctx context.Context, client *http.Client, rawURL string, limit int64) ([]byte, error) {
	resp, err := t.get(ctx, client, rawURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, t.networkError(rawURL, err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("openshell: %s is larger than %d bytes", rawURL, limit)
	}
	return body, nil
}

func (t *TarballInstaller) get(ctx context.Context, client *http.Client, rawURL string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("openshell: request %s: %w", rawURL, err)
	}
	req.Header.Set("User-Agent", "defenseclaw-sandbox-daemon")
	resp, err := client.Do(req)
	if err != nil {
		return nil, t.networkError(rawURL, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("openshell: download %s: HTTP %d", rawURL, resp.StatusCode)
	}
	return resp, nil
}

// networkError names an unreachable server as ErrTarballOffline with the
// two ways out; any other failure keeps its own words.
func (t *TarballInstaller) networkError(rawURL string, err error) error {
	var netErr net.Error
	var urlErr *url.Error
	if errors.Is(err, context.Canceled) {
		return err
	}
	if errors.As(err, &netErr) || errors.As(err, &urlErr) {
		host := rawURL
		if u, perr := url.Parse(rawURL); perr == nil {
			host = u.Hostname()
		}
		return fmt.Errorf("%w (%s) to install OpenShell %s: %v; check the network and the proxy your administrator set in enterprise.network, "+
			"or ask your administrator to install OpenShell (enterprise.openshell.install: prerequisite)",
			ErrTarballOffline, host, t.Version, err)
	}
	return fmt.Errorf("openshell: download %s: %w", rawURL, err)
}

// download streams rawURL into dst and returns the lowercase SHA-256 of what
// it wrote.
func (t *TarballInstaller) download(ctx context.Context, client *http.Client, rawURL, dst string) (string, error) {
	resp, err := t.get(ctx, client, rawURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	file, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("openshell: create %s: %w", dst, err)
	}
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(file, hash), io.LimitReader(resp.Body, tarballMaxAssetBytes+1))
	if cerr := file.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", t.networkError(rawURL, err)
	}
	if n > tarballMaxAssetBytes {
		return "", fmt.Errorf("openshell: %s is larger than %d bytes", rawURL, int64(tarballMaxAssetBytes))
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// extractSingleBinary writes the one regular file name of the tarball to
// target, atomically and executable. A tarball with anything else in it is
// refused before anything is written: no other entry, no link, no path that
// leaves the archive root.
func extractSingleBinary(archive, name, target string) error {
	if err := walkSingleBinary(archive, name, nil); err != nil {
		return err
	}
	return walkSingleBinary(archive, name, func(r io.Reader, size int64) error {
		return writeExecutableAtomic(target, r, size)
	})
}

// walkSingleBinary checks that archive holds exactly the regular file name
// and calls write with its contents when write is set.
func walkSingleBinary(archive, name string, write func(io.Reader, int64) error) error {
	file, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("%w: %s is not a gzip archive: %v", ErrTarballContent, filepath.Base(archive), err)
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	found := false
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: %s: %v", ErrTarballContent, filepath.Base(archive), err)
		}
		clean := path.Clean(strings.TrimPrefix(header.Name, "./"))
		switch {
		case header.Typeflag == tar.TypeDir && clean == ".":
			continue
		case header.Typeflag != tar.TypeReg:
			return fmt.Errorf("%w: %s holds the %s entry %q", ErrTarballContent, filepath.Base(archive), tarTypeName(header.Typeflag), header.Name)
		case clean != name:
			return fmt.Errorf("%w: %s holds %q, want only %q", ErrTarballContent, filepath.Base(archive), header.Name, name)
		case found:
			return fmt.Errorf("%w: %s holds %q twice", ErrTarballContent, filepath.Base(archive), name)
		case header.Size <= 0 || header.Size > tarballMaxBinaryBytes:
			return fmt.Errorf("%w: %s: %q has size %d", ErrTarballContent, filepath.Base(archive), name, header.Size)
		}
		found = true
		if write != nil {
			if err := write(reader, header.Size); err != nil {
				return err
			}
		}
	}
	if !found {
		return fmt.Errorf("%w: %s does not hold %q", ErrTarballContent, filepath.Base(archive), name)
	}
	return nil
}

func tarTypeName(flag byte) string {
	switch flag {
	case tar.TypeSymlink:
		return "symlink"
	case tar.TypeLink:
		return "hard link"
	case tar.TypeDir:
		return "directory"
	}
	return "non-regular"
}

// writeExecutableAtomic writes size bytes of r to path through a temporary
// file in the same directory and renames it into place, so a running binary
// is replaced, never rewritten.
func writeExecutableAtomic(target string, r io.Reader, size int64) error {
	dir := filepath.Dir(target)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(target)+".tmp-")
	if err != nil {
		return fmt.Errorf("openshell: install %s: %w", target, err)
	}
	cleanup := func() { _ = os.Remove(tmp.Name()) }
	n, err := io.Copy(tmp, io.LimitReader(r, size))
	if err == nil && n != size {
		err = io.ErrUnexpectedEOF
	}
	if err == nil {
		err = tmp.Chmod(0o755)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		cleanup()
		return fmt.Errorf("openshell: install %s: %w", target, err)
	}
	if err := os.Rename(tmp.Name(), target); err != nil {
		cleanup()
		return fmt.Errorf("openshell: install %s: %w", target, err)
	}
	return nil
}

// checkInstalledVersion runs the installed CLI and checks that it reports
// the release (a run of the user's own file by the user).
func (t *TarballInstaller) checkInstalledVersion(ctx context.Context) error {
	cli := filepath.Join(t.binDir(), "openshell")
	out, err := t.Runner.Output(ctx, Command{Name: cli, Args: []string{"--version"}, Timeout: 30 * time.Second})
	if err != nil {
		return fmt.Errorf("openshell: the installed %s does not run: %w", cli, err)
	}
	got, err := VersionFromOutput(strings.TrimSpace(string(out)))
	if err != nil {
		return fmt.Errorf("openshell: the installed %s reports %q: %w", cli, strings.TrimSpace(string(out)), err)
	}
	if want, _ := ParseVersion(t.Version); got.Compare(want) != 0 {
		return fmt.Errorf("openshell: the installed %s reports %s, want %s", cli, got, t.Version)
	}
	return nil
}

func fileSHA256(p string) (string, error) {
	file, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", p)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func readSmallFile(p string, limit int64) ([]byte, error) {
	file, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", p, limit)
	}
	return data, nil
}

func writeJSONAtomic(p string, v any, mode os.FileMode) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), "."+filepath.Base(p)+".tmp-")
	if err != nil {
		return fmt.Errorf("openshell: write %s: %w", p, err)
	}
	_, err = tmp.Write(append(data, '\n'))
	if err == nil {
		err = tmp.Chmod(mode)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), p)
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("openshell: write %s: %w", p, err)
	}
	return nil
}
