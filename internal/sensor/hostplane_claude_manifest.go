// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sensor

import (
	"bytes"
	"container/list"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/openpgp" //nolint:staticcheck // Release manifests use OpenPGP signatures.

	"github.com/defenseclaw/defenseclaw/internal/sensor/netprobe"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
)

// The release signing key is checked against Anthropic's published fingerprint.
//
//go:embed claude_release_key.asc
var claudeReleaseKey string

const claudeReleaseFingerprint = "31ddde24ddfab679f42d7bd2baa929ff1a7ecace"

// signedClaudeRelease reports whether digest, a hex SHA-256 an exec's source
// read from its image, is one of the version's signed release checksums.
func signedClaudeRelease(digest string, checksums [][32]byte) bool {
	raw, err := hex.DecodeString(digest)
	if err != nil || len(raw) != sha256.Size {
		return false
	}
	for _, value := range checksums {
		if bytes.Equal(value[:], raw) {
			return true
		}
	}
	return false
}

const (
	// maxReleaseManifests and maxFailedManifests bound the cache: a host runs
	// a handful of releases, and a failed or forged version is remembered
	// only to be refused quickly.
	maxReleaseManifests = 16
	maxFailedManifests  = 32
	// failedManifestRetry is how long a failed version is not fetched again.
	failedManifestRetry = 10 * time.Minute
	// unknownManifestInterval spaces fetches of versions not yet cached, and
	// maxManifestFetches bounds those running at once.
	unknownManifestInterval = 5 * time.Second
	maxManifestFetches      = 2
)

// releaseManifests is the host plane's view of the signed release
// manifests. Its lookup never blocks: a version that is not cached starts one
// fetch in the background (single flight, rate limited) and is answered as
// unknown, so its exec is classified as before -- detection fires -- until
// the signed manifest is in the cache. The event consumer never waits on the
// network (R108-COWORK-3 review 1).
type releaseManifests struct {
	fetch func(version string) ([][32]byte, bool)
	now   func() time.Time

	mu       sync.Mutex
	known    *list.List // of releaseManifest, most recent first
	byName   map[string]*list.Element
	failed   *list.List // of failedManifest, most recent first
	failedAt map[string]*list.Element
	inflight map[string]struct{}
	next     time.Time
	fetches  sync.WaitGroup
}

type releaseManifest struct {
	version   string
	checksums [][32]byte
}

type failedManifest struct {
	version string
	retry   time.Time
}

func newReleaseManifests(fetch func(string) ([][32]byte, bool)) *releaseManifests {
	return &releaseManifests{
		fetch: fetch, now: time.Now,
		known: list.New(), byName: make(map[string]*list.Element),
		failed: list.New(), failedAt: make(map[string]*list.Element),
		inflight: make(map[string]struct{}),
	}
}

// claudeReleases serves every host plane in this process.
var claudeReleases = newReleaseManifests(fetchClaudeReleaseChecksums)

// checksums returns the cached signed checksums of version, or starts their
// fetch and returns false.
func (m *releaseManifests) checksums(version string) ([][32]byte, bool) {
	if !plane.IsClaudeReleaseVersion(version) {
		return nil, false
	}
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	if element, found := m.byName[version]; found {
		m.known.MoveToFront(element)
		return element.Value.(releaseManifest).checksums, true
	}
	if element, found := m.failedAt[version]; found {
		if now.Before(element.Value.(failedManifest).retry) {
			return nil, false
		}
		m.failed.Remove(element)
		delete(m.failedAt, version)
	}
	if _, running := m.inflight[version]; running || len(m.inflight) >= maxManifestFetches || now.Before(m.next) {
		return nil, false
	}
	m.inflight[version] = struct{}{}
	m.next = now.Add(unknownManifestInterval)
	m.fetches.Add(1)
	go m.load(version, now)
	return nil, false
}

func (m *releaseManifests) load(version string, asked time.Time) {
	defer m.fetches.Done()
	values, ok := m.fetch(version)
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.inflight, version)
	if ok && len(values) != 0 {
		m.byName[version] = m.known.PushFront(releaseManifest{version: version, checksums: values})
		for m.known.Len() > maxReleaseManifests {
			oldest := m.known.Back()
			m.known.Remove(oldest)
			delete(m.byName, oldest.Value.(releaseManifest).version)
		}
		return
	}
	m.failedAt[version] = m.failed.PushFront(failedManifest{version: version, retry: asked.Add(failedManifestRetry)})
	for m.failed.Len() > maxFailedManifests {
		oldest := m.failed.Back()
		m.failed.Remove(oldest)
		delete(m.failedAt, oldest.Value.(failedManifest).version)
	}
}

// claudeReleaseHost serves the signed release manifests. It is the only host
// fetchClaudeReleaseChecksums reaches, redirects included.
const claudeReleaseHost = "downloads.claude.ai"

// withoutReleaseManifestFetch drops the connections to the release manifest
// host from the gateway's own connections: its fetch below is DefenseClaw's
// egress, not AI use (cowork-1-0-8 GAP-0068). The caller passes only the
// connections of this process, matched by its pid (os.Getpid), never by
// name: another process going to that host, a process merely named like the
// gateway, and the gateway going anywhere else are all still scored.
func withoutReleaseManifestFetch(
	connections []netprobe.Connection,
	resolve func(netprobe.Connection) (hostname string, confidence float64, source string),
) []netprobe.Connection {
	kept := make([]netprobe.Connection, 0, len(connections))
	for _, connection := range connections {
		if connection.State != netprobe.StateListen && !connection.Loopback() && connection.Public() &&
			connection.RemotePort == 443 {
			if hostname, _, _ := resolve(connection); strings.EqualFold(hostname, claudeReleaseHost) {
				continue
			}
		}
		kept = append(kept, connection)
	}
	return kept
}

func fetchClaudeReleaseChecksums(version string) ([][32]byte, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client := &http.Client{CheckRedirect: func(req *http.Request, _ []*http.Request) error {
		if req.URL.Scheme != "https" || req.URL.Host != claudeReleaseHost {
			return http.ErrUseLastResponse
		}
		return nil
	}}
	base := "https://" + claudeReleaseHost + "/claude-code-releases/" + version + "/manifest.json"
	manifest, ok := readClaudeReleaseFile(ctx, client, base, 1<<20)
	if !ok {
		return nil, false
	}
	signature, ok := readClaudeReleaseFile(ctx, client, base+".sig", 16<<10)
	if !ok {
		return nil, false
	}
	return parseClaudeReleaseManifest(manifest, signature, version)
}

func readClaudeReleaseFile(ctx context.Context, client *http.Client, url string, limit int64) ([]byte, bool) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, false
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength > limit {
		return nil, false
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	return data, err == nil && int64(len(data)) <= limit
}

func parseClaudeReleaseManifest(manifest, signature []byte, version string) ([][32]byte, bool) {
	keyring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(claudeReleaseKey))
	if err != nil || len(keyring) != 1 ||
		hex.EncodeToString(keyring[0].PrimaryKey.Fingerprint[:]) != claudeReleaseFingerprint {
		return nil, false
	}
	if _, err := openpgp.CheckArmoredDetachedSignature(keyring, bytes.NewReader(manifest), bytes.NewReader(signature)); err != nil {
		return nil, false
	}
	var release struct {
		Version   string `json:"version"`
		Platforms map[string]struct {
			Checksum string `json:"checksum"`
		} `json:"platforms"`
	}
	if json.Unmarshal(manifest, &release) != nil || release.Version != version {
		return nil, false
	}
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x64"
	}
	platformOS := runtime.GOOS
	if platformOS == "windows" {
		platformOS = "win32"
	}
	platform := platformOS + "-" + arch
	names := []string{platform}
	if runtime.GOOS == "linux" {
		names = append(names, platform+"-musl")
	}
	var checksums [][32]byte
	for _, name := range names {
		row, found := release.Platforms[name]
		if !found {
			continue
		}
		decoded, err := hex.DecodeString(row.Checksum)
		if err != nil || len(decoded) != 32 {
			return nil, false
		}
		var checksum [32]byte
		copy(checksum[:], decoded)
		checksums = append(checksums, checksum)
	}
	return checksums, len(checksums) != 0
}
