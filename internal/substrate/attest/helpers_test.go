// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// memRegistry is a minimal in-memory OCI registry for tests.
type memRegistry struct {
	mu        sync.Mutex
	blobs     map[string][]byte // digest → bytes (shared across repos: enough for tests)
	manifests map[string]manifestEntry
	uploads   map[string]*bytes.Buffer
	srv       *httptest.Server
	down      bool
	nextUp    int
}

type manifestEntry struct {
	body []byte
	ct   string
}

func newMemRegistry(t *testing.T) *memRegistry {
	t.Helper()
	m := &memRegistry{blobs: map[string][]byte{}, manifests: map[string]manifestEntry{}, uploads: map[string]*bytes.Buffer{}}
	m.srv = httptest.NewServer(http.HandlerFunc(m.handle))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *memRegistry) host() string { return strings.TrimPrefix(m.srv.URL, "http://") }

var (
	reManifest = regexp.MustCompile(`^/v2/(.+)/manifests/([^/]+)$`)
	reBlob     = regexp.MustCompile(`^/v2/(.+)/blobs/(sha256:[0-9a-f]{64})$`)
	reUploadNe = regexp.MustCompile(`^/v2/(.+)/blobs/uploads/$`)
	reUploadId = regexp.MustCompile(`^/v2/(.+)/blobs/uploads/([a-z0-9]+)$`)
	reTags     = regexp.MustCompile(`^/v2/(.+)/tags/list$`)
)

func (m *memRegistry) handle(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.down {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	p := r.URL.Path
	switch {
	case reManifest.MatchString(p):
		g := reManifest.FindStringSubmatch(p)
		key := g[1] + "|" + g[2]
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			e, ok := m.manifests[key]
			if !ok {
				http.Error(w, "no manifest", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", e.ct)
			w.Header().Set("Docker-Content-Digest", DigestOf(e.body))
			_, _ = w.Write(e.body)
		case http.MethodPut:
			body, _ := io.ReadAll(r.Body)
			ct := r.Header.Get("Content-Type")
			m.manifests[key] = manifestEntry{body, ct}
			m.manifests[g[1]+"|"+DigestOf(body)] = manifestEntry{body, ct}
			w.WriteHeader(http.StatusCreated)
		}
	case reBlob.MatchString(p):
		g := reBlob.FindStringSubmatch(p)
		b, ok := m.blobs[g[2]]
		if !ok {
			http.Error(w, "no blob", http.StatusNotFound)
			return
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = w.Write(b)
	case reUploadNe.MatchString(p) && r.Method == http.MethodPost:
		m.nextUp++
		id := "up" + string(rune('a'+m.nextUp%26)) + hex.EncodeToString([]byte{byte(m.nextUp)})
		m.uploads[id] = &bytes.Buffer{}
		g := reUploadNe.FindStringSubmatch(p)
		w.Header().Set("Location", "/v2/"+g[1]+"/blobs/uploads/"+id)
		w.WriteHeader(http.StatusAccepted)
	case reUploadId.MatchString(p) && r.Method == http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		want := r.URL.Query().Get("digest")
		if DigestOf(body) != want {
			http.Error(w, "digest mismatch", http.StatusBadRequest)
			return
		}
		m.blobs[want] = body
		w.WriteHeader(http.StatusCreated)
	case reTags.MatchString(p):
		g := reTags.FindStringSubmatch(p)
		var tags []string
		for k := range m.manifests {
			if repo, ref, _ := strings.Cut(k, "|"); repo == g[1] && !strings.HasPrefix(ref, "sha256:") {
				tags = append(tags, ref)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"name": g[1], "tags": tags})
	default:
		http.NotFound(w, r)
	}
}

func (m *memRegistry) setDown(v bool) { m.mu.Lock(); m.down = v; m.mu.Unlock() }

func (m *memRegistry) hasTag(repo, tag string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.manifests[repo+"|"+tag]
	return ok
}

func (m *memRegistry) client() *Registry {
	return NewRegistry(RegistryOptions{PlainHTTP: []string{m.host()}})
}

// tarFile is a file of a test layer.
type tarFile struct {
	path     string
	mode     int64
	uid, gid int
	data     string
	dir      bool
	// link makes a hard link to that path, symlink a symbolic link.
	link, symlink string
}

func gzipTar(t *testing.T, files []tarFile) (gz []byte, diffID string) {
	t.Helper()
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for _, f := range files {
		h := &tar.Header{Name: strings.TrimPrefix(f.path, "/"), Mode: f.mode, Uid: f.uid, Gid: f.gid, ModTime: time.Unix(0, 0)}
		switch {
		case f.dir:
			h.Typeflag, h.Name = tar.TypeDir, h.Name+"/"
		case f.link != "":
			h.Typeflag, h.Linkname = tar.TypeLink, strings.TrimPrefix(f.link, "/")
		case f.symlink != "":
			h.Typeflag, h.Linkname = tar.TypeSymlink, f.symlink
		default:
			h.Typeflag, h.Size = tar.TypeReg, int64(len(f.data))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte(f.data)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw.Bytes())
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	_, _ = zw.Write(raw.Bytes())
	_ = zw.Close()
	return out.Bytes(), "sha256:" + hex.EncodeToString(sum[:])
}

// pushImage pushes a one-layer image and returns its ref (by tag).
func pushImage(t *testing.T, m *memRegistry, repo, tag string, files []tarFile, env []string, user string) Ref {
	t.Helper()
	ctx := context.Background()
	g := m.client()
	gz, diff := gzipTar(t, files)
	ld, err := g.PutBlobBytes(ctx, m.host(), repo, gz)
	if err != nil {
		t.Fatal(err)
	}
	cfg := map[string]any{
		"architecture": "amd64", "os": "linux",
		"config": map[string]any{"Env": env, "User": user, "WorkingDir": "/work"},
		"rootfs": map[string]any{"type": "layers", "diff_ids": []string{diff}},
	}
	cb, _ := json.Marshal(cfg)
	cd, err := g.PutBlobBytes(ctx, m.host(), repo, cb)
	if err != nil {
		t.Fatal(err)
	}
	man := Manifest{SchemaVersion: 2, MediaType: MediaOCIManifest,
		Config: Descriptor{MediaType: MediaOCIConfig, Digest: cd, Size: int64(len(cb))},
		Layers: []Descriptor{{MediaType: MediaOCILayerGzip, Digest: ld, Size: int64(len(gz))}}}
	mb, _ := json.Marshal(man)
	ref := Ref{Registry: m.host(), Repo: repo, Tag: tag}
	if _, err := g.PutManifest(ctx, ref, MediaOCIManifest, mb); err != nil {
		t.Fatal(err)
	}
	return ref
}

// fakeSkillScanner flags a skill whose files contain the word MALICIOUS.
type fakeSkillScanner struct{ fail bool }

func (fakeSkillScanner) Name() string               { return "skill-scanner" }
func (fakeSkillScanner) Version() string            { return "test" }
func (fakeSkillScanner) SupportedTargets() []string { return []string{"skill"} }
func (f fakeSkillScanner) Scan(ctx context.Context, dir string) (*scanner.ScanResult, error) {
	res := &scanner.ScanResult{Scanner: "skill-scanner", Target: dir, Timestamp: time.Now()}
	if f.fail {
		res.ExitCode, res.ScanError = 2, "boom"
		return res, nil
	}
	out, err := grepDir(dir, "MALICIOUS")
	if err != nil {
		return nil, err
	}
	if out {
		res.Findings = append(res.Findings, scanner.Finding{ID: "x", RuleID: "x", Severity: scanner.SeverityHigh,
			Title: "malicious skill", Scanner: "skill-scanner"})
	}
	return res, nil
}

// fakeMCPScanner flags a tools file that mentions ssh keys.
type fakeMCPScanner struct{}

func (fakeMCPScanner) Name() string               { return "mcp-scanner" }
func (fakeMCPScanner) Version() string            { return "test" }
func (fakeMCPScanner) SupportedTargets() []string { return []string{"mcp"} }
func (fakeMCPScanner) Scan(ctx context.Context, file string) (*scanner.ScanResult, error) {
	res := &scanner.ScanResult{Scanner: "mcp-scanner", Target: file, Timestamp: time.Now()}
	data, err := readFile(file)
	if err != nil {
		return nil, err
	}
	if strings.Contains(data, "id_rsa") {
		res.Findings = append(res.Findings, scanner.Finding{ID: "p", RuleID: "mcp-yara", Severity: scanner.SeverityHigh,
			Title: "credential harvesting in a tool description", Scanner: "mcp-scanner"})
	}
	return res, nil
}

func readFile(p string) (string, error) {
	b, err := os.ReadFile(p)
	return string(b), err
}

func grepDir(dir, needle string) (bool, error) {
	found := false
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if strings.Contains(string(b), needle) {
			found = true
		}
		return nil
	})
	return found, err
}
