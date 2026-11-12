// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// Platform selects an image in an index.
type Platform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Variant      string `json:"variant,omitempty"`
}

// DefaultPlatform is what E1 and the kind nodes run.
var DefaultPlatform = Platform{OS: "linux", Architecture: "amd64"}

// Descriptor is an OCI content descriptor.
type Descriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Platform    *Platform         `json:"platform,omitempty"`
}

// Manifest is an OCI or Docker v2 image manifest.
type Manifest struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType,omitempty"`
	Config        Descriptor        `json:"config"`
	Layers        []Descriptor      `json:"layers"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

type indexDoc struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType,omitempty"`
	Manifests     []Descriptor `json:"manifests"`
}

// ConfigDoc is an image config that keeps every field it does not edit.
type ConfigDoc struct {
	raw map[string]json.RawMessage
}

// ParseConfig reads an image config.
func ParseConfig(data []byte) (*ConfigDoc, error) {
	c := &ConfigDoc{}
	if err := json.Unmarshal(data, &c.raw); err != nil {
		return nil, fmt.Errorf("image config: %w", err)
	}
	if c.raw == nil {
		c.raw = map[string]json.RawMessage{}
	}
	return c, nil
}

// Marshal encodes the config deterministically (keys sorted).
func (c *ConfigDoc) Marshal() ([]byte, error) { return json.Marshal(c.raw) }

type containerCfg struct {
	User       string            `json:"User,omitempty"`
	WorkingDir string            `json:"WorkingDir,omitempty"`
	Env        []string          `json:"Env,omitempty"`
	Entrypoint []string          `json:"Entrypoint,omitempty"`
	Cmd        []string          `json:"Cmd,omitempty"`
	Labels     map[string]string `json:"Labels,omitempty"`
}

func (c *ConfigDoc) container() (map[string]json.RawMessage, error) {
	out := map[string]json.RawMessage{}
	if raw, ok := c.raw["config"]; ok && len(raw) > 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, fmt.Errorf("image config: config: %w", err)
		}
	}
	return out, nil
}

// Container returns the fields of config the checks read.
func (c *ConfigDoc) Container() (user, workdir string, env []string, labels map[string]string, err error) {
	var cc containerCfg
	if raw, ok := c.raw["config"]; ok && len(raw) > 0 && string(raw) != "null" {
		if err = json.Unmarshal(raw, &cc); err != nil {
			return "", "", nil, nil, fmt.Errorf("image config: config: %w", err)
		}
	}
	return cc.User, cc.WorkingDir, cc.Env, cc.Labels, nil
}

// EnvMap returns the image environment as a map; the last assignment wins.
func (c *ConfigDoc) EnvMap() (map[string]string, error) {
	_, _, env, _, err := c.Container()
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		m[k] = v
	}
	return m, nil
}

// DiffIDs returns rootfs.diff_ids.
func (c *ConfigDoc) DiffIDs() ([]string, error) {
	var rootfs struct {
		Type    string   `json:"type"`
		DiffIDs []string `json:"diff_ids"`
	}
	if raw, ok := c.raw["rootfs"]; ok {
		if err := json.Unmarshal(raw, &rootfs); err != nil {
			return nil, fmt.Errorf("image config: rootfs: %w", err)
		}
	}
	return rootfs.DiffIDs, nil
}

func (c *ConfigDoc) setContainerField(key string, v any) error {
	cc, err := c.container()
	if err != nil {
		return err
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	cc[key] = b
	whole, err := json.Marshal(cc)
	if err != nil {
		return err
	}
	c.raw["config"] = whole
	return nil
}

// SetEnv replaces the image environment.
func (c *ConfigDoc) SetEnv(env []string) error { return c.setContainerField("Env", env) }

// SetUser sets the image USER.
func (c *ConfigDoc) SetUser(u string) error { return c.setContainerField("User", u) }

// SetWorkingDir sets the image WORKDIR.
func (c *ConfigDoc) SetWorkingDir(w string) error { return c.setContainerField("WorkingDir", w) }

// SetEntrypoint sets the image ENTRYPOINT.
func (c *ConfigDoc) SetEntrypoint(e []string) error { return c.setContainerField("Entrypoint", e) }

// SetCmd sets the image CMD.
func (c *ConfigDoc) SetCmd(e []string) error { return c.setContainerField("Cmd", e) }

// SetLabels merges labels over the existing ones.
func (c *ConfigDoc) SetLabels(add map[string]string) error {
	_, _, _, have, err := c.Container()
	if err != nil {
		return err
	}
	if have == nil {
		have = map[string]string{}
	}
	for k, v := range add {
		have[k] = v
	}
	return c.setContainerField("Labels", have)
}

// AppendLayer adds a diff id and a history entry.
func (c *ConfigDoc) AppendLayer(diffID, createdBy string) error {
	rootfs := map[string]json.RawMessage{}
	if raw, ok := c.raw["rootfs"]; ok {
		if err := json.Unmarshal(raw, &rootfs); err != nil {
			return fmt.Errorf("image config: rootfs: %w", err)
		}
	}
	var ids []string
	if raw, ok := rootfs["diff_ids"]; ok {
		if err := json.Unmarshal(raw, &ids); err != nil {
			return fmt.Errorf("image config: diff_ids: %w", err)
		}
	}
	ids = append(ids, diffID)
	rootfs["type"] = json.RawMessage(`"layers"`)
	b, _ := json.Marshal(ids)
	rootfs["diff_ids"] = b
	whole, _ := json.Marshal(rootfs)
	c.raw["rootfs"] = whole

	var hist []json.RawMessage
	if raw, ok := c.raw["history"]; ok {
		if err := json.Unmarshal(raw, &hist); err != nil {
			return fmt.Errorf("image config: history: %w", err)
		}
	}
	entry, _ := json.Marshal(map[string]string{"created_by": createdBy, "comment": "defenseclaw template build"})
	hist = append(hist, entry)
	hb, _ := json.Marshal(hist)
	c.raw["history"] = hb
	return nil
}

// Image is a single-platform image loaded from a registry.
type Image struct {
	Ref    Ref
	Digest string // manifest digest
	// IndexDigest is the digest of the index the platform image was picked
	// from; empty when the reference named the image itself.
	IndexDigest string
	Manifest    Manifest
	ManifestRaw []byte
	Config      *ConfigDoc
	ConfigRaw   []byte
}

// Image resolves ref (following an index to platform) and loads manifest and
// config.
func (g *Registry) Image(ctx context.Context, ref Ref, platform Platform) (*Image, error) {
	body, mt, digest, err := g.Manifest(ctx, ref)
	if err != nil {
		return nil, err
	}
	indexDigest := ""
	if mt == MediaOCIIndex || mt == MediaDockerList {
		var idx indexDoc
		if err := json.Unmarshal(body, &idx); err != nil {
			return nil, fmt.Errorf("image index: %w", err)
		}
		var pick *Descriptor
		for i := range idx.Manifests {
			p := idx.Manifests[i].Platform
			if p != nil && p.OS == platform.OS && p.Architecture == platform.Architecture {
				pick = &idx.Manifests[i]
				break
			}
		}
		if pick == nil {
			return nil, fmt.Errorf("image %s has no %s/%s manifest", ref, platform.OS, platform.Architecture)
		}
		indexDigest = digest
		ref = ref.WithDigest(pick.Digest)
		body, mt, digest, err = g.Manifest(ctx, ref)
		if err != nil {
			return nil, err
		}
	}
	if mt != MediaOCIManifest && mt != MediaDockerManifest {
		return nil, fmt.Errorf("image %s: unsupported manifest type %q", ref, mt)
	}
	img := &Image{Ref: ref.WithDigest(digest), Digest: digest, IndexDigest: indexDigest, ManifestRaw: body}
	if err := json.Unmarshal(body, &img.Manifest); err != nil {
		return nil, fmt.Errorf("image manifest: %w", err)
	}
	cfgRaw, err := g.SmallBlob(ctx, ref.Registry, ref.Repo, img.Manifest.Config.Digest, maxConfigBytes)
	if err != nil {
		return nil, fmt.Errorf("image config: %w", err)
	}
	img.ConfigRaw = cfgRaw
	if img.Config, err = ParseConfig(cfgRaw); err != nil {
		return nil, err
	}
	return img, nil
}

// FileEntry is one path of an image's merged filesystem.
type FileEntry struct {
	Path     string // absolute, cleaned
	Type     byte   // tar type flag
	Mode     int64
	UID, GID int
	Size     int64
	Linkname string
	Layer    int
	off      int64 // data offset in the layer's uncompressed tar
}

// IsDir, IsRegular and IsSymlink classify an entry.
func (e *FileEntry) IsDir() bool     { return e.Type == tar.TypeDir }
func (e *FileEntry) IsRegular() bool { return e.Type == tar.TypeReg || e.Type == '\x00' }
func (e *FileEntry) IsSymlink() bool { return e.Type == tar.TypeSymlink }

// Limits bound what an image may make a build read.
type Limits struct {
	// MaxLayerBytes is the uncompressed size of one layer; MaxTotalBytes
	// the sum over layers; MaxEntries the number of tar entries.
	MaxLayerBytes int64
	MaxTotalBytes int64
	MaxEntries    int
	// MaxFileBytes is the largest file Read returns.
	MaxFileBytes int64
}

// DefaultLimits suit a harness image with a coding agent in it.
func DefaultLimits() Limits {
	return Limits{MaxLayerBytes: 6 << 30, MaxTotalBytes: 10 << 30, MaxEntries: 2_000_000, MaxFileBytes: 4 << 20}
}

// ImageFS is the merged, read-only view of an image's layers. It keeps the
// layers as uncompressed tar files in a private temp directory and an index
// of every path with its owner and mode taken from the tar headers, so
// ownership is judged without extracting anything as root.
type ImageFS struct {
	dir    string
	layers []string
	idx    map[string]*FileEntry
	limits Limits
	count  int // tar entries seen
	sorted []string
}

// OpenFS downloads the layers (digest-checked) and indexes them.
func (g *Registry) OpenFS(ctx context.Context, img *Image, lim Limits) (*ImageFS, error) {
	if lim == (Limits{}) {
		lim = DefaultLimits()
	}
	dir, err := os.MkdirTemp("", "dc-attest-fs-")
	if err != nil {
		return nil, err
	}
	fsys := &ImageFS{dir: dir, idx: map[string]*FileEntry{}, limits: lim}
	var total int64
	for i, l := range img.Manifest.Layers {
		file, n, err := g.cacheLayer(ctx, img.Ref, l, i, dir, lim.MaxLayerBytes)
		if err != nil {
			fsys.Close()
			return nil, err
		}
		fsys.layers = append(fsys.layers, file)
		total += n
		if total > lim.MaxTotalBytes {
			fsys.Close()
			return nil, fmt.Errorf("image %s is larger than %d bytes uncompressed", img.Ref, lim.MaxTotalBytes)
		}
		if err := fsys.indexLayer(i, file); err != nil {
			fsys.Close()
			return nil, err
		}
	}
	return fsys, nil
}

// cacheLayer stores the uncompressed layer in dir and checks the digest of
// the compressed bytes.
func (g *Registry) cacheLayer(ctx context.Context, ref Ref, l Descriptor, i int, dir string, maxBytes int64) (string, int64, error) {
	rc, _, err := g.Blob(ctx, ref.Registry, ref.Repo, l.Digest)
	if err != nil {
		return "", 0, fmt.Errorf("layer %d: %w", i, err)
	}
	defer rc.Close()
	h := sha256.New()
	src := io.TeeReader(rc, h)
	br := bufio.NewReader(src)
	var dec io.Reader = br
	head, _ := br.Peek(4)
	switch {
	case len(head) >= 2 && head[0] == 0x1f && head[1] == 0x8b:
		zr, err := gzip.NewReader(br)
		if err != nil {
			return "", 0, fmt.Errorf("layer %d: %w", i, err)
		}
		defer zr.Close()
		dec = zr
	case len(head) >= 4 && head[0] == 0x28 && head[1] == 0xb5 && head[2] == 0x2f && head[3] == 0xfd:
		return "", 0, fmt.Errorf("layer %d is zstd-compressed, which this build does not read", i)
	}
	name := filepath.Join(dir, fmt.Sprintf("layer-%03d.tar", i))
	out, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return "", 0, err
	}
	n, err := io.Copy(out, io.LimitReader(dec, maxBytes+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", 0, fmt.Errorf("layer %d: %w", i, err)
	}
	if n > maxBytes {
		return "", 0, fmt.Errorf("layer %d is larger than %d bytes uncompressed", i, maxBytes)
	}
	// Drain what the decoder did not need (gzip trailer) so the digest covers
	// every byte.
	_, _ = io.Copy(io.Discard, br)
	if got := "sha256:" + hex.EncodeToString(h.Sum(nil)); got != l.Digest {
		return "", 0, fmt.Errorf("layer %d: bytes hash to %s, manifest says %s", i, got, l.Digest)
	}
	return name, n, nil
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func cleanImagePath(name string) (string, bool) {
	p := path.Clean("/" + strings.TrimPrefix(name, "./"))
	return p, !strings.Contains(name, "\x00")
}

func (f *ImageFS) indexLayer(layer int, file string) error {
	fh, err := os.Open(file)
	if err != nil {
		return err
	}
	defer fh.Close()
	cr := &countingReader{r: bufio.NewReaderSize(fh, 1<<16)}
	tr := tar.NewReader(cr)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("layer %d: %w", layer, err)
		}
		f.count++
		if f.count > f.limits.MaxEntries {
			return fmt.Errorf("image has more than %d entries", f.limits.MaxEntries)
		}
		if hdr.Typeflag == tar.TypeGNUSparse {
			return fmt.Errorf("layer %d: sparse entries are not read", layer)
		}
		for k := range hdr.PAXRecords {
			if strings.HasPrefix(k, "GNU.sparse") {
				return fmt.Errorf("layer %d: sparse entries are not read", layer)
			}
		}
		p, ok := cleanImagePath(hdr.Name)
		if !ok {
			return fmt.Errorf("layer %d: bad path in tar", layer)
		}
		dir, base := path.Split(p)
		// A whiteout removes what lower layers hold; entries the same layer
		// adds, in any order, stay (OCI image spec, layer changesets).
		switch {
		case base == ".wh..wh..opq":
			f.removeBelow(path.Clean(f.canon(dir, true)), false, layer)
			continue
		case strings.HasPrefix(base, ".wh."):
			f.removeBelow(path.Join(f.canon(dir, true), strings.TrimPrefix(base, ".wh.")), true, layer)
			continue
		}
		// The parents are the real folders the extractor writes into: a
		// symlinked parent from a lower layer moves the entry.
		p = f.canon(p, false)
		e := &FileEntry{Path: p, Type: hdr.Typeflag, Mode: hdr.Mode, UID: hdr.Uid, GID: hdr.Gid,
			Size: hdr.Size, Linkname: hdr.Linkname, Layer: layer, off: cr.n}
		if hdr.Typeflag == tar.TypeLink {
			// A hard link is the same file as its target as it is now; a
			// later layer that replaces the target does not change it.
			t, ok := f.idx[f.canon(hdr.Linkname, true)]
			if !ok {
				return fmt.Errorf("layer %d: hard link %s has no target %s", layer, p, hdr.Linkname)
			}
			c := *t
			c.Path = p
			e = &c
		}
		f.idx[p] = e
		f.sorted = nil
	}
}

// canon resolves symlinked folders in p against the index, as the file system
// would: every parent always, the last element only when followLast. Loops
// and long chains stop where they are.
func (f *ImageFS) canon(p string, followLast bool) string {
	comps := strings.Split(strings.Trim(path.Clean("/"+p), "/"), "/")
	cur := "/"
	hops := 0
	for i := 0; i < len(comps); i++ {
		c := comps[i]
		if c == "" {
			continue
		}
		next := path.Join(cur, c)
		last := i == len(comps)-1
		if e, ok := f.idx[next]; ok && e.IsSymlink() && (!last || followLast) && hops < 16 {
			hops++
			base := cur
			if path.IsAbs(e.Linkname) {
				base = "/"
			}
			resolved := path.Clean(path.Join(base, e.Linkname))
			rest := append([]string(nil), comps[i+1:]...)
			comps = append(strings.Split(strings.Trim(resolved, "/"), "/"), rest...)
			cur, i = "/", -1
			continue
		}
		cur = next
	}
	return cur
}

// removeBelow deletes p (when self) and everything below it that lower
// layers added. An opaque whiteout keeps the directory itself.
func (f *ImageFS) removeBelow(p string, self bool, layer int) {
	prefix := p + "/"
	if p == "/" {
		prefix = "/"
	}
	for k, e := range f.idx {
		if e.Layer < layer && (strings.HasPrefix(k, prefix) || (self && k == p)) {
			delete(f.idx, k)
			f.sorted = nil
		}
	}
}

// Close removes the cached layers.
func (f *ImageFS) Close() error { return os.RemoveAll(f.dir) }

// Lookup returns the entry at p; symlinked parent folders are followed, a
// symlink at the end is returned as it is.
func (f *ImageFS) Lookup(p string) (*FileEntry, bool) {
	e, ok := f.idx[f.canon(p, false)]
	return e, ok
}

// Resolve is Lookup that also follows a symlink at the end, inside the image
// root, and returns the real path.
func (f *ImageFS) Resolve(p string) (*FileEntry, string, bool) {
	real := f.canon(p, true)
	e, ok := f.idx[real]
	return e, real, ok
}

// Paths lists every path, sorted.
func (f *ImageFS) Paths() []string {
	if f.sorted == nil {
		f.sorted = make([]string, 0, len(f.idx))
		for p := range f.idx {
			f.sorted = append(f.sorted, p)
		}
		sort.Strings(f.sorted)
	}
	return f.sorted
}

// Read returns a regular file's content. Symlinks are followed inside the
// image; a hard link is already its target.
func (f *ImageFS) Read(p string) ([]byte, error) {
	e, _, ok := f.Resolve(p)
	if !ok {
		return nil, fmt.Errorf("%s: %w", p, os.ErrNotExist)
	}
	if !e.IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", p)
	}
	if e.Size > f.limits.MaxFileBytes {
		return nil, fmt.Errorf("%s: %d bytes is over the %d byte read limit", p, e.Size, f.limits.MaxFileBytes)
	}
	fh, err := os.Open(f.layers[e.Layer])
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	buf := make([]byte, e.Size)
	if _, err := fh.ReadAt(buf, e.off); err != nil && (!errors.Is(err, io.EOF) || e.Size != 0) {
		return nil, err
	}
	return buf, nil
}

// Glob returns entries whose path matches a path.Match pattern (the
// pattern's slash count must equal the path's, as path.Match does).
func (f *ImageFS) Glob(pattern string) []*FileEntry {
	var out []*FileEntry
	for _, p := range f.Paths() {
		if ok, _ := path.Match(pattern, p); ok {
			out = append(out, f.idx[p])
		}
	}
	return out
}

// Under lists entries below dir (not dir itself), sorted by path.
func (f *ImageFS) Under(dir string) []*FileEntry {
	prefix := f.canon(dir, true) + "/"
	if prefix == "//" {
		prefix = "/"
	}
	paths := f.Paths()
	i := sort.SearchStrings(paths, prefix)
	var out []*FileEntry
	for ; i < len(paths) && strings.HasPrefix(paths[i], prefix); i++ {
		out = append(out, f.idx[paths[i]])
	}
	return out
}

// Materialize writes the content of the files below dir into a new folder
// under dest, mode 0600/0700, and returns it with the entries it could not
// copy: a scanner reads content and never gets a link out of the tree. A
// symlink to a file inside the image is copied as that file; a link to a
// folder, a device or a name that climbs out of the folder is reported.
func (f *ImageFS) Materialize(dir, dest string) (string, []string, error) {
	root := f.canon(dir, true)
	target := filepath.Join(dest, filepath.FromSlash(strings.TrimPrefix(root, "/")))
	if err := os.MkdirAll(target, 0o700); err != nil {
		return "", nil, err
	}
	var skipped []string
	for _, e := range f.Under(root) {
		rel := strings.TrimPrefix(e.Path, root+"/")
		out := filepath.Join(target, filepath.FromSlash(rel))
		if rel == "" || strings.Contains(rel, "..") || !strings.HasPrefix(out, target+string(filepath.Separator)) {
			skipped = append(skipped, e.Path+" (name)")
			continue
		}
		real := e
		if e.IsSymlink() {
			r, realPath, ok := f.Resolve(e.Path)
			if !ok {
				if len(f.Under(realPath)) > 0 {
					// A folder with no entry of its own, reached through a link.
					skipped = append(skipped, e.Path+" (link to a folder)")
				}
				continue // otherwise a dangling link has no content
			}
			real = r
		}
		switch {
		case real.IsDir() && e.IsDir():
			if err := os.MkdirAll(out, 0o700); err != nil {
				return "", nil, err
			}
		case real.IsDir():
			skipped = append(skipped, e.Path+" (link to a folder)")
		case real.IsRegular():
			data, err := f.Read(e.Path)
			if err != nil {
				return "", nil, err
			}
			if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
				return "", nil, err
			}
			if err := os.WriteFile(out, data, 0o600); err != nil {
				return "", nil, err
			}
		default:
			skipped = append(skipped, e.Path+" (special file)")
		}
	}
	return target, skipped, nil
}

// AddLayerGzip adds one more layer on top (a kit layer that is not pushed
// yet), so the scan reads the image as it will be.
func (f *ImageFS) AddLayerGzip(gz []byte) error {
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return err
	}
	defer zr.Close()
	i := len(f.layers)
	name := filepath.Join(f.dir, fmt.Sprintf("layer-%03d.tar", i))
	out, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	n, err := io.Copy(out, io.LimitReader(zr, f.limits.MaxLayerBytes+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n > f.limits.MaxLayerBytes {
		return fmt.Errorf("layer is larger than %d bytes uncompressed", f.limits.MaxLayerBytes)
	}
	f.layers = append(f.layers, name)
	return f.indexLayer(i, name)
}
