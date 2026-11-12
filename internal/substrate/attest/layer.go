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
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"
)

// LayerFile is one file of the kit layer. Ownership is explicit: the layer
// is written by the build, not extracted on a host, so a root-owned hook
// file is root-owned whoever runs the build.
type LayerFile struct {
	Path     string // absolute
	Mode     int64
	UID, GID int
	Data     []byte
	// Symlink, when set, makes the entry a symlink and ignores Data.
	Symlink string
	// Dir makes the entry a folder with this owner and mode.
	Dir bool
}

// LayerResult is a built layer.
type LayerResult struct {
	Gzip   []byte
	Digest string // of Gzip
	DiffID string // of the uncompressed tar
}

// BuildLayer writes a deterministic layer: sorted paths, parent directories
// owned by root with mode 0755 (or the owner of the first child, for a path
// under a user's home), a fixed mtime and a gzip header with no name or time.
// A parent folder the base already has is left as it is.
// Whiteouts remove paths of the base image.
func BuildLayer(files []LayerFile, whiteouts []string, homeOwners map[string][2]int, exists func(string) bool) (*LayerResult, error) {
	type item struct {
		name string
		hdr  tar.Header
		data []byte
	}
	byPath := map[string]*item{}
	epoch := time.Unix(0, 0)
	var order []string
	add := func(it *item) {
		if _, dup := byPath[it.name]; !dup {
			order = append(order, it.name)
		}
		byPath[it.name] = it
	}
	for _, f := range files {
		p := path.Clean(f.Path)
		if !path.IsAbs(p) || p == "/" {
			return nil, fmt.Errorf("layer file path %q must be absolute", f.Path)
		}
		h := tar.Header{Name: strings.TrimPrefix(p, "/"), Mode: f.Mode, Uid: f.UID, Gid: f.GID, ModTime: epoch, Format: tar.FormatPAX}
		it := &item{name: p, hdr: h}
		if f.Dir {
			it.hdr.Typeflag = tar.TypeDir
			it.hdr.Name += "/"
		} else if f.Symlink != "" {
			it.hdr.Typeflag = tar.TypeSymlink
			it.hdr.Linkname = f.Symlink
			it.hdr.Mode = 0o777
		} else {
			it.hdr.Typeflag = tar.TypeReg
			it.hdr.Size = int64(len(f.Data))
			it.data = f.Data
		}
		add(it)
	}
	// Parent directories that no file names: root-owned, except below a home
	// the build says belongs to a user.
	for _, name := range append([]string(nil), order...) {
		for d := path.Dir(name); d != "/" && d != "."; d = path.Dir(d) {
			if _, ok := byPath[d]; ok || (exists != nil && exists(d)) {
				continue
			}
			o := [2]int{0, 0}
			for home, ho := range homeOwners {
				if d == home || strings.HasPrefix(d, home+"/") {
					o = ho
				}
			}
			add(&item{name: d, hdr: tar.Header{Name: strings.TrimPrefix(d, "/") + "/", Typeflag: tar.TypeDir,
				Mode: 0o755, Uid: o[0], Gid: o[1], ModTime: epoch, Format: tar.FormatPAX}})
		}
	}
	for _, w := range whiteouts {
		p := path.Clean(w)
		if !path.IsAbs(p) || p == "/" {
			return nil, fmt.Errorf("whiteout path %q must be absolute", w)
		}
		wh := path.Join(path.Dir(p), ".wh."+path.Base(p))
		add(&item{name: wh, hdr: tar.Header{Name: strings.TrimPrefix(wh, "/"), Typeflag: tar.TypeReg, Mode: 0, ModTime: epoch, Format: tar.FormatPAX}})
	}
	sort.Strings(order)
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for _, name := range order {
		it := byPath[name]
		if err := tw.WriteHeader(&it.hdr); err != nil {
			return nil, err
		}
		if len(it.data) > 0 {
			if _, err := tw.Write(it.data); err != nil {
				return nil, err
			}
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	diff := sha256.Sum256(raw.Bytes())
	var gz bytes.Buffer
	zw, err := gzip.NewWriterLevel(&gz, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	zw.Header = gzip.Header{OS: 255} // unknown OS, no name, no mtime
	if _, err := io.Copy(zw, &raw); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(gz.Bytes())
	return &LayerResult{Gzip: gz.Bytes(), Digest: "sha256:" + hex.EncodeToString(sum[:]), DiffID: "sha256:" + hex.EncodeToString(diff[:])}, nil
}

// ConfigEdit edits the new image's config after the layer is appended.
type ConfigEdit func(*ConfigDoc) error

// AppendLayer writes base + layer to target and returns the new image. Base
// layers are copied into the target repository when it does not have them.
// The new manifest keeps the base's media-type family.
func (g *Registry) AppendLayer(ctx context.Context, base *Image, layer *LayerResult, target Ref, createdBy string, edit ConfigEdit) (*Image, error) {
	docker := base.Manifest.MediaType == MediaDockerManifest ||
		(base.Manifest.MediaType == "" && strings.Contains(string(base.ManifestRaw), "docker.distribution"))
	manifestType, configType, layerType := MediaOCIManifest, MediaOCIConfig, MediaOCILayerGzip
	if docker {
		manifestType, configType, layerType = MediaDockerManifest, MediaDockerConfig, MediaDockerLayer
	}
	for i, l := range base.Manifest.Layers {
		if base.Ref.Registry == target.Registry && base.Ref.Repo == target.Repo {
			continue
		}
		if ok, _ := g.BlobExists(ctx, target.Registry, target.Repo, l.Digest); ok {
			continue
		}
		rc, size, err := g.Blob(ctx, base.Ref.Registry, base.Ref.Repo, l.Digest)
		if err != nil {
			return nil, fmt.Errorf("copy layer %d: %w", i, err)
		}
		if size <= 0 {
			size = l.Size
		}
		err = g.PutBlob(ctx, target.Registry, target.Repo, l.Digest, rc, size)
		_ = rc.Close()
		if err != nil {
			return nil, fmt.Errorf("copy layer %d: %w", i, err)
		}
	}
	if _, err := g.PutBlobBytes(ctx, target.Registry, target.Repo, layer.Gzip); err != nil {
		return nil, fmt.Errorf("push kit layer: %w", err)
	}
	cfg, err := ParseConfig(base.ConfigRaw)
	if err != nil {
		return nil, err
	}
	if err := cfg.AppendLayer(layer.DiffID, createdBy); err != nil {
		return nil, err
	}
	if edit != nil {
		if err := edit(cfg); err != nil {
			return nil, err
		}
	}
	cfgRaw, err := cfg.Marshal()
	if err != nil {
		return nil, err
	}
	cfgDigest, err := g.PutBlobBytes(ctx, target.Registry, target.Repo, cfgRaw)
	if err != nil {
		return nil, fmt.Errorf("push config: %w", err)
	}
	m := Manifest{SchemaVersion: 2, MediaType: manifestType,
		Config: Descriptor{MediaType: configType, Digest: cfgDigest, Size: int64(len(cfgRaw))}}
	for _, l := range base.Manifest.Layers {
		lt := l.MediaType
		if lt == "" {
			lt = layerType
		}
		m.Layers = append(m.Layers, Descriptor{MediaType: lt, Digest: l.Digest, Size: l.Size})
	}
	m.Layers = append(m.Layers, Descriptor{MediaType: layerType, Digest: layer.Digest, Size: int64(len(layer.Gzip))})
	body, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	digest, err := g.PutManifest(ctx, target, manifestType, body)
	if err != nil {
		return nil, err
	}
	return &Image{Ref: target.WithDigest(digest), Digest: digest, Manifest: m, ManifestRaw: body, Config: cfg, ConfigRaw: cfgRaw}, nil
}
