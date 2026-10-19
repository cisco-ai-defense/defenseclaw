// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows || linux

package workspace

// This is a captured-tree reader, not a repository/transport implementation.
// go-git's object package links config/osfs transitively; no ambient config,
// filesystem storage, transport, subprocess or mmap API is called here.

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/format/idxfile"
	"github.com/go-git/go-git/v5/plumbing/format/packfile"
	"github.com/go-git/go-git/v5/plumbing/storer"
)

const (
	capturedObjectMaxBytes   = 32 << 20
	capturedDecodedMaxBytes  = 512 << 20
	capturedObjectMaxCount   = 100_000
	capturedDeltaMaxDepth    = 64
	capturedMetadataMaxBytes = 16 << 20
	capturedPathMaxBytes     = 4096
)

// CapturedGitError is an explicit refusal of an unsupported format or bounded
// resource contract. Reasons contain no source content or configuration value.
type CapturedGitError struct{ Reason string }

func (e *CapturedGitError) Error() string {
	return "workspace: captured Git staging refused: " + e.Reason
}
func capturedRefuse(reason string) error { return &CapturedGitError{Reason: reason} }

type capturedObjectLocation struct {
	kind       plumbing.ObjectType
	size       int64
	file       string
	base       plumbing.Hash
	delta      bool
	deltaDepth int
}

type capturedObjectStore struct {
	ctx             context.Context
	source, scratch *os.Root
	locations       map[plumbing.Hash]capturedObjectLocation
	decoded         map[plumbing.Hash]capturedObjectLocation
	inflated        int64
	count           int
}

func newCapturedObjectStore(ctx context.Context, source, scratch *os.Root) (*capturedObjectStore, error) {
	s := &capturedObjectStore{ctx: ctx, source: source, scratch: scratch,
		locations: map[plumbing.Hash]capturedObjectLocation{}, decoded: map[plumbing.Hash]capturedObjectLocation{}}
	for _, dir := range []string{"decoded", "deltas"} {
		if err := scratch.Mkdir(dir, 0o700); err != nil {
			return nil, err
		}
	}
	return s, s.inventory()
}

func (s *capturedObjectStore) charge(n int64) error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	if n < 0 || n > capturedObjectMaxBytes {
		return capturedRefuse("object_size_limit")
	}
	if n > capturedDecodedMaxBytes-s.inflated {
		return capturedRefuse("decoded_bytes_limit")
	}
	s.inflated += n
	return nil
}

func (s *capturedObjectStore) addLocation(h plumbing.Hash, loc capturedObjectLocation) error {
	if s.count >= capturedObjectMaxCount {
		return capturedRefuse("object_count_limit")
	}
	// Git can legitimately retain a loose copy of an object also in a pack.
	// Count physical entries for the resource cap; resolve one representation
	// and verify its content against the object ID before exposing it.
	if _, exists := s.locations[h]; !exists {
		s.locations[h] = loc
	}
	s.count++
	return nil
}

func capturedRead(root *os.Root, name string, limit int64) ([]byte, error) {
	if err := capturedRelativePath(name); err != nil {
		return nil, err
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > limit {
		return nil, capturedRefuse("file_size_or_type_limit")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) != info.Size() {
		return nil, capturedRefuse("captured_file_size_changed")
	}
	return b, nil
}

func capturedWrite(root *os.Root, name string, content []byte) error {
	if err := capturedRelativePath(name); err != nil {
		return err
	}
	if err := root.MkdirAll(path.Dir(name), 0o700); err != nil {
		return err
	}
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(content)
	return errors.Join(err, f.Close())
}

func capturedRelativePath(name string) error {
	if name == "" || name == "." || path.Clean(name) != name || strings.HasPrefix(name, "/") {
		return capturedRefuse("nonrelative_path")
	}
	if len(name) > capturedPathMaxBytes {
		return capturedRefuse("path_size_limit")
	}
	parts := strings.Split(name, "/")
	if len(parts) > hostStageMaxDepth {
		return capturedRefuse("path_depth_limit")
	}
	for _, part := range parts {
		if err := validateWindowsHostStageName(part); err != nil {
			return capturedRefuse("unsupported_windows_path")
		}
	}
	return nil
}

func (s *capturedObjectStore) inventory() error {
	entries, err := fs.ReadDir(s.source.FS(), ".git/objects")
	if err != nil {
		return err
	}
	var packs []string
	for _, d := range entries {
		if d.Name() == "info" {
			continue
		}
		if d.Name() == "pack" {
			if !d.IsDir() {
				return capturedRefuse("invalid_pack_directory")
			}
			files, err := fs.ReadDir(s.source.FS(), ".git/objects/pack")
			if err != nil {
				return err
			}
			for _, f := range files {
				if f.IsDir() {
					return capturedRefuse("invalid_pack_entry")
				}
				if strings.HasSuffix(f.Name(), ".pack") {
					packs = append(packs, f.Name())
					continue
				}
				// Reverse indexes, bitmaps, cruft timestamps and the multi-pack
				// index are optional metadata; neither interpreted nor copied.
				// Every pack still requires its independently verified IDX v2.
				// Promisor markers
				// are intentionally refused: a partial source is not complete.
				if strings.HasSuffix(f.Name(), ".idx") || strings.HasSuffix(f.Name(), ".rev") || strings.HasSuffix(f.Name(), ".bitmap") || strings.HasSuffix(f.Name(), ".keep") || strings.HasSuffix(f.Name(), ".mtimes") || f.Name() == "multi-pack-index" {
					continue
				}
				return capturedRefuse("unsupported_pack_sidecar")
			}
			continue
		}
		if !d.IsDir() || len(d.Name()) != 2 || !isLowerHex(d.Name()) {
			return capturedRefuse("invalid_loose_object_directory")
		}
		files, err := fs.ReadDir(s.source.FS(), ".git/objects/"+d.Name())
		if err != nil {
			return err
		}
		for _, f := range files {
			if f.IsDir() || len(f.Name()) != 38 || !isLowerHex(f.Name()) {
				return capturedRefuse("invalid_loose_object_name")
			}
			h := plumbing.NewHash(d.Name() + f.Name())
			if err := s.addLocation(h, capturedObjectLocation{file: ".git/objects/" + d.Name() + "/" + f.Name()}); err != nil {
				return err
			}
		}
	}
	for _, p := range packs {
		if err := s.readPack(p); err != nil {
			return err
		}
	}
	return nil
}

func isLowerHex(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return s != ""
}

func (s *capturedObjectStore) readPack(name string) error {
	base := strings.TrimSuffix(name, ".pack")
	if len(base) != 45 || !strings.HasPrefix(base, "pack-") || !isLowerHex(base[5:]) {
		return capturedRefuse("invalid_pack_name")
	}
	idx, err := s.readPackIndex(base + ".idx")
	if err != nil {
		return err
	}
	f, err := s.source.Open(".git/objects/pack/" + name)
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := packfile.NewScanner(capturedContextReadSeeker{s.ctx, f})
	_, count, err := scanner.Header()
	if err != nil {
		return err
	}
	if count > capturedObjectMaxCount || count != idx.Fanout[255] || int(count) > capturedObjectMaxCount-s.count {
		return capturedRefuse("pack_object_count_limit")
	}
	byOffset := make(map[int64]plumbing.Hash, count)
	iter, err := idx.Entries()
	if err != nil {
		return err
	}
	defer iter.Close()
	for {
		e, err := iter.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if e.Offset < 12 || e.Offset > uint64(^uint64(0)>>1) {
			return capturedRefuse("invalid_pack_offset")
		}
		if _, dup := byOffset[int64(e.Offset)]; dup {
			return capturedRefuse("duplicate_pack_offset")
		}
		byOffset[int64(e.Offset)] = e.Hash
	}
	type pending struct {
		h          plumbing.Hash
		loc        capturedObjectLocation
		offsetBase int64
	}
	var records []pending
	for i := uint32(0); i < count; i++ {
		hdr, err := scanner.NextObjectHeader()
		if err != nil {
			return err
		}
		h, found := byOffset[hdr.Offset]
		if !found {
			return capturedRefuse("pack_index_offset_mismatch")
		}
		if err := s.charge(hdr.Length); err != nil {
			return err
		}
		if hdr.Type != plumbing.CommitObject && hdr.Type != plumbing.TreeObject && hdr.Type != plumbing.BlobObject && hdr.Type != plumbing.TagObject && hdr.Type != plumbing.OFSDeltaObject && hdr.Type != plumbing.REFDeltaObject {
			return capturedRefuse("unsupported_object_type")
		}
		// Spill each inflated entry before resolving dependencies; recursive
		// resolution retains metadata only, never one payload per depth level.
		payload := "deltas/" + strconv.Itoa(s.count+len(records))
		out, err := s.scratch.OpenFile(payload, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		n, crc, readErr := scanner.NextObject(capturedContextWriter{s.ctx, out})
		err = errors.Join(readErr, out.Close())
		if err != nil {
			return err
		}
		if n != hdr.Length {
			return capturedRefuse("pack_inflated_size_mismatch")
		}
		want, err := idx.FindCRC32(h)
		if err != nil || want != crc {
			return capturedRefuse("pack_index_crc_mismatch")
		}
		loc := capturedObjectLocation{kind: hdr.Type, size: hdr.Length, file: payload, base: hdr.Reference, delta: hdr.Type == plumbing.OFSDeltaObject || hdr.Type == plumbing.REFDeltaObject}
		records = append(records, pending{h, loc, hdr.OffsetReference})
	}
	checksum, err := scanner.Checksum()
	if err != nil {
		return err
	}
	if checksum.String() != base[5:] || checksum != plumbing.Hash(idx.PackfileChecksum) {
		return capturedRefuse("pack_checksum_identity_mismatch")
	}
	position, err := scanner.SeekFromStart(0)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if position != info.Size() {
		return capturedRefuse("trailing_pack_bytes")
	}
	for _, r := range records {
		if r.loc.kind == plumbing.OFSDeltaObject {
			h, ok := byOffset[r.offsetBase]
			if !ok {
				return capturedRefuse("missing_offset_delta_base")
			}
			r.loc.base = h
		}
		if err := s.addLocation(r.h, r.loc); err != nil {
			return err
		}
	}
	return nil
}

func (s *capturedObjectStore) readPackIndex(name string) (*idxfile.MemoryIndex, error) {
	f, err := s.source.Open(".git/objects/pack/" + name)
	if err != nil {
		return nil, capturedRefuse("missing_pack_index")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	// Validate fanout count and exact possible v2 layout BEFORE the decoder
	// allocates fanout-driven hash/offset/CRC tables. No mmap is used.
	var head [1032]byte
	if _, err = io.ReadFull(f, head[:]); err != nil {
		return nil, err
	}
	if !bytes.Equal(head[:4], []byte{255, 't', 'O', 'c'}) || binary.BigEndian.Uint32(head[4:8]) != 2 {
		return nil, capturedRefuse("unsupported_pack_index_version")
	}
	count := binary.BigEndian.Uint32(head[1028:1032])
	minSize := int64(1072) + int64(count)*28
	if count > capturedObjectMaxCount || info.Size() < minSize || info.Size() > minSize+int64(count)*8 {
		return nil, capturedRefuse("pack_index_count_or_size_limit")
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	idx := idxfile.NewMemoryIndex()
	if err = idxfile.NewDecoder(f).Decode(idx); err != nil {
		return nil, err
	}
	return idx, nil
}

type capturedContextReader struct {
	ctx context.Context
	io.Reader
}

func (r capturedContextReader) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.Reader.Read(b)
}

type capturedContextReadSeeker struct {
	ctx context.Context
	io.ReadSeeker
}

func (r capturedContextReadSeeker) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.ReadSeeker.Read(b)
}

type capturedContextWriter struct {
	ctx context.Context
	io.Writer
}

func (w capturedContextWriter) Write(b []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	return w.Writer.Write(b)
}

func (s *capturedObjectStore) resolve(h plumbing.Hash, depth int, active map[plumbing.Hash]bool) (capturedObjectLocation, error) {
	if err := s.ctx.Err(); err != nil {
		return capturedObjectLocation{}, err
	}
	if loc, ok := s.decoded[h]; ok {
		if depth+loc.deltaDepth > capturedDeltaMaxDepth {
			return capturedObjectLocation{}, capturedRefuse("delta_depth_limit")
		}
		return loc, nil
	}
	if depth > capturedDeltaMaxDepth {
		return capturedObjectLocation{}, capturedRefuse("delta_depth_limit")
	}
	if active[h] {
		return capturedObjectLocation{}, capturedRefuse("delta_cycle")
	}
	loc, ok := s.locations[h]
	if !ok {
		return capturedObjectLocation{}, capturedRefuse("missing_object_or_thin_pack")
	}
	active[h] = true
	defer delete(active, h)
	if loc.kind == plumbing.InvalidObject {
		return s.readLoose(h, loc.file)
	}
	if loc.delta {
		base, err := s.resolve(loc.base, depth+1, active)
		if err != nil {
			return capturedObjectLocation{}, err
		}
		// Base resolution completed before loading this level's delta bytes.
		delta, err := capturedRead(s.scratch, loc.file, capturedObjectMaxBytes)
		if err != nil {
			return capturedObjectLocation{}, err
		}
		sourceSize, targetSize, err := capturedDeltaSizes(delta)
		if err != nil {
			return capturedObjectLocation{}, err
		}
		if sourceSize != base.size {
			return capturedObjectLocation{}, capturedRefuse("delta_base_size_mismatch")
		}
		if base.deltaDepth >= capturedDeltaMaxDepth {
			return capturedObjectLocation{}, capturedRefuse("delta_depth_limit")
		}
		if err := s.charge(targetSize); err != nil {
			return capturedObjectLocation{}, err
		}
		data, err := capturedRead(s.scratch, base.file, capturedObjectMaxBytes)
		if err != nil {
			return capturedObjectLocation{}, err
		}
		result, err := packfile.PatchDelta(data, delta)
		if err != nil {
			return capturedObjectLocation{}, err
		}
		if int64(len(result)) != targetSize {
			return capturedObjectLocation{}, capturedRefuse("delta_result_size_mismatch")
		}
		resolved, err := s.cache(h, base.kind, result)
		if err != nil {
			return capturedObjectLocation{}, err
		}
		resolved.deltaDepth = base.deltaDepth + 1
		s.decoded[h] = resolved
		return resolved, nil
	}
	data, err := capturedRead(s.scratch, loc.file, capturedObjectMaxBytes)
	if err != nil {
		return capturedObjectLocation{}, err
	}
	if plumbing.ComputeHash(loc.kind, data) != h {
		return capturedObjectLocation{}, capturedRefuse("object_id_mismatch")
	}
	// A full packed entry is already in held scratch: retain that verified
	// file instead of storing a second complete decoded copy.
	s.decoded[h] = loc
	return loc, nil
}

func capturedDeltaSizes(delta []byte) (int64, int64, error) {
	pos := 0
	read := func() (int64, error) {
		var value uint64
		for shift := uint(0); shift < 63; shift += 7 {
			if pos >= len(delta) {
				return 0, capturedRefuse("invalid_delta_header")
			}
			b := delta[pos]
			pos++
			value |= uint64(b&127) << shift
			if b&128 == 0 {
				if value > capturedObjectMaxBytes {
					return 0, capturedRefuse("object_size_limit")
				}
				return int64(value), nil
			}
		}
		return 0, capturedRefuse("delta_header_overflow")
	}
	a, err := read()
	if err != nil {
		return 0, 0, err
	}
	b, err := read()
	return a, b, err
}

func (s *capturedObjectStore) cache(h plumbing.Hash, kind plumbing.ObjectType, data []byte) (capturedObjectLocation, error) {
	if plumbing.ComputeHash(kind, data) != h {
		return capturedObjectLocation{}, capturedRefuse("object_id_mismatch")
	}
	loc := capturedObjectLocation{kind: kind, size: int64(len(data)), file: "decoded/" + h.String()}
	if err := capturedWrite(s.scratch, loc.file, data); err != nil {
		return capturedObjectLocation{}, err
	}
	s.decoded[h] = loc
	return loc, nil
}

func (s *capturedObjectStore) readLoose(h plumbing.Hash, name string) (capturedObjectLocation, error) {
	f, err := s.source.Open(name)
	if err != nil {
		return capturedObjectLocation{}, err
	}
	defer f.Close()
	compressed := bufio.NewReader(capturedContextReader{s.ctx, f})
	zr, err := zlib.NewReader(compressed)
	if err != nil {
		return capturedObjectLocation{}, err
	}
	defer zr.Close()
	// objfile.Header has an unbounded read-until-delimiter API. Bound the
	// header before parsing instead of calling it on an attacker stream.
	reader := bufio.NewReaderSize(zr, 128)
	header, err := reader.ReadSlice(0)
	if err != nil || len(header) > 64 {
		return capturedObjectLocation{}, capturedRefuse("loose_object_header_limit")
	}
	typeText, sizeText, ok := strings.Cut(string(header[:len(header)-1]), " ")
	if !ok {
		return capturedObjectLocation{}, capturedRefuse("invalid_loose_object_header")
	}
	kind, err := plumbing.ParseObjectType(typeText)
	if err != nil || kind < plumbing.CommitObject || kind > plumbing.TagObject {
		return capturedObjectLocation{}, capturedRefuse("unsupported_object_type")
	}
	size, err := strconv.ParseInt(sizeText, 10, 64)
	if err != nil || strconv.FormatInt(size, 10) != sizeText {
		return capturedObjectLocation{}, capturedRefuse("invalid_loose_object_size")
	}
	if err = s.charge(size); err != nil {
		return capturedObjectLocation{}, err
	}
	data, err := io.ReadAll(io.LimitReader(reader, size+1))
	if err != nil {
		return capturedObjectLocation{}, err
	}
	if int64(len(data)) != size {
		return capturedObjectLocation{}, capturedRefuse("loose_object_size_mismatch")
	}
	if _, err := compressed.Peek(1); err != io.EOF {
		return capturedObjectLocation{}, capturedRefuse("trailing_loose_object_bytes")
	}
	return s.cache(h, kind, data)
}

func (s *capturedObjectStore) NewEncodedObject() plumbing.EncodedObject {
	return &plumbing.MemoryObject{}
}
func (s *capturedObjectStore) SetEncodedObject(obj plumbing.EncodedObject) (plumbing.Hash, error) {
	if err := s.charge(obj.Size()); err != nil {
		return plumbing.ZeroHash, err
	}
	r, err := obj.Reader()
	if err != nil {
		return plumbing.ZeroHash, err
	}
	defer r.Close()
	data, err := io.ReadAll(io.LimitReader(r, obj.Size()+1))
	if err != nil {
		return plumbing.ZeroHash, err
	}
	if int64(len(data)) != obj.Size() {
		return plumbing.ZeroHash, capturedRefuse("encoded_object_size_mismatch")
	}
	h := plumbing.ComputeHash(obj.Type(), data)
	if _, ok := s.decoded[h]; ok {
		return h, nil
	}
	if _, ok := s.locations[h]; !ok {
		if err = s.addLocation(h, capturedObjectLocation{}); err != nil {
			return plumbing.ZeroHash, err
		}
	}
	_, err = s.cache(h, obj.Type(), data)
	return h, err
}
func (s *capturedObjectStore) EncodedObject(kind plumbing.ObjectType, h plumbing.Hash) (plumbing.EncodedObject, error) {
	loc, err := s.resolve(h, 0, map[plumbing.Hash]bool{})
	if err != nil {
		return nil, err
	}
	if kind != plumbing.AnyObject && kind != loc.kind {
		return nil, plumbing.ErrObjectNotFound
	}
	return &capturedReadObject{store: s, loc: loc, hash: h}, nil
}

type capturedReadObject struct {
	store *capturedObjectStore
	loc   capturedObjectLocation
	hash  plumbing.Hash
}

func (o *capturedReadObject) Hash() plumbing.Hash         { return o.hash }
func (o *capturedReadObject) Type() plumbing.ObjectType   { return o.loc.kind }
func (o *capturedReadObject) Size() int64                 { return o.loc.size }
func (o *capturedReadObject) SetType(plumbing.ObjectType) {}
func (o *capturedReadObject) SetSize(int64)               {}
func (o *capturedReadObject) Reader() (io.ReadCloser, error) {
	f, err := o.store.scratch.Open(o.loc.file)
	if err != nil {
		return nil, err
	}
	return &capturedContextReadCloser{capturedContextReader{o.store.ctx, f}, f}, nil
}
func (o *capturedReadObject) Writer() (io.WriteCloser, error) {
	return nil, capturedRefuse("read_only_encoded_object")
}

type capturedContextReadCloser struct {
	capturedContextReader
	io.Closer
}

func (s *capturedObjectStore) IterEncodedObjects(plumbing.ObjectType) (storer.EncodedObjectIter, error) {
	return nil, capturedRefuse("object_iteration_not_supported")
}
func (s *capturedObjectStore) HasEncodedObject(h plumbing.Hash) error {
	_, err := s.resolve(h, 0, map[plumbing.Hash]bool{})
	return err
}
func (s *capturedObjectStore) EncodedObjectSize(h plumbing.Hash) (int64, error) {
	loc, err := s.resolve(h, 0, map[plumbing.Hash]bool{})
	return loc.size, err
}
func (s *capturedObjectStore) AddAlternate(string) error {
	return capturedRefuse("alternates_not_supported")
}

var _ storer.EncodedObjectStorer = (*capturedObjectStore)(nil)
