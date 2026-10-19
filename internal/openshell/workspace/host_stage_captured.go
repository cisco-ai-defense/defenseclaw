// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows || linux

package workspace

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	gitconfig "github.com/go-git/go-git/v5/plumbing/format/config"
	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
	"github.com/go-git/go-git/v5/plumbing/format/idxfile"
	"github.com/go-git/go-git/v5/plumbing/format/index"
	"github.com/go-git/go-git/v5/plumbing/format/objfile"
	"github.com/go-git/go-git/v5/plumbing/format/packfile"
	"github.com/go-git/go-git/v5/plumbing/hash"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// capturedGitSettings must be frozen by the host authority before engine use.
// In particular, local config alone is not the effective operator line-ending
// setting. This helper never reads HOME, system/global config or environment.
// The engine is used only by private host preparation. Stage and customer
// provider availability remain unchanged.
type capturedGitSettings struct {
	frozen      bool
	lineEndings map[string]string
}

type capturedStageEngine struct {
	ctx                     context.Context
	source, output, scratch *os.Root
	store                   *capturedObjectStore
	settings                capturedGitSettings
	remaining, written      int64
	trees                   map[plumbing.Hash]map[string]object.TreeEntry
	objects                 map[plumbing.Hash]bool
	shallow                 map[plumbing.Hash]bool
	graphVisits             int
	flattenedEntries        int
	flattenedPathBytes      int
	ignoreCase              bool
}

// stageCapturedSHA1 reads only a validated private captured source and writes
// only held-root-relative owned output/scratch paths. It has no runtime,
// launch, transport or original-source authority. Callers own cleanup of all
// three roots on refusal. opts.Project is used only as a policy display fact.
func stageCapturedSHA1(ctx context.Context, source, output, scratch *os.Root, opts StageOptions, scan secretScanOptions, settings capturedGitSettings) (CopyRecord, error) {
	var rec CopyRecord
	if !settings.frozen {
		return rec, capturedRefuse("operator_settings_not_frozen")
	}
	if len(scan.patterns) > maxMasks || len(scan.unmask) > maxMasks || len(scan.unmaskAsked) > maxMasks {
		return rec, capturedRefuse("sanitizer_pattern_count_limit")
	}
	if len(plumbing.ZeroHash) != 20 {
		return rec, capturedRefuse("sha1_build_required")
	}
	settings.lineEndings = maps.Clone(settings.lineEndings)
	if settings.lineEndings == nil {
		settings.lineEndings = map[string]string{}
	}
	for k := range settings.lineEndings {
		if !slices.Contains(lineEndingKeys, k) {
			return rec, capturedRefuse("line_ending_setting_not_supported")
		}
	}
	limit := opts.MaxBytes
	if limit <= 0 {
		limit = DefaultCopyMaxBytes
	}
	ctx, cancel := context.WithTimeout(ctx, hostStageDeadline)
	defer cancel()
	e := &capturedStageEngine{ctx: ctx, source: source, output: output, scratch: scratch, settings: settings, remaining: limit,
		trees: map[plumbing.Hash]map[string]object.TreeEntry{}, objects: map[plumbing.Hash]bool{}, shallow: map[plumbing.Hash]bool{}}
	repo := RepoName(opts.Project)
	if err := capturedRelativePath(repo); err != nil {
		return rec, err
	}
	rec = CopyRecord{Name: opts.Name, Project: opts.Project, RepoName: repo, Kind: CopyPlain}
	if err := output.Mkdir(repo, 0o700); err != nil {
		return rec, err
	}
	gitDir := ".dc/git"
	var cfg *gitconfig.Config
	var tracked map[string]filemode.FileMode
	info, err := source.Lstat(".git")
	if err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return rec, capturedRefuse("linked_git_metadata_not_supported")
		}
		rec.Kind = CopyGit
		gitDir = repo + "/.git"
		cfg, err = e.readConfig()
		if err != nil {
			return rec, err
		}
		tracked, err = e.readIndex()
		if err != nil {
			return rec, err
		}
		rec.Head, rec.Branch, err = e.readHead()
		if err != nil {
			return rec, err
		}
		if err = e.readShallow(); err != nil {
			return rec, err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return rec, err
	}
	if rec.Kind == CopyPlain {
		e.settings.lineEndings = map[string]string{}
	}
	effective, err := normalizeCapturedLineEndings(e.settings.lineEndings)
	if err != nil {
		return rec, err
	}
	e.settings.lineEndings = effective
	rec.LineEndings = maps.Clone(effective)
	if err = output.MkdirAll(gitDir+"/objects/info", 0o700); err != nil {
		return rec, err
	}
	if err = output.MkdirAll(gitDir+"/objects/pack", 0o700); err != nil {
		return rec, err
	}
	if rec.Kind == CopyGit {
		e.store, err = newCapturedObjectStore(ctx, source, scratch)
	} else {
		// A plain snapshot still receives a typed synthetic Git baseline, with
		// no repository discovery or external Git process.
		e.store = &capturedObjectStore{ctx: ctx, source: source, scratch: scratch, locations: map[plumbing.Hash]capturedObjectLocation{}, decoded: map[plumbing.Hash]capturedObjectLocation{}}
		err = scratch.Mkdir("decoded", 0o700)
	}
	if err != nil {
		return rec, err
	}
	candidates, leftOut, err := e.candidates(tracked, rec.Kind == CopyGit)
	if err != nil {
		return rec, err
	}
	if w := leftOutWarning(leftOut); w != "" {
		rec.Warnings = append(rec.Warnings, w)
	}
	selection := selectionIO{stat: source.Lstat, read: func(rel string, n int64) ([]byte, error) { return capturedRead(source, rel, n) }}
	files, held, err := selectCapturedFiles(selection, candidates, scan, limit, &rec)
	if err != nil {
		return rec, err
	}
	rec.HeldBack = held
	heldSet := toSet(held)
	withheld := func(rel string) bool {
		return skipped(heldSet, rel) || !unmaskedBy(scan.unmask, rel) && secretByName(scan.patterns, rel)
	}
	var headTree map[string]object.TreeEntry
	drop := map[plumbing.Hash]bool{}
	if rec.Head != "" {
		head := plumbing.NewHash(rec.Head)
		depth := opts.GitDepth
		if depth <= 0 {
			depth = DefaultGitDepth
		}
		if depth > capturedObjectMaxCount {
			return rec, capturedRefuse("history_depth_limit")
		}
		if err = e.history(head, depth, withheld, drop); err != nil {
			return rec, err
		}
		commit, err := e.commit(head)
		if err != nil {
			return rec, err
		}
		headTree, err = e.flatten(commit.TreeHash, 0)
		if err != nil {
			return rec, err
		}
	}
	baselineFiles := map[string]object.TreeEntry{}
	// A withheld tracked path remains in the baseline tree/index and is
	// skip-worktree, while its bytes are withheld from the guest object store.
	for rel, entry := range headTree {
		if skipped(heldSet, rel) {
			baselineFiles[rel] = entry
		}
	}
	for _, file := range files {
		data, err := capturedRead(source, file.rel, capturedObjectMaxBytes)
		if err != nil {
			return rec, err
		}
		if err = e.write(repo+"/"+file.rel, data); err != nil {
			return rec, err
		}
		blob := e.store.NewEncodedObject()
		blob.SetType(plumbing.BlobObject)
		blob.SetSize(int64(len(data)))
		w, _ := blob.Writer()
		_, err = w.Write(data)
		err = errors.Join(err, w.Close())
		if err != nil {
			return rec, err
		}
		h, err := e.store.SetEncodedObject(blob)
		if err != nil {
			return rec, err
		}
		mode := tracked[file.rel]
		if runtime.GOOS == "linux" {
			info, err := source.Lstat(file.rel)
			if err != nil {
				return rec, err
			}
			workingMode := filemode.Regular
			if info.Mode()&0o111 != 0 {
				workingMode = filemode.Executable
			}
			if mode != 0 && mode != workingMode {
				return rec, capturedRefuse("working_executable_mode_differs_from_index")
			}
			mode = workingMode
		} else if mode == 0 {
			mode = filemode.Regular
		}
		if runtime.GOOS == "linux" && mode == filemode.Executable {
			// Linux materializes executable working files in its private copy.
			// The preexisting Windows branch performs no additional I/O.
			if err := output.Chmod(repo+"/"+file.rel, 0o700); err != nil {
				return rec, err
			}
		}
		baselineFiles[file.rel] = object.TreeEntry{Hash: h, Mode: mode, Name: path.Base(file.rel)}
	}
	treeHash, err := e.buildTree(baselineFiles)
	if err != nil {
		return rec, err
	}
	now := time.Now().UTC()
	if opts.Now != nil {
		now = opts.Now().UTC()
	}
	sig := object.Signature{Name: "DefenseClaw", Email: "sandbox@localhost", When: now}
	baseline := &object.Commit{Author: sig, Committer: sig, TreeHash: treeHash, Message: "defenseclaw: baseline (working tree uploaded to the sandbox)\n"}
	if rec.Head != "" {
		baseline.ParentHashes = []plumbing.Hash{plumbing.NewHash(rec.Head)}
	}
	encoded := e.store.NewEncodedObject()
	if err = baseline.Encode(encoded); err != nil {
		return rec, err
	}
	baselineHash, err := e.store.SetEncodedObject(encoded)
	if err != nil {
		return rec, err
	}
	rec.Baseline = baselineHash.String()
	e.objects[baselineHash] = true
	if _, err = e.collectTree(treeHash, 0); err != nil {
		return rec, err
	}
	// Public duplicate content at HEAD or baseline remains available even
	// when the same object was once stored at a secret-named history path.
	for _, entries := range []map[string]object.TreeEntry{headTree, baselineFiles} {
		for rel, entry := range entries {
			if !withheld(rel) {
				delete(drop, entry.Hash)
			}
		}
	}
	rec.Withheld = len(drop)
	if rec.Withheld > 0 {
		rec.Warnings = append(rec.Warnings, fmt.Sprintf("%d committed version(s) of held-back or secret-named files are left out of the copy's history; git commands that need them fail", rec.Withheld))
	}
	fullPrefix := gitDir + "/objects"
	if len(drop) > 0 {
		fullPrefix = withheldObjectsDir
	}
	hashes := make([]plumbing.Hash, 0, len(e.objects))
	for h := range e.objects {
		hashes = append(hashes, h)
	}
	sort.Slice(hashes, func(i, j int) bool { return bytes.Compare(hashes[i][:], hashes[j][:]) < 0 })
	for _, h := range hashes {
		if err = e.writeObject(fullPrefix, h); err != nil {
			return rec, err
		}
	}
	if len(drop) > 0 {
		var keep []plumbing.Hash
		for _, h := range hashes {
			if !drop[h] {
				keep = append(keep, h)
			}
		}
		if err = e.writePromisor(gitDir, keep); err != nil {
			return rec, err
		}
	}
	if rec.Kind == CopyPlain {
		rec.Branch = "refs/heads/main"
		if err = e.write(gitDir+"/"+rec.Branch, []byte(rec.Baseline+"\n")); err != nil {
			return rec, err
		}
	} else if rec.Head != "" && rec.Branch != "" {
		if err = e.write(gitDir+"/"+rec.Branch, []byte(rec.Head+"\n")); err != nil {
			return rec, err
		}
	}
	headText := rec.Head + "\n"
	if rec.Branch != "" {
		headText = "ref: " + rec.Branch + "\n"
	}
	if err = e.write(gitDir+"/HEAD", []byte(headText)); err != nil {
		return rec, err
	}
	if err = e.write(gitDir+"/"+baselineRef, []byte(rec.Baseline+"\n")); err != nil {
		return rec, err
	}
	if err = e.writeOutputIndex(gitDir, headTree, heldSet); err != nil {
		return rec, err
	}
	if err = e.writeConfig(gitDir, cfg, &rec); err != nil {
		return rec, err
	}
	var boundaries []string
	for h := range e.shallow {
		if e.objects[h] {
			boundaries = append(boundaries, h.String())
		}
	}
	sort.Strings(boundaries)
	if len(boundaries) > 0 {
		if err = e.write(gitDir+"/shallow", []byte(strings.Join(boundaries, "\n")+"\n")); err != nil {
			return rec, err
		}
	}
	rec.Files = len(files)
	rec.Bytes = e.written
	return rec, nil
}

func normalizeCapturedLineEndings(values map[string]string) (map[string]string, error) {
	out := map[string]string{}
	for key, value := range values {
		value = strings.ToLower(value)
		switch key {
		case "core.autocrlf":
			switch value {
			case "false", "no", "off", "0":
				value = "false"
			default:
				return nil, capturedRefuse("line_ending_transform_not_supported")
			}
		case "core.eol":
			if value != "lf" {
				return nil, capturedRefuse("line_ending_transform_not_supported")
			}
		case "core.safecrlf":
			switch value {
			case "true", "yes", "on", "1":
				value = "true"
			case "false", "no", "off", "0":
				value = "false"
			case "warn":
			default:
				return nil, capturedRefuse("line_ending_transform_not_supported")
			}
		default:
			return nil, capturedRefuse("line_ending_setting_not_supported")
		}
		out[key] = value
	}
	return out, nil
}

// The legacy selector tolerates disappearing/unreadable live files. A private
// captured snapshot has no such partial-selection contract: a transient read
// failure must not skip secret scanning and then permit a later successful
// read to emit that file. Keep the original I/O cause and refuse before output.
func selectCapturedFiles(source selectionIO, candidates []string, scan secretScanOptions, limit int64, rec *CopyRecord) ([]stagedFile, []string, error) {
	var fault error
	record := func(err error) {
		if err != nil && fault == nil {
			fault = err
		}
	}
	strict := selectionIO{stat: func(rel string) (fs.FileInfo, error) { info, err := source.stat(rel); record(err); return info, err }, read: func(rel string, n int64) ([]byte, error) {
		data, err := source.read(rel, n)
		record(err)
		return data, err
	}}
	files, held, err := selectFilesFrom(strict, candidates, scan, limit, rec)
	if fault != nil {
		return nil, nil, errors.Join(capturedRefuse("captured_selection_io_failed"), fault, err)
	}
	return files, held, err
}

func (e *capturedStageEngine) readConfig() (*gitconfig.Config, error) {
	for _, name := range []string{".git/commondir", ".git/gitdir", ".git/config.worktree", ".git/index.lock", ".git/objects/info/alternates", ".git/objects/info/http-alternates", ".git/info/grafts", ".git/info/attributes", ".git/info/sparse-checkout", ".git/worktrees", ".git/modules", ".git/refs/replace"} {
		if _, err := e.source.Lstat(name); err == nil {
			return nil, capturedRefuse("external_or_extended_git_metadata_not_supported")
		} else if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	}
	data, err := capturedRead(e.source, ".git/config", 1<<20)
	if err != nil {
		return nil, err
	}
	cfg, err := parseCapturedGitConfig(data)
	if err != nil {
		return nil, err
	}
	for _, section := range cfg.Sections {
		switch strings.ToLower(section.Name) {
		case "include", "includeif", "filter", "submodule":
			return nil, capturedRefuse("config_feature_not_supported")
		case "extensions":
			for _, option := range section.Options {
				if !strings.EqualFold(option.Key, "objectformat") || !strings.EqualFold(option.Value, "sha1") {
					return nil, capturedRefuse("repository_extension_not_supported")
				}
			}
		case "core":
			if section.HasOption("ignorecase") {
				value := strings.ToLower(section.Option("ignorecase"))
				switch value {
				case "true", "yes", "on", "1":
					e.ignoreCase = true
				case "false", "no", "off", "0":
					e.ignoreCase = false
				default:
					return nil, capturedRefuse("invalid_ignorecase_boolean")
				}
			}
			for _, key := range []string{"worktree", "excludesfile", "attributesfile", "fsmonitor", "sparsecheckout", "sparsecheckoutcone"} {
				if section.HasOption(key) {
					return nil, capturedRefuse("core_feature_not_supported")
				}
			}
			if v := section.Option("repositoryformatversion"); v != "" && v != "0" && v != "1" {
				return nil, capturedRefuse("repository_format_not_supported")
			}
			if strings.EqualFold(section.Option("bare"), "true") {
				return nil, capturedRefuse("bare_repository_not_supported")
			}
			for _, key := range lineEndingKeys {
				short := strings.TrimPrefix(key, "core.")
				if section.HasOption(short) {
					e.settings.lineEndings[key] = section.Option(short)
				}
			}
		case "remote":
			for _, remote := range section.Subsections {
				if remote.Options.Has("promisor") || remote.Options.Has("partialclonefilter") {
					return nil, capturedRefuse("partial_source_not_supported")
				}
			}
		}
	}
	return cfg, nil
}

func capturedRawHash(data []byte) plumbing.Hash {
	h := hash.New(hash.CryptoType)
	_, _ = h.Write(data)
	var result plumbing.Hash
	copy(result[:], h.Sum(nil))
	return result
}

func (e *capturedStageEngine) readIndex() (map[string]filemode.FileMode, error) {
	data, err := capturedRead(e.source, ".git/index", capturedMetadataMaxBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]filemode.FileMode{}, nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) < 32 || !bytes.Equal(data[:4], []byte("DIRC")) {
		return nil, capturedRefuse("invalid_index_header")
	}
	version, count := binary.BigEndian.Uint32(data[4:8]), binary.BigEndian.Uint32(data[8:12])
	if version != 2 && version != 3 {
		return nil, capturedRefuse("index_version_not_supported")
	}
	if count > capturedObjectMaxCount || int64(count)*64 > int64(len(data)-32) {
		return nil, capturedRefuse("index_entry_count_limit")
	}
	if sum := capturedRawHash(data[:len(data)-20]); !bytes.Equal(sum[:], data[len(data)-20:]) {
		return nil, capturedRefuse("index_checksum_mismatch")
	}
	// Preflight entry boundaries and optional extensions before the upstream
	// decoder. Optional caches are deliberately not decoded or trusted.
	pos := 12
	for i := uint32(0); i < count; i++ {
		start := pos
		if len(data)-20-pos < 62 {
			return nil, capturedRefuse("truncated_index_entry")
		}
		flags := binary.BigEndian.Uint16(data[pos+60 : pos+62])
		pos += 62
		if flags&0x4000 != 0 {
			if version < 3 || len(data)-20-pos < 2 {
				return nil, capturedRefuse("invalid_extended_index_entry")
			}
			pos += 2
		}
		end := bytes.IndexByte(data[pos:len(data)-20], 0)
		if end < 0 || end > 32768 {
			return nil, capturedRefuse("index_path_size_limit")
		}
		if err := capturedWorkingPath(string(data[pos : pos+end])); err != nil {
			return nil, err
		}
		pos += end + 1
		pos += (8 - (pos-start)%8) % 8
		if pos > len(data)-20 {
			return nil, capturedRefuse("truncated_index_padding")
		}
	}
	entryEnd := pos
	for pos < len(data)-20 {
		if len(data)-20-pos < 8 {
			return nil, capturedRefuse("truncated_index_extension")
		}
		tag := data[pos : pos+4]
		n := binary.BigEndian.Uint32(data[pos+4 : pos+8])
		pos += 8
		if tag[0] < 'A' || tag[0] > 'Z' {
			return nil, capturedRefuse("mandatory_index_extension_not_supported")
		}
		if int64(n) > int64(len(data)-20-pos) {
			return nil, capturedRefuse("truncated_index_extension")
		}
		pos += int(n)
	}
	clean := slices.Clone(data[:entryEnd])
	sum := capturedRawHash(clean)
	clean = append(clean, sum[:]...)
	idx := &index.Index{}
	if err = index.NewDecoder(bytes.NewReader(clean)).Decode(idx); err != nil {
		return nil, err
	}
	tracked := map[string]filemode.FileMode{}
	folded := map[string]bool{}
	for _, entry := range idx.Entries {
		if entry.Stage != 0 || entry.IntentToAdd || entry.SkipWorktree {
			return nil, capturedRefuse("unmerged_or_sparse_index_not_supported")
		}
		if entry.Mode != filemode.Regular && entry.Mode != filemode.Executable {
			return nil, capturedRefuse("symlink_or_submodule_not_supported")
		}
		fold := strings.ToLower(entry.Name)
		if folded[fold] {
			return nil, capturedRefuse("index_path_collision")
		}
		folded[fold] = true
		tracked[entry.Name] = entry.Mode
	}
	return tracked, nil
}

func (e *capturedStageEngine) readHead() (string, string, error) {
	data, err := capturedRead(e.source, ".git/HEAD", 4096)
	if err != nil {
		return "", "", err
	}
	text := strings.TrimSuffix(string(data), "\n")
	text = strings.TrimSuffix(text, "\r")
	if branch, ok := strings.CutPrefix(text, "ref: "); ok {
		if !strings.HasPrefix(branch, "refs/heads/") || !plumbing.ReferenceName(branch).IsBranch() {
			return "", "", capturedRefuse("invalid_head_reference")
		}
		if err := plumbing.ReferenceName(branch).Validate(); err != nil {
			return "", "", capturedRefuse("invalid_head_reference")
		}
		if err := capturedRelativePath(branch); err != nil {
			return "", "", err
		}
		ref, err := capturedRead(e.source, ".git/"+branch, 128)
		if err == nil {
			h := strings.TrimSpace(string(ref))
			if len(h) != 40 || !isLowerHex(h) {
				return "", "", capturedRefuse("invalid_head_object_id")
			}
			return h, branch, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", "", err
		}
		packed, err := capturedRead(e.source, ".git/packed-refs", capturedMetadataMaxBytes)
		if err == nil {
			for _, line := range strings.Split(string(packed), "\n") {
				if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "^") || line == "" {
					continue
				}
				h, name, ok := strings.Cut(line, " ")
				if !ok || len(h) != 40 || !isLowerHex(h) {
					return "", "", capturedRefuse("invalid_packed_reference")
				}
				if name == branch {
					return h, branch, nil
				}
			}
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "", "", err
		}
		return "", branch, nil
	}
	if len(text) != 40 || !isLowerHex(text) {
		return "", "", capturedRefuse("invalid_head_object_id")
	}
	return text, "", nil
}

func (e *capturedStageEngine) readShallow() error {
	data, err := capturedRead(e.source, ".git/shallow", capturedMetadataMaxBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if len(line) != 40 || !isLowerHex(line) {
			return capturedRefuse("invalid_shallow_boundary")
		}
		e.shallow[plumbing.NewHash(line)] = true
		if len(e.shallow) > capturedObjectMaxCount {
			return capturedRefuse("shallow_boundary_count_limit")
		}
	}
	return nil
}

func (e *capturedStageEngine) candidates(tracked map[string]filemode.FileMode, isGit bool) ([]string, map[string]bool, error) {
	var patterns []gitignore.Pattern
	var patternWorkBytes int64
	addIgnore := func(name string, domain []string) error {
		data, err := capturedRead(e.source, name, 1<<20)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		domainBytes := 0
		for _, part := range domain {
			domainBytes += len(part) + 17
		}
		for _, line := range strings.Split(string(data), "\n") {
			if len(patterns) >= capturedObjectMaxCount {
				return capturedRefuse("ignore_pattern_count_limit")
			}
			line = strings.TrimSuffix(line, "\r")
			if line != "" && !strings.HasPrefix(line, "#") {
				if len(line) > capturedPathMaxBytes {
					return capturedRefuse("ignore_pattern_bytes_limit")
				}
				patternWorkBytes += int64(len(line) + domainBytes + 32)
				if patternWorkBytes > 1<<20 {
					return capturedRefuse("ignore_pattern_bytes_limit")
				}
				if strings.ContainsRune(line, '\\') {
					return capturedRefuse("ignore_syntax_not_supported")
				}
				// The pinned matcher is rune-oriented and does not backtrack
				// across ** path components like Git wildmatch. Refuse those
				// unrepresented forms rather than include an ignored file.
				if strings.Contains(line, "**") {
					return capturedRefuse("double_star_ignore_not_supported")
				}
				if strings.Contains(line, "[!") || strings.Contains(line, "[:") {
					return capturedRefuse("ignore_syntax_not_supported")
				}
				if !capturedASCII(line) {
					return capturedRefuse("nonascii_ignore_pattern_not_supported")
				}
				for _, part := range strings.Split(strings.TrimPrefix(line, "!"), "/") {
					if _, err := path.Match(part, ""); err != nil {
						return capturedRefuse("ignore_syntax_not_supported")
					}
				}
				if e.ignoreCase {
					line = capturedASCIILower(line)
				}
				patternDomain := slices.Clone(domain)
				if e.ignoreCase {
					for i := range patternDomain {
						patternDomain[i] = capturedASCIILower(patternDomain[i])
					}
				}
				patterns = append(patterns, gitignore.ParsePattern(line, patternDomain))
			}
		}
		return nil
	}
	if isGit {
		if err := addIgnore(".git/info/exclude", nil); err != nil {
			return nil, nil, err
		}
		if err := addIgnore(".gitignore", nil); err != nil {
			return nil, nil, err
		}
	}
	var names []string
	leftOut := map[string]bool{}
	count, pathBytes := 0, 0
	err := fs.WalkDir(e.source.FS(), ".", func(rel string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := e.ctx.Err(); err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		count++
		if count > hostStageMaxEntries {
			return capturedRefuse("working_tree_entry_limit")
		}
		if err := capturedRelativePath(rel); err != nil {
			return err
		}
		if d.IsDir() {
			if strings.EqualFold(d.Name(), ".git") {
				return fs.SkipDir
			}
			if rel != "." {
				if _, err := e.source.Lstat(rel + "/.git"); err == nil {
					for p := range tracked {
						if strings.HasPrefix(p, rel+"/") {
							return capturedRefuse("tracked_nested_repository_not_supported")
						}
					}
					leftOut[rel] = true
					return fs.SkipDir
				} else if !errors.Is(err, fs.ErrNotExist) {
					return err
				}
			}
			if isGit {
				return addIgnore(rel+"/.gitignore", strings.Split(rel, "/"))
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return capturedRefuse("nonregular_working_file_not_supported")
		}
		if strings.EqualFold(path.Base(rel), ".gitattributes") {
			data, err := capturedRead(e.source, rel, 1<<20)
			if err != nil {
				return err
			}
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					return capturedRefuse("attributes_not_supported")
				}
			}
		}
		pathBytes += len(rel)
		if pathBytes > capturedMetadataMaxBytes || len(names) >= capturedObjectMaxCount {
			return capturedRefuse("working_path_count_or_bytes_limit")
		}
		names = append(names, rel)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	// WalkDir visits a parent before children; patterns need root-to-leaf
	// precedence. Build each path's applicable list by its domain depth.
	matcher := gitignore.NewMatcher(patterns)
	var candidates []string
	trackedFolded := map[string]bool{}
	for rel := range tracked {
		if err := capturedWorkingPath(rel); err != nil {
			return nil, nil, err
		}
		trackedFolded[strings.ToUpper(rel)] = true
		if _, err := e.source.Lstat(rel); err == nil {
			candidates = append(candidates, rel)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return nil, nil, err
		}
	}
	matchWork := 10_000_000
	weightedWork := int64(4) << 30
	for _, rel := range names {
		if err := e.ctx.Err(); err != nil {
			return nil, nil, err
		}
		if trackedFolded[strings.ToUpper(rel)] {
			continue
		}
		if isGit && !capturedASCII(rel) {
			return nil, nil, capturedRefuse("nonascii_untracked_path_not_supported")
		}
		if dir := heavyDirOf(rel); dir != "" {
			leftOut[dir] = true
			continue
		}
		ignored := false
		if isGit {
			matchRel := rel
			if e.ignoreCase {
				matchRel = capturedASCIILower(rel)
			}
			parts := strings.Split(matchRel, "/")
			cost := len(patterns) * len(parts)
			weightedCost := patternWorkBytes * int64(len(matchRel)) * int64(len(parts))
			if cost > matchWork || weightedCost > weightedWork {
				return nil, nil, capturedRefuse("ignore_matching_work_limit")
			}
			matchWork -= cost
			weightedWork -= weightedCost
			for i := 1; i <= len(parts); i++ {
				if matcher.Match(parts[:i], i < len(parts)) {
					ignored = true
					break
				}
			}
		}
		if ignored {
			leftOut[rel] = true
			continue
		}
		candidates = append(candidates, rel)
	}
	return candidates, leftOut, nil
}

func capturedASCIILower(value string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, value)
}

func capturedASCII(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] > 127 {
			return false
		}
	}
	return true
}

func capturedWorkingPath(name string) error {
	if err := capturedRelativePath(name); err != nil {
		return err
	}
	for _, part := range strings.Split(name, "/") {
		fold := strings.ToLower(part)
		if fold == ".git" || strings.HasPrefix(fold, "git~") {
			return capturedRefuse("git_metadata_path_not_supported")
		}
	}
	return nil
}

func (e *capturedStageEngine) commit(h plumbing.Hash) (*object.Commit, error) {
	obj, err := e.store.EncodedObject(plumbing.CommitObject, h)
	if err != nil {
		return nil, err
	}
	if obj.Size() > 1<<20 {
		return nil, capturedRefuse("commit_metadata_size_limit")
	}
	r, err := obj.Reader()
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(r, (1<<20)+1))
	err = errors.Join(err, r.Close())
	if err != nil {
		return nil, err
	}
	header, _, ok := bytes.Cut(raw, []byte("\n\n"))
	if !ok || bytes.Count(header, []byte{'\n'}) > 10_000 {
		return nil, capturedRefuse("invalid_commit_headers")
	}
	parents, trees := 0, 0
	for _, line := range bytes.Split(header, []byte{'\n'}) {
		if bytes.HasPrefix(line, []byte("tree ")) {
			trees++
			value := string(line[5:])
			if len(value) != 40 || !isLowerHex(value) {
				return nil, capturedRefuse("invalid_commit_tree")
			}
		}
		if bytes.HasPrefix(line, []byte("parent ")) {
			parents++
			value := string(line[7:])
			if len(value) != 40 || !isLowerHex(value) {
				return nil, capturedRefuse("invalid_commit_parent")
			}
		}
	}
	if trees != 1 || parents > 64 {
		return nil, capturedRefuse("commit_parent_or_tree_count_limit")
	}
	commit, err := object.DecodeCommit(nil, obj)
	if err != nil {
		return nil, err
	}
	if len(commit.ParentHashes) > 64 {
		return nil, capturedRefuse("commit_parent_count_limit")
	}
	return commit, nil
}

func (e *capturedStageEngine) history(head plumbing.Hash, depth int, withheld func(string) bool, drop map[plumbing.Hash]bool) error {
	type item struct {
		hash  plumbing.Hash
		depth int
	}
	queue := []item{{head, 1}}
	seen := map[plumbing.Hash]bool{}
	// A subtree may occur at different paths with different withholding rules.
	// Reuse only an identical tree at the identical path across history.
	type treeVisit struct {
		hash   plumbing.Hash
		prefix string
	}
	trees := map[treeVisit]bool{}
	entriesVisited, pathBytes := 0, 0
	var walk func(plumbing.Hash, string, int) error
	walk = func(h plumbing.Hash, prefix string, depth int) error {
		if err := e.ctx.Err(); err != nil {
			return err
		}
		if depth > hostStageMaxDepth {
			return capturedRefuse("tree_depth_limit")
		}
		key := treeVisit{h, prefix}
		if trees[key] {
			return nil
		}
		if len(trees) >= capturedObjectMaxCount {
			return capturedRefuse("history_tree_visit_limit")
		}
		trees[key] = true
		tree, err := e.readTree(h)
		if err != nil {
			return err
		}
		e.objects[h] = true
		for _, entry := range tree.Entries {
			rel := prefix + entry.Name
			if err := capturedRelativePath(rel); err != nil {
				return err
			}
			entriesVisited++
			pathBytes += len(rel)
			if entriesVisited > capturedObjectMaxCount || pathBytes > capturedMetadataMaxBytes {
				return capturedRefuse("history_tree_expansion_limit")
			}
			if entry.Mode == filemode.Dir {
				if err := walk(entry.Hash, rel+"/", depth+1); err != nil {
					return err
				}
			} else {
				e.objects[entry.Hash] = true
				if withheld(rel) {
					drop[entry.Hash] = true
				}
			}
		}
		return nil
	}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if seen[current.hash] {
			continue
		}
		seen[current.hash] = true
		if len(seen) > capturedObjectMaxCount {
			return capturedRefuse("commit_count_limit")
		}
		commit, err := e.commit(current.hash)
		if err != nil {
			return err
		}
		e.objects[current.hash] = true
		if err := walk(commit.TreeHash, "", 0); err != nil {
			return err
		}
		if e.shallow[current.hash] || current.depth >= depth {
			if len(commit.ParentHashes) > 0 {
				e.shallow[current.hash] = true
			}
			continue
		}
		for _, parent := range commit.ParentHashes {
			queue = append(queue, item{parent, current.depth + 1})
		}
		if len(queue) > capturedObjectMaxCount {
			return capturedRefuse("commit_queue_limit")
		}
	}
	return nil
}

func (e *capturedStageEngine) readTree(h plumbing.Hash) (*object.Tree, error) {
	obj, err := e.store.EncodedObject(plumbing.TreeObject, h)
	if err != nil {
		return nil, err
	}
	// One malicious tree can otherwise allocate far more entries than the
	// object-count cap. Check entry structure/count before the decoder.
	r, err := obj.Reader()
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(r, capturedObjectMaxBytes+1))
	err = errors.Join(err, r.Close())
	if err != nil {
		return nil, err
	}
	pos, entries := 0, 0
	for pos < len(raw) {
		space := bytes.IndexByte(raw[pos:], ' ')
		if space < 0 || space > 6 {
			return nil, capturedRefuse("invalid_tree_mode")
		}
		pos += space + 1
		end := bytes.IndexByte(raw[pos:], 0)
		if end <= 0 || end > 255 {
			return nil, capturedRefuse("tree_name_limit")
		}
		if err := capturedWorkingPath(string(raw[pos : pos+end])); err != nil {
			return nil, capturedRefuse("unsupported_tree_path")
		}
		pos += end + 1 + 20
		if pos > len(raw) {
			return nil, capturedRefuse("truncated_tree_entry")
		}
		entries++
		if entries > capturedObjectMaxCount {
			return nil, capturedRefuse("tree_entry_count_limit")
		}
	}
	tree, err := object.DecodeTree(nil, obj)
	if err != nil {
		return nil, err
	}
	folded := map[string]bool{}
	for _, entry := range tree.Entries {
		fold := strings.ToLower(entry.Name)
		if folded[fold] {
			return nil, capturedRefuse("tree_path_collision")
		}
		folded[fold] = true
		if entry.Mode != filemode.Dir && entry.Mode != filemode.Regular && entry.Mode != filemode.Executable {
			return nil, capturedRefuse("symlink_or_submodule_not_supported")
		}
	}
	return tree, nil
}

func (e *capturedStageEngine) flatten(h plumbing.Hash, depth int) (map[string]object.TreeEntry, error) {
	if depth > hostStageMaxDepth {
		return nil, capturedRefuse("tree_depth_limit")
	}
	if cached, ok := e.trees[h]; ok {
		return cached, nil
	}
	tree, err := e.readTree(h)
	if err != nil {
		return nil, err
	}
	out := map[string]object.TreeEntry{}
	for _, entry := range tree.Entries {
		e.graphVisits++
		if e.graphVisits > capturedObjectMaxCount {
			return nil, capturedRefuse("tree_expansion_limit")
		}
		switch entry.Mode {
		case filemode.Dir:
			children, err := e.flatten(entry.Hash, depth+1)
			if err != nil {
				return nil, err
			}
			for child, file := range children {
				out[entry.Name+"/"+child] = file
			}
		case filemode.Regular, filemode.Executable:
			out[entry.Name] = entry
		default:
			return nil, capturedRefuse("symlink_or_submodule_not_supported")
		}
		if len(out) > capturedObjectMaxCount {
			return nil, capturedRefuse("flattened_tree_count_limit")
		}
	}
	for rel := range out {
		if err := capturedRelativePath(rel); err != nil {
			return nil, err
		}
		e.flattenedEntries++
		e.flattenedPathBytes += len(rel)
		if e.flattenedEntries > capturedObjectMaxCount || e.flattenedPathBytes > capturedMetadataMaxBytes {
			return nil, capturedRefuse("cumulative_tree_expansion_limit")
		}
	}
	e.trees[h] = out
	return out, nil
}

func (e *capturedStageEngine) collectTree(h plumbing.Hash, depth int) (map[string]object.TreeEntry, error) {
	entries, err := e.flatten(h, depth)
	if err != nil {
		return nil, err
	}
	// Include every intermediate raw tree with its original identity.
	var visit func(plumbing.Hash, int) error
	visit = func(id plumbing.Hash, d int) error {
		if d > hostStageMaxDepth {
			return capturedRefuse("tree_depth_limit")
		}
		if e.objects[id] {
			return nil
		}
		e.objects[id] = true
		obj, err := e.store.EncodedObject(plumbing.TreeObject, id)
		if err != nil {
			return err
		}
		tree, err := object.DecodeTree(nil, obj)
		if err != nil {
			return err
		}
		for _, entry := range tree.Entries {
			if entry.Mode == filemode.Dir {
				if err = visit(entry.Hash, d+1); err != nil {
					return err
				}
			} else {
				e.objects[entry.Hash] = true
			}
		}
		return nil
	}
	return entries, visit(h, depth)
}

func (e *capturedStageEngine) buildTree(files map[string]object.TreeEntry) (plumbing.Hash, error) {
	type node struct {
		files    map[string]object.TreeEntry
		children map[string]*node
	}
	root := &node{map[string]object.TreeEntry{}, map[string]*node{}}
	nodes := 1
	pathBytes := 0
	for name, entry := range files {
		if err := capturedWorkingPath(name); err != nil {
			return plumbing.ZeroHash, err
		}
		pathBytes += len(name)
		if pathBytes > capturedMetadataMaxBytes {
			return plumbing.ZeroHash, capturedRefuse("baseline_path_bytes_limit")
		}
		parts := strings.Split(name, "/")
		n := root
		for _, part := range parts[:len(parts)-1] {
			if _, ok := n.files[part]; ok {
				return plumbing.ZeroHash, capturedRefuse("tree_file_directory_conflict")
			}
			if n.children[part] == nil {
				nodes++
				if nodes > capturedObjectMaxCount {
					return plumbing.ZeroHash, capturedRefuse("baseline_tree_node_limit")
				}
				n.children[part] = &node{map[string]object.TreeEntry{}, map[string]*node{}}
			}
			n = n.children[part]
		}
		last := parts[len(parts)-1]
		if n.children[last] != nil {
			return plumbing.ZeroHash, capturedRefuse("tree_file_directory_conflict")
		}
		entry.Name = last
		n.files[last] = entry
	}
	var encode func(*node) (plumbing.Hash, error)
	encode = func(n *node) (plumbing.Hash, error) {
		tree := &object.Tree{}
		for _, entry := range n.files {
			tree.Entries = append(tree.Entries, entry)
		}
		for name, child := range n.children {
			h, err := encode(child)
			if err != nil {
				return plumbing.ZeroHash, err
			}
			tree.Entries = append(tree.Entries, object.TreeEntry{Name: name, Mode: filemode.Dir, Hash: h})
		}
		sort.Sort(object.TreeEntrySorter(tree.Entries))
		obj := e.store.NewEncodedObject()
		if err := tree.Encode(obj); err != nil {
			return plumbing.ZeroHash, err
		}
		return e.store.SetEncodedObject(obj)
	}
	return encode(root)
}

func (e *capturedStageEngine) write(name string, data []byte) error {
	if int64(len(data)) > e.remaining {
		return capturedRefuse("emitted_bytes_limit")
	}
	if err := capturedWrite(e.output, name, data); err != nil {
		return err
	}
	e.remaining -= int64(len(data))
	e.written += int64(len(data))
	return nil
}

type capturedOutputWriter struct {
	engine *capturedStageEngine
	io.Writer
}

func (w capturedOutputWriter) Write(data []byte) (int, error) {
	if err := w.engine.ctx.Err(); err != nil {
		return 0, err
	}
	if int64(len(data)) > w.engine.remaining {
		return 0, capturedRefuse("emitted_bytes_limit")
	}
	n, err := w.Writer.Write(data)
	w.engine.remaining -= int64(n)
	w.engine.written += int64(n)
	return n, err
}

func (e *capturedStageEngine) writeObject(prefix string, h plumbing.Hash) error {
	obj, err := e.store.EncodedObject(plumbing.AnyObject, h)
	if err != nil {
		return err
	}
	name := prefix + "/" + h.String()[:2] + "/" + h.String()[2:]
	if err = e.output.MkdirAll(path.Dir(name), 0o700); err != nil {
		return err
	}
	f, err := e.output.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	// The compressed object stream is charged while writing, including
	// zlib headers/trailers, so small compressed inputs cannot bypass output.
	writer := objfile.NewWriter(capturedOutputWriter{e, f})
	err = writer.WriteHeader(obj.Type(), obj.Size())
	if err == nil {
		r, openErr := obj.Reader()
		err = openErr
		if err == nil {
			_, err = io.Copy(writer, r)
			err = errors.Join(err, r.Close())
		}
	}
	return errors.Join(err, writer.Close(), f.Close())
}

func (e *capturedStageEngine) writePromisor(gitDir string, keep []plumbing.Hash) error {
	temp := gitDir + "/objects/pack/owned.pack"
	f, err := e.output.OpenFile(temp, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	h, err := packfile.NewEncoder(capturedOutputWriter{e, f}, e.store, false).Encode(keep, 0)
	if err != nil {
		_ = f.Close()
		return err
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		_ = f.Close()
		return err
	}
	scanner := packfile.NewScanner(capturedContextReadSeeker{e.ctx, f})
	_, count, err := scanner.Header()
	if err != nil {
		_ = f.Close()
		return err
	}
	if count != uint32(len(keep)) {
		_ = f.Close()
		return capturedRefuse("output_pack_count_mismatch")
	}
	w := &idxfile.Writer{}
	if err = w.OnHeader(count); err != nil {
		_ = f.Close()
		return err
	}
	for i := uint32(0); i < count; i++ {
		header, err := scanner.NextObjectHeader()
		if err != nil {
			_ = f.Close()
			return err
		}
		if header.Length < 0 || header.Length > capturedObjectMaxBytes || header.Type == plumbing.OFSDeltaObject || header.Type == plumbing.REFDeltaObject {
			_ = f.Close()
			return capturedRefuse("unexpected_output_delta")
		}
		hasher := plumbing.NewHasher(header.Type, header.Length)
		n, crc, err := scanner.NextObject(hasher)
		if err != nil || n != header.Length {
			_ = f.Close()
			return errors.Join(err, capturedRefuse("output_object_size_mismatch"))
		}
		w.Add(hasher.Sum(), uint64(header.Offset), crc)
	}
	sum, err := scanner.Checksum()
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if h != sum {
		return capturedRefuse("output_pack_checksum_mismatch")
	}
	if err = w.OnFooter(h); err != nil {
		return err
	}
	idx, err := w.Index()
	if err != nil {
		return err
	}
	var encoded bytes.Buffer
	if _, err = idxfile.NewEncoder(&encoded).Encode(idx); err != nil {
		return err
	}
	name := gitDir + "/objects/pack/pack-" + h.String()
	if err = e.output.Rename(temp, name+".pack"); err != nil {
		return err
	}
	if err = e.write(name+".idx", encoded.Bytes()); err != nil {
		return err
	}
	return e.write(name+".promisor", nil)
}

func (e *capturedStageEngine) writeOutputIndex(gitDir string, files map[string]object.TreeEntry, held map[string]struct{}) error {
	idx := &index.Index{Version: 2}
	for name, entry := range files {
		item := idx.Add(name)
		item.Mode = entry.Mode
		item.Hash = entry.Hash
		item.SkipWorktree = skipped(held, name)
		if item.SkipWorktree {
			idx.Version = 3
		}
	}
	var data bytes.Buffer
	if err := index.NewEncoder(&data).Encode(idx); err != nil {
		return err
	}
	return e.write(gitDir+"/index", data.Bytes())
}

func (e *capturedStageEngine) writeConfig(gitDir string, source *gitconfig.Config, rec *CopyRecord) error {
	cfg := gitconfig.New()
	cfg.SetOption("core", "", "repositoryformatversion", "0")
	cfg.SetOption("core", "", "bare", "false")
	cfg.SetOption("core", "", "filemode", "false")
	cfg.SetOption("core", "", "autocrlf", "false")
	for key, value := range e.settings.lineEndings {
		cfg.SetOption("core", "", strings.TrimPrefix(key, "core."), value)
	}
	rec.Remotes = map[string]string{}
	if source != nil {
		for _, section := range source.Sections {
			if !section.IsName("remote") {
				continue
			}
			for _, remote := range section.Subsections {
				if remote.Name == withheldRemote || len(remote.Name) > 255 || plumbing.ReferenceName("refs/remotes/"+remote.Name+"/fixed").Validate() != nil {
					return capturedRefuse("invalid_remote_name")
				}
				urls := remote.Options.GetAll("url")
				if len(urls) > 1 {
					return capturedRefuse("multiple_remote_urls_not_supported")
				}
				if len(urls) == 0 {
					continue
				}
				safe, ok := sanitizeRemoteURL(urls[0])
				if !ok {
					rec.Warnings = append(rec.Warnings, "remote "+remote.Name+" is a local path and is not configured in the copy")
					continue
				}
				rec.Remotes[remote.Name] = safe
				cfg.SetOption("remote", remote.Name, "url", safe)
				cfg.SetOption("remote", remote.Name, "fetch", "+refs/heads/*:refs/remotes/"+remote.Name+"/*")
			}
		}
	}
	if rec.Withheld > 0 {
		cfg.SetOption("core", "", "repositoryformatversion", "1")
		cfg.SetOption("extensions", "", "partialclone", withheldRemote)
		cfg.SetOption("pack", "", "window", "0")
	}
	if source != nil && strings.HasPrefix(rec.Branch, "refs/heads/") {
		branch := strings.TrimPrefix(rec.Branch, "refs/heads/")
		section := source.Section("branch").Subsection(branch)
		remote := section.Options.Get("remote")
		if _, kept := rec.Remotes[remote]; kept {
			cfg.SetOption("branch", branch, "remote", remote)
			if merge := section.Options.Get("merge"); merge != "" {
				if err := plumbing.ReferenceName(merge).Validate(); err != nil {
					return capturedRefuse("invalid_branch_merge_reference")
				}
				cfg.SetOption("branch", branch, "merge", merge)
			}
		}
	}
	var data bytes.Buffer
	if err := gitconfig.NewEncoder(&data).Encode(cfg); err != nil {
		return err
	}
	return e.write(gitDir+"/config", data.Bytes())
}
