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

package manager

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/processutil"
)

// An agent in a plain container is found by its command's name first
// (agentProcess). A harness copied under another name (claude as cl2) runs
// no command of that name, so the processes of a container none of whose
// commands is a harness's are looked into by content (GAP-0689): a command
// line that names a harness's package, or a program or script, read from
// the container with docker cp (the engine's archive API: nothing runs in
// the container), that carries it. The package names are the AI signature
// catalog's scoped npm names (@anthropic-ai/claude-code, @openai/codex,
// ...): the harness's own files carry them, the native Claude Code and
// Codex builds included, and other programs do not; an unscoped name is too
// common a word to tell anything. What was read is remembered for the
// container's life: a process seen before is not read again, and a file
// only again once its size or time changed.
//
// The boundary: a program started under another name in its own process
// (exec -a), deleted once started, or found on no PATH the container
// declares is not read, and a container the scan budget did not reach is
// read at the next reconcile.

const (
	// contentScanTimeout bounds the content look-ups of one scan.
	contentScanTimeout = time.Minute
	// contentScanBytes bounds the bytes one scan reads; contentFileBytes
	// those of one file (the native Claude Code and Codex builds are
	// about 250 MiB).
	contentScanBytes = 1 << 30
	contentFileBytes = 512 << 20
	// contentScanReads bounds the docker runs (cp, inspect) of one scan.
	contentScanReads = 128
	// contentChunk is the read size of a file.
	contentChunk = 1 << 20
	// maxContentProcesses bounds the processes of one container looked at.
	maxContentProcesses = 256
	// maxContentRemembered bounds what one container's record remembers.
	maxContentRemembered = 4096
)

// defaultContainerPath is searched after the PATH a container declares.
var defaultContainerPath = []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"}

// contentMarker is a byte string only a harness's files carry.
type contentMarker struct {
	text    []byte
	harness string
}

// contentMarkers are the scoped package names of the harnesses in the
// built-in AI signature catalog.
var contentMarkers = sync.OnceValue(func() []contentMarker {
	sigs, err := inventory.LoadAISignatures()
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []contentMarker
	for _, sig := range sigs {
		if _, ok := harness.Get(sig.SupportedConnector); !ok {
			continue
		}
		for _, pkg := range sig.PackageNames {
			if len(pkg) < 4 || pkg[0] != '@' || !strings.Contains(pkg, "/") || seen[pkg] {
				continue
			}
			seen[pkg] = true
			out = append(out, contentMarker{text: []byte(pkg), harness: sig.SupportedConnector})
		}
	}
	return out
})

// markerHarness is the harness whose marker b carries, or "".
func markerHarness(b []byte, markers []contentMarker) string {
	for _, m := range markers {
		if bytes.Contains(b, m.text) {
			return m.harness
		}
	}
	return ""
}

// scanMarkers reads r, at most limit bytes, for a marker: the harness whose
// marker it carries ("" none), the bytes read and whether limit stopped the
// read before the end. A marker split across two reads is found.
func scanMarkers(r io.Reader, markers []contentMarker, limit int64) (string, int64, bool, error) {
	longest := 0
	for _, m := range markers {
		longest = max(longest, len(m.text))
	}
	if longest == 0 {
		return "", 0, false, nil
	}
	buf := make([]byte, longest-1+contentChunk)
	keep := 0
	var n int64
	for n < limit {
		want := int(min(int64(contentChunk), limit-n))
		k, err := io.ReadFull(r, buf[keep:keep+want])
		n += int64(k)
		window := buf[:keep+k]
		if h := markerHarness(window, markers); h != "" {
			return h, n, false, nil
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return "", n, false, nil
		}
		if err != nil {
			return "", n, false, err
		}
		keep = min(longest-1, len(window))
		copy(buf, window[len(window)-keep:])
	}
	return "", n, true, nil
}

// topProcess is one process of docker top's output.
type topProcess struct {
	pid  string
	uid  int
	args []string
}

// topProcesses parses docker top's output ("PID ARGS" lines after a
// header, or "PID UID ARGS" with withUID).
func topProcesses(top string, withUID bool) []topProcess {
	first := 1
	if withUID {
		first = 2
	}
	lines := strings.Split(top, "\n")
	var out []topProcess
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) <= first {
			continue
		}
		uid := -1
		if withUID {
			if n, err := strconv.Atoi(fields[1]); err == nil && n >= 0 {
				uid = n
			}
		}
		out = append(out, topProcess{pid: fields[0], uid: uid, args: fields[first:]})
		if len(out) == maxContentProcesses {
			break
		}
	}
	return out
}

// containerFile streams file of container id as docker cp writes it: a tar
// archive of the file, a link followed (a seam for tests).
var containerFile = func(ctx context.Context, bin, id, file string) (io.ReadCloser, error) {
	ctx, cancel := context.WithCancel(ctx)
	cmd := processutil.CommandContext(ctx, bin, "cp", "-L", id+":"+file, "-")
	out, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, err
	}
	return &commandStream{ReadCloser: out, wait: cmd.Wait, cancel: cancel}, nil
}

// commandStream is a command's output; Close ends the command.
type commandStream struct {
	io.ReadCloser
	wait   func() error
	cancel context.CancelFunc
}

func (c *commandStream) Close() error {
	c.cancel()
	_ = c.wait()
	return nil
}

// containerConfig is what docker inspect says of a container's commands:
// its PATH and working directory (a seam for tests).
var containerConfig = func(ctx context.Context, bin, id string) (pathDirs []string, workdir string, err error) {
	out, err := openshell.ExecRunner{}.Output(ctx, openshell.Command{Name: bin, Timeout: discoveryTimeout,
		Args: []string{"inspect", "--format", "{{json .Config}}", id}})
	if err != nil {
		return nil, "", err
	}
	var cfg struct {
		Env        []string `json:"Env"`
		WorkingDir string   `json:"WorkingDir"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out), &cfg); err != nil {
		return nil, "", err
	}
	for _, kv := range cfg.Env {
		if v, ok := strings.CutPrefix(kv, "PATH="); ok {
			pathDirs = strings.Split(v, ":")
		}
	}
	return pathDirs, cfg.WorkingDir, nil
}

// contentFile is what one read of a container's file found.
type contentFile struct {
	size    int64
	mod     time.Time
	harness string
}

// containerContent is what the content scans remember of one container.
type containerContent struct {
	// procs: a process (pid and command line) to the harness it runs ("").
	procs map[string]string
	// paths: a command's name to the file it resolved to ("" none).
	paths map[string]string
	// files: a file to what it held when read.
	files map[string]contentFile
	// pathDirs and workdir, once inspected.
	inspected bool
	pathDirs  []string
	workdir   string
}

var (
	// contentMu serializes the content scans and guards contentSeen.
	contentMu   sync.Mutex
	contentSeen = map[string]*containerContent{}
)

// contentScan is one scan's content look-ups, on a budget of their own.
type contentScan struct {
	ctx    context.Context
	cancel context.CancelFunc
	bin    string
	bytes  int64
	reads  int
}

func newContentScan(parent context.Context, bin string) *contentScan {
	contentMu.Lock()
	ctx, cancel := context.WithTimeout(parent, contentScanTimeout)
	return &contentScan{ctx: ctx, cancel: cancel, bin: bin}
}

// end forgets the containers that are not running (live: those the scan
// listed) and ends the scan.
func (s *contentScan) end(live map[string]bool) {
	s.cancel()
	for id := range contentSeen {
		if !live[id] {
			delete(contentSeen, id)
		}
	}
	contentMu.Unlock()
}

// spent reports a scan out of time, reads or bytes.
func (s *contentScan) spent() bool {
	return s.ctx.Err() != nil || s.reads >= contentScanReads || s.bytes >= contentScanBytes
}

// agent is the harness one of the container's processes runs by content,
// and the uid it runs as (-1 unknown), or "".
func (s *contentScan) agent(id, top string, withUID bool) (string, int) {
	markers := contentMarkers()
	if len(markers) == 0 {
		return "", -1
	}
	seen := contentSeen[id]
	if seen == nil || len(seen.procs) > maxContentRemembered || len(seen.files) > maxContentRemembered {
		seen = &containerContent{procs: map[string]string{}, paths: map[string]string{}, files: map[string]contentFile{}}
		contentSeen[id] = seen
	}
	for _, p := range topProcesses(top, withUID) {
		key := p.pid + "\x00" + strings.Join(p.args, " ")
		h, known := seen.procs[key]
		if !known {
			var done bool
			if h, done = s.process(id, seen, p.args, markers); !done {
				continue // out of budget: the next scan reads it
			}
			seen.procs[key] = h
		}
		if h != "" {
			return h, p.uid
		}
	}
	return "", -1
}

// process is the harness a process runs by content: its command line names
// the package, or its program or (an interpreter's) script carries it.
// done is false when the budget ran out before it was known.
func (s *contentScan) process(id string, seen *containerContent, args []string, markers []contentMarker) (h string, done bool) {
	if h := markerHarness([]byte(strings.Join(args, " ")), markers); h != "" {
		return h, true
	}
	names := args[:1]
	if len(args) > 1 && !strings.HasPrefix(args[1], "-") {
		names = args[:2]
	}
	for _, name := range names {
		h, done := s.command(id, seen, name, markers)
		if !done || h != "" {
			return h, done
		}
	}
	return "", true
}

// command is the harness the file a command's name resolves to carries.
func (s *contentScan) command(id string, seen *containerContent, name string, markers []contentMarker) (string, bool) {
	if file, ok := seen.paths[name]; ok {
		if file == "" {
			return "", true
		}
		h, _, done := s.file(id, seen, file, markers)
		return h, done
	}
	candidates, done := s.candidates(id, seen, name)
	if !done {
		return "", false
	}
	for _, file := range candidates {
		h, exists, done := s.file(id, seen, file, markers)
		if !done {
			return "", false
		}
		if exists {
			seen.paths[name] = file
			return h, true
		}
	}
	seen.paths[name] = ""
	return "", true
}

// candidates are the files a command's name may be: itself when absolute,
// under the working directory when relative, else on the container's PATH.
func (s *contentScan) candidates(id string, seen *containerContent, name string) ([]string, bool) {
	if strings.HasPrefix(name, "/") {
		return []string{path.Clean(name)}, true
	}
	if !seen.inspected {
		if s.spent() {
			return nil, false
		}
		s.reads++
		dirs, workdir, err := containerConfig(s.ctx, s.bin, id)
		if err != nil && s.ctx.Err() != nil {
			return nil, false
		}
		seen.inspected, seen.pathDirs, seen.workdir = true, dirs, workdir
	}
	if strings.Contains(name, "/") {
		return []string{path.Join("/", seen.workdir, name)}, true
	}
	var out []string
	known := map[string]bool{}
	for _, dir := range append(append([]string(nil), seen.pathDirs...), defaultContainerPath...) {
		if !strings.HasPrefix(dir, "/") {
			continue
		}
		if file := path.Join(dir, name); !known[file] {
			known[file] = true
			out = append(out, file)
		}
	}
	return out, true
}

// file reads one file of the container for a marker: the harness it
// carries, whether it exists, and done false when the budget ran out
// first. A file read before is read again only once its size or time
// changed.
func (s *contentScan) file(id string, seen *containerContent, file string, markers []contentMarker) (h string, exists, done bool) {
	if s.spent() {
		return "", false, false
	}
	s.reads++
	rc, err := containerFile(s.ctx, s.bin, id, file)
	if err != nil {
		return "", false, s.ctx.Err() == nil
	}
	defer rc.Close()
	tr := tar.NewReader(rc)
	hdr, err := tr.Next()
	if err != nil {
		// No such file (docker cp wrote nothing), unless the scan ran out.
		return "", false, s.ctx.Err() == nil
	}
	if hdr.Typeflag != tar.TypeReg {
		return "", true, true
	}
	if f, ok := seen.files[file]; ok && f.size == hdr.Size && f.mod.Equal(hdr.ModTime) {
		return f.harness, true, true
	}
	limit := min(int64(contentFileBytes), contentScanBytes-s.bytes)
	h, n, cut, err := scanMarkers(tr, markers, limit)
	s.bytes += n
	if err != nil || (cut && limit < contentFileBytes && n < hdr.Size) {
		return "", true, false // read again by the next scan
	}
	seen.files[file] = contentFile{size: hdr.Size, mod: hdr.ModTime, harness: h}
	return h, true, true
}
