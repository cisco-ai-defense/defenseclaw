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

package gateway

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Reason codes of the skill pass (B5.4, GAP-0477). They go in the code field
// of a substrate_quarantine entry and in the reason of the audit rows below.
const (
	SkillReasonFinding     = "skill_finding"
	SkillReasonPending     = "skill_pending"
	SkillReasonScannerDown = "skill_scanner_down"
	SkillReasonScanTimeout = "skill_scan_timeout"
	SkillReasonScannerBusy = "skill_scanner_busy"
	SkillReasonScanFailed  = "skill_scan_failed"
	SkillReasonTooBig      = "skill_too_big"
	SkillReasonNotSent     = "skill_not_sent"
	SkillReasonArchive     = "skill_archive"
)

// Audit actions of the skill pass (B5.4): the passed side as well as the
// refused one, so an admin sees every folder that was checked.
const (
	AuditSkillScanned   = "substrate.skill.scanned"
	AuditSkillBlocked   = "substrate.skill.blocked"
	AuditSkillUnscanned = "substrate.skill.unscanned"
	AuditSkillPending   = "substrate.skill.pending"
)

var (
	// errSkillPending: the scan is still running after skills.pending_wait.
	// It goes on in the background; the kit sends the folder again with its
	// next hook and gets the verdict then.
	errSkillPending = errors.New("substrate: the skill is still being checked")
	// ErrSubstrateSkillScanTimeout: the scan did not finish inside
	// skills.scan.timeout (in the gateway or in the scanner sidecar).
	ErrSubstrateSkillScanTimeout = errors.New("substrate: the skill scan did not finish in time")
	// errSkillScannerBusy: no scan slot came free inside skills.pending_wait
	// (GAP-0932); never an allow as scanned.
	errSkillScannerBusy = errors.New("substrate: the skill scanner is busy")
)

// substrateSkillScansInFlight bounds the scans running on one replica (the
// sidecar queues 32), and substrateSkillScansPerActor one actor's share of
// them (GAP-0932: one post carries at most 8 folders), so one actor cannot
// keep every other actor's folders from being scanned. Past either a new
// folder waits for a slot inside pending_wait, then is skill_scanner_busy.
const (
	substrateSkillScansInFlight = 32
	substrateSkillScansPerActor = substrateSkillFoldersMax
)

// skillScanCall is one scan of one folder content; hooks of any actor that
// bring the same content while it runs wait for the same call.
type skillScanCall struct {
	done    chan struct{}
	blocked bool
	reason  string
	err     error
	took    time.Duration
	// keep: a managed or strict post stopped waiting for it (the folder is
	// held), so its outcome is kept for the next post (scanKept).
	keep bool
}

// skillScanKept is the kept outcome of a held folder's scan.
type skillScanKept struct {
	res skillScanResult
	at  time.Time
}

// substrateSkillKeptMax bounds scanKept and heldSince; skillKeptTTL is how
// long a kept outcome waits for the next post (the longest skills.scan.timeout).
const (
	substrateSkillKeptMax = 512
	skillKeptTTL          = 10 * time.Minute
)

// skillScanResult is what one hook learns from a scan.
type skillScanResult struct {
	blocked bool
	reason  string
	err     error
	took    time.Duration
	waited  time.Duration
}

// skillScanKey names a folder content: the folder path and every file.
func skillScanKey(name, dir string, files []SubstrateAttachedFile) string {
	h := sha256.New()
	h.Write([]byte(name + "\x00" + dir + "\x00"))
	for _, f := range files {
		h.Write([]byte(f.Path + "\x00" + strconv.Itoa(len(f.Content)) + "\x00" + strconv.FormatBool(f.Truncated) + "\x00"))
		h.Write(f.Content)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// blocksUnscanned: managed installs and the strict tier refuse a skill
// folder DefenseClaw could not scan (the hook fail mode, GAP-0039).
func (st *substrateState) blocksUnscanned(connector string) bool {
	return st.cfg.BlockUnscannedSkills != nil && st.cfg.BlockUnscannedSkills(connector)
}

// skillPostWait is how long one hook post waits for the scans of its
// folders, in every tier: skills.pending_wait (GAP-0980, GAP-0982). It is
// one deadline for the whole post (the wait for a scan slot and every folder,
// scanned in parallel), under the kit's first attempt (9 s), so a post is
// always answered: a folder still being scanned then is pending, its scan
// goes on (skills.scan.timeout) and a later post gets the verdict. 0 without
// limits (tests, or no config): the post waits for the scans.
func (st *substrateState) skillPostWait() time.Duration {
	if st.cfg.SkillScanLimits == nil {
		return 0
	}
	_, wait := st.cfg.SkillScanLimits()
	return wait
}

// skillPostStartKey holds when the gateway took the hook post
// (withSkillPostStart): the write gate and the folder pass share the post's
// one deadline.
type skillPostStartKey struct{}

func withSkillPostStart(ctx context.Context) context.Context {
	return context.WithValue(ctx, skillPostStartKey{}, time.Now())
}

// skillPostUntil is the post's scan deadline (skillPostWait from the post's
// start) and its cancel; nil (wait for the scans) without limits or when
// the call scans nothing (scans false).
func (st *substrateState) skillPostUntil(ctx context.Context, scans bool) (<-chan struct{}, context.CancelFunc) {
	wait := st.skillPostWait()
	if wait <= 0 || !scans {
		return nil, func() {}
	}
	start, ok := ctx.Value(skillPostStartKey{}).(time.Time)
	if !ok {
		start = time.Now()
	}
	pctx, cancel := context.WithDeadline(ctx, start.Add(wait))
	return pctx.Done(), cancel
}

// scanSkillFolder scans one folder inside skills.scan.timeout and waits for
// the scan until the post's deadline (until; nil waits for the whole scan).
// The scan runs detached from the hook, so a hook that stops waiting leaves
// it running; its verdict is cached by the runtime scanner, and a post that
// brings the same content while it runs waits for the same call.
// keep (managed, strict: the folder is held while pending) bounds the hold
// (GAP-0980): the outcome of a scan that ends after the post left is kept
// for the next post (a timeout or a dead scanner then goes to the fail mode,
// never a new scan that holds it again), and the content is held at most
// skills.scan.timeout from the first post that brought it.
func (st *substrateState) scanSkillFolder(ctx context.Context, until <-chan struct{}, keep bool, name, dir string, files []SubstrateAttachedFile) skillScanResult {
	var timeout time.Duration
	if st.cfg.SkillScanLimits != nil {
		timeout, _ = st.cfg.SkillScanLimits()
	}
	start := time.Now()
	actor, _ := substrateActorFrom(ctx)
	key := skillScanKey(name, dir, files)
	st.scanMu.Lock()
	c, ok := st.scans[key]
	if !ok && keep {
		if k, found := st.scanKept[key]; found {
			delete(st.scanKept, key)
			delete(st.heldSince, key)
			st.scanMu.Unlock()
			if time.Since(k.at) <= skillKeptTTL {
				k.res.waited = time.Since(start)
				return k.res
			}
			st.scanMu.Lock()
		}
	}
	for !ok && (len(st.scans) >= substrateSkillScansInFlight || st.scanActors[actor.UID] >= substrateSkillScansPerActor) {
		if st.scanFree == nil {
			st.scanFree = make(chan struct{})
		}
		free := st.scanFree
		st.scanMu.Unlock()
		select {
		case <-free:
		case <-until:
			return st.skillHeld(ctx, keep, key, timeout, skillScanResult{err: errSkillScannerBusy, waited: time.Since(start)})
		case <-ctx.Done():
			return skillScanResult{err: errSkillPending, waited: time.Since(start)}
		}
		st.scanMu.Lock()
		c, ok = st.scans[key]
	}
	if !ok {
		if st.scans == nil {
			st.scans = map[string]*skillScanCall{}
			st.scanActors = map[string]int{}
		}
		c = &skillScanCall{done: make(chan struct{})}
		st.scans[key] = c
		st.scanActors[actor.UID]++
		sctx := context.WithoutCancel(ctx)
		cancel := context.CancelFunc(func() {})
		if timeout > 0 {
			scanFor := timeout
			if since, held := st.heldSince[key]; keep && held {
				// Held already (no scan slot came free): the hold ends at
				// skills.scan.timeout from the first post, not from now.
				scanFor = max(timeout-time.Since(since), time.Millisecond)
			}
			sctx, cancel = context.WithTimeout(sctx, scanFor)
		}
		go func() {
			defer cancel()
			start := time.Now()
			c.blocked, c.reason, c.err = st.cfg.Skills.ScanSkillFolder(sctx, name, dir, files)
			c.took = time.Since(start)
			if sctx.Err() != nil {
				// Past the timeout nothing the scan said is a verdict.
				c.blocked, c.reason, c.err = false, "", ErrSubstrateSkillScanTimeout
			}
			st.scanMu.Lock()
			delete(st.scans, key)
			if c.keep {
				st.keepSkillScanLocked(key, skillScanResult{blocked: c.blocked, reason: c.reason, err: c.err, took: c.took})
			}
			if st.scanActors[actor.UID]--; st.scanActors[actor.UID] <= 0 {
				delete(st.scanActors, actor.UID)
			}
			if st.scanFree != nil {
				close(st.scanFree)
				st.scanFree = nil
			}
			// Closed under scanMu, so a post that stops waiting either sees
			// it done or marks it keep before the outcome is kept.
			close(c.done)
			st.scanMu.Unlock()
		}()
	}
	st.scanMu.Unlock()
	select {
	case <-c.done:
		if keep {
			st.scanMu.Lock()
			delete(st.scanKept, key)
			delete(st.heldSince, key)
			st.scanMu.Unlock()
		}
		return skillScanResult{blocked: c.blocked, reason: c.reason, err: c.err, took: c.took, waited: time.Since(start)}
	case <-until:
	case <-ctx.Done():
	}
	if keep {
		st.scanMu.Lock()
		select {
		case <-c.done:
			// It ended just now: this post has the outcome, keep none.
			st.scanMu.Unlock()
			return skillScanResult{blocked: c.blocked, reason: c.reason, err: c.err, took: c.took, waited: time.Since(start)}
		default:
		}
		c.keep = true
		st.scanMu.Unlock()
	}
	return st.skillHeld(ctx, keep, key, timeout, skillScanResult{err: errSkillPending, waited: time.Since(start)})
}

// skillHeld records when a held (keep) content was first held and turns a
// hold that has lasted skills.scan.timeout into a scan timeout, so the fail
// mode decides (GAP-0980). Without keep it returns res unchanged.
func (st *substrateState) skillHeld(ctx context.Context, keep bool, key string, timeout time.Duration, res skillScanResult) skillScanResult {
	if !keep {
		return res
	}
	first, ok := ctx.Value(skillPostStartKey{}).(time.Time)
	if !ok {
		first = time.Now()
	}
	st.scanMu.Lock()
	defer st.scanMu.Unlock()
	if since, held := st.heldSince[key]; held {
		first = since
	} else {
		if st.heldSince == nil {
			st.heldSince = map[string]time.Time{}
		}
		if len(st.heldSince) >= substrateSkillKeptMax {
			for k, t := range st.heldSince {
				if time.Since(t) > skillKeptTTL {
					delete(st.heldSince, k)
				}
			}
		}
		if len(st.heldSince) < substrateSkillKeptMax {
			st.heldSince[key] = first
		}
	}
	if timeout > 0 && time.Since(first) >= timeout {
		delete(st.heldSince, key)
		res.err = ErrSubstrateSkillScanTimeout
	}
	return res
}

// keepSkillScanLocked keeps a held folder's scan outcome for its next post
// (bounded; an entry past skillKeptTTL is dropped). st.scanMu is held.
func (st *substrateState) keepSkillScanLocked(key string, res skillScanResult) {
	if st.scanKept == nil {
		st.scanKept = map[string]skillScanKept{}
	}
	if len(st.scanKept) >= substrateSkillKeptMax {
		for k, v := range st.scanKept {
			if time.Since(v.at) > skillKeptTTL {
				delete(st.scanKept, k)
			}
		}
	}
	if len(st.scanKept) < substrateSkillKeptMax {
		st.scanKept[key] = skillScanKept{res: res, at: time.Now()}
	}
}

// skillScanErrCode is the reason code and the plain reason of a scan that
// gave no verdict.
func skillScanErrCode(err error) (code, why string) {
	switch {
	case errors.Is(err, errSkillPending):
		return SkillReasonPending, "DefenseClaw is still checking the skill"
	case errors.Is(err, ErrSubstrateSkillScanTimeout):
		return SkillReasonScanTimeout, "the skill scan did not finish in time"
	case errors.Is(err, errSkillScannerBusy):
		return SkillReasonScannerBusy, "the skill scanner is busy with other skills"
	case errors.Is(err, ErrSubstrateSkillScannerUnavailable):
		return SkillReasonScannerDown, "the skill scanner is not running"
	}
	return SkillReasonScanFailed, "the skill scan could not complete"
}

// skillPendingMessage is the hook reply for a use refused while the scan runs.
func skillPendingMessage(name string) string {
	return fmt.Sprintf("DefenseClaw is still checking the skill %q. Try again in a few seconds.", name)
}

// skillHeldMessage is the hook reply of a managed or strict call refused
// while folders it can reach are still being checked (GAP-0980).
func skillHeldMessage(held []SubstrateUnscanned) string {
	names := make([]string, 0, len(held))
	for _, h := range held {
		names = append(names, strconv.Quote(path.Base(path.Clean("/"+strings.TrimPrefix(h.Path, "/")))))
	}
	return fmt.Sprintf("%s is still being scanned; DefenseClaw refuses tool calls until the scan finishes. Try again in a few seconds.", strings.Join(names, ", "))
}

// skillBlockedMessage is the reason of a folder the scan refused: the kit
// moves it to <root>/../.defenseclaw-quarantine/.
func skillBlockedMessage(dir, reason string) string {
	q := path.Join(path.Dir(path.Dir(dir)), ".defenseclaw-quarantine")
	return fmt.Sprintf("DefenseClaw blocked the skill %q: %s. It was moved to %s.", path.Base(dir), reason, q)
}

// auditSkill writes one skill audit row per actor, folder, fingerprint and
// action (bounded memory, as alertOnce), so a folder named in every hook
// post is recorded once per outcome.
func (st *substrateState) auditSkill(ctx context.Context, action, severity, connector, dir string, f *SubstrateFacts, extra map[string]any) {
	if st.action == nil {
		return
	}
	actor, _ := substrateActorFrom(ctx)
	fp := ""
	if f != nil {
		for _, s := range f.Skills {
			if path.Clean("/"+s.Path) == dir {
				fp = s.FP
			}
		}
	}
	key := "audit\x00" + action + "\x00" + actor.UID + "\x00" + dir + "\x00" + fp + "\x00" + fmt.Sprint(extra["outcome"])
	st.alertMu.Lock()
	if st.alerted == nil || len(st.alerted) >= substrateAlertMemory {
		st.alerted = map[string]bool{}
	}
	seen := st.alerted[key]
	st.alerted[key] = true
	st.alertMu.Unlock()
	if seen {
		return
	}
	details := map[string]any{"actor_uid": actor.UID, "atespace": actor.Atespace, "actor": actor.Name,
		"connector": connector, "folder": dir, "skill": path.Base(dir), "fingerprint": fp}
	for k, v := range extra {
		details[k] = v
	}
	st.action(ctx, action, severity, details)
}

// skillArchiveMagic are the leading bytes of archive and compression
// formats (gzip, xz, zstd, lz4, ar) that no text file starts with; at offset
// 257 a tar header says "ustar", and a cpio archive starts with a whole
// ASCII header (skillCPIOHeader). skillArchiveAnywhere are the headers found
// anywhere in a file (GAP-0933): a zip local, central or end record, and the
// rar and 7z signatures, so a script with an archive appended or a
// self-extracting archive is found too. skillArchiveShortMagic (lzma, cpio
// binary and ASCII magic, bzip2 in skillArchiveFile) and the name rule
// skillArchiveExt are short or name-only, so they count only for a binary
// file: a text file named messages.ar or README.pt.br, or a CSV that starts
// 070701, is not an archive (GAP-0981).
var (
	skillArchiveMagic = [][]byte{
		{0x1f, 0x8b}, {0xfd, '7', 'z', 'X', 'Z', 0x00}, {0x28, 0xb5, 0x2f, 0xfd}, {0x04, 0x22, 0x4d, 0x18}, []byte("!<arch>\n"),
	}
	skillArchiveShortMagic = [][]byte{
		{0x5d, 0x00, 0x00}, []byte("070701"), []byte("070702"), []byte("070707"), {0xc7, 0x71},
	}
	skillArchiveAnywhere = [][]byte{
		[]byte("PK\x03\x04"), []byte("PK\x01\x02"), []byte("PK\x05\x06"), []byte("PK\x07\x08"),
		[]byte("Rar!\x1a\x07"), {'7', 'z', 0xbc, 0xaf, 0x27, 0x1c},
	}
	// skillArchiveExt are archive file names (binary files only).
	skillArchiveExt = map[string]bool{
		".zip": true, ".jar": true, ".war": true, ".ear": true, ".apk": true, ".whl": true, ".egg": true, ".nupkg": true,
		".vsix": true, ".xpi": true, ".crx": true, ".tar": true, ".tgz": true, ".gz": true, ".bz2": true, ".tbz": true,
		".tbz2": true, ".xz": true, ".txz": true, ".zst": true, ".tzst": true, ".lz4": true, ".lzma": true, ".lz": true,
		".7z": true, ".rar": true, ".cpio": true, ".ar": true, ".deb": true, ".rpm": true, ".cab": true, ".iso": true,
		".dmg": true, ".z": true, ".sz": true, ".br": true,
		".docx": true, ".docm": true, ".xlsx": true, ".xlsm": true, ".pptx": true, ".pptm": true, ".odt": true, ".ods": true, ".odp": true,
	}
	// skillScannerZipExt are the zip formats the skill scanner opens and
	// scans inside (skill-scanner content_extractor ZIP_EXTENSIONS).
	skillScannerZipExt = map[string]bool{
		".zip": true, ".jar": true, ".war": true, ".apk": true, ".docx": true, ".docm": true, ".xlsx": true, ".xlsm": true,
		".pptx": true, ".pptm": true, ".odt": true, ".ods": true, ".odp": true,
	}
)

// skillArchiveScanMax bounds the bytes of one file searched for archive
// headers (the kit attaches at most substrateAttachedMaxBytes per post).
const skillArchiveScanMax = substrateAttachedMaxBytes

// skillArchiveListMax bounds the bytes a tar is read through (decompressed)
// to list its members, and skillGzipMax the payload of a plain .gz the
// gateway unpacks for the scan.
const (
	skillArchiveListMax = 8 << 20
	skillGzipMax        = 1 << 20
)

// skillArchiveFile is the first file of a folder that is an archive the scan
// could not look inside, as a path inside the folder; "" when there is none.
// See skillArchiveFileFrom.
func skillArchiveFile(dir string, files []SubstrateAttachedFile) string {
	return skillArchiveFileFrom(dir, files, nil)
}

// skillArchiveFileFrom is skillArchiveFile for files that include the
// payloads of plain .gz files the gateway unpacked for the scan
// (skillExpandGzip; from maps a payload to its .gz). An archive is found by
// its leading bytes, a header anywhere in it or, for a binary file, its name
// or a short magic. The static analyzers read files as they are, so a clean
// verdict says nothing of what an archive holds (B5.4 skill_archive): the
// fail mode decides. Not counted: a zip or tar the skill scanner itself
// opens and scans inside (skillScannerOpens), and a .gz whose payload was
// scanned (the payload is checked in its place, and named by its .gz). The
// search is linear in the attached bytes and bounded by skillArchiveScanMax.
func skillArchiveFileFrom(dir string, files []SubstrateAttachedFile, from map[string]string) string {
	unpacked := make(map[string]bool, len(from))
	for _, gz := range from {
		unpacked[gz] = true
	}
	for _, f := range files {
		if unpacked[f.Path] || !skillArchiveHit(f) {
			continue
		}
		p := f.Path
		if gz, ok := from[p]; ok {
			p = gz
		}
		return strings.TrimPrefix(path.Clean("/"+strings.TrimPrefix(p, "/")), dir+"/")
	}
	return ""
}

// skillArchiveHit reports whether one attached file is an archive the scan
// could not look inside.
func skillArchiveHit(f SubstrateAttachedFile) bool {
	c := f.Content
	if len(c) > skillArchiveScanMax {
		c = c[:skillArchiveScanMax]
	}
	if len(c) == 0 || (!f.Truncated && skillScannerOpens(f.Path, f.Content)) {
		return false
	}
	if (len(c) >= 262 && bytes.Equal(c[257:262], []byte("ustar"))) || skillCPIOHeader(c) {
		return true
	}
	for _, m := range skillArchiveMagic {
		if bytes.HasPrefix(c, m) {
			return true
		}
	}
	for _, m := range skillArchiveAnywhere {
		if bytes.Contains(c, m) {
			return true
		}
	}
	if skillTextContent(c, f.Truncated || len(c) < len(f.Content)) {
		return false
	}
	if skillArchiveExt[strings.ToLower(path.Ext(f.Path))] ||
		(len(c) >= 4 && bytes.HasPrefix(c, []byte("BZh")) && c[3] >= '1' && c[3] <= '9') {
		return true
	}
	for _, m := range skillArchiveShortMagic {
		if bytes.HasPrefix(c, m) {
			return true
		}
	}
	return false
}

// skillTextContent reports whether c is text: valid UTF-8 with no NUL byte
// (a rune cut at the end of a cut file does not count).
func skillTextContent(c []byte, cut bool) bool {
	if bytes.IndexByte(c, 0) >= 0 {
		return false
	}
	if utf8.Valid(c) {
		return true
	}
	for i := 0; cut && i < utf8.UTFMax-1 && len(c) > 0; i++ {
		if c = c[:len(c)-1]; utf8.Valid(c) {
			return true
		}
	}
	return false
}

// skillCPIOHeader reports whether c starts with a whole cpio ASCII header:
// newc or crc ("070701", "070702" and 104 hex digits) or odc ("070707" and
// 70 octal digits). A text file that only starts with the magic is not one.
func skillCPIOHeader(c []byte) bool {
	digits, n := "0123456789abcdefABCDEF", 110
	switch {
	case bytes.HasPrefix(c, []byte("070701")), bytes.HasPrefix(c, []byte("070702")):
	case bytes.HasPrefix(c, []byte("070707")):
		digits, n = "01234567", 76
	default:
		return false
	}
	if len(c) < n {
		return false
	}
	for _, b := range c[6:n] {
		if strings.IndexByte(digits, b) < 0 {
			return false
		}
	}
	return true
}

// skillScannerOpens reports whether the skill scanner opens this file and
// scans what it holds (its content extractor): a zip format (zip, jar, war,
// apk, Office and OpenDocument) or a tar (.tar, .tar.gz, .tgz, .tar.bz2)
// whose name and content agree, that Go opens too, whose zip entries are
// neither encrypted nor compressed in a way it does not read, and that holds
// no archive the scanner does not open (only the scanner's own formats are
// unpacked inside it). A .tar.xz is not checked here and stays skill_archive.
func skillScannerOpens(name string, c []byte) bool {
	lower := strings.ToLower(path.Base(name))
	switch {
	case skillScannerZipExt[path.Ext(lower)]:
		if !bytes.HasPrefix(c, []byte("PK\x03\x04")) {
			return false
		}
		zr, err := zip.NewReader(bytes.NewReader(c), int64(len(c)))
		if err != nil {
			return false
		}
		for _, e := range zr.File {
			if e.Flags&0x1 != 0 || (e.Method != zip.Store && e.Method != zip.Deflate) || !skillMemberOK(e.Name) {
				return false
			}
		}
		return true
	case strings.HasSuffix(lower, ".tar"):
		return skillTarMembersOK(bytes.NewReader(c))
	case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
		zr, err := gzip.NewReader(bytes.NewReader(c))
		if err != nil {
			return false
		}
		return skillTarMembersOK(zr)
	case strings.HasSuffix(lower, ".tar.bz2"):
		if !bytes.HasPrefix(c, []byte("BZh")) {
			return false
		}
		return skillTarMembersOK(bzip2.NewReader(bytes.NewReader(c)))
	}
	return false
}

// skillMemberOK reports whether an archive member's name is not an archive
// the scanner leaves unopened.
func skillMemberOK(name string) bool {
	lower := strings.ToLower(path.Base(name))
	ext := path.Ext(lower)
	if !skillArchiveExt[ext] {
		return true
	}
	return skillScannerZipExt[ext] || ext == ".tar" || ext == ".tgz" ||
		strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tar.bz2")
}

// skillTarMembersOK reads a tar to its end (at most skillArchiveListMax
// bytes) and reports whether it is whole and every member name passes
// skillMemberOK.
func skillTarMembersOK(r io.Reader) bool {
	lr := &io.LimitedReader{R: r, N: skillArchiveListMax}
	tr := tar.NewReader(lr)
	members := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return members > 0 && lr.N > 0
		}
		if err != nil || !skillMemberOK(h.Name) {
			return false
		}
		members++
	}
}

// skillExpandGzip returns a folder's files with the payload of each plain
// .gz file (not a .tar.gz or .tgz, which the scanner opens) added for the
// scan, at the .gz path without ".gz", and a map from each payload to its
// .gz (GAP-0981: managed installs scan the payload instead of refusing the
// .gz as skill_archive). A payload is added only when the .gz is whole and
// unpacks to at most skillGzipMax bytes, and no file of the folder has its
// path; otherwise the .gz stays an archive. The .gz header's own file name
// is never used.
func skillExpandGzip(dir string, files []SubstrateAttachedFile) ([]SubstrateAttachedFile, map[string]string) {
	var add []SubstrateAttachedFile
	var from map[string]string
	have := make(map[string]bool, len(files))
	for _, f := range files {
		have[f.Path] = true
	}
	for _, f := range files {
		lower := strings.ToLower(f.Path)
		if f.Truncated || !strings.HasSuffix(lower, ".gz") || strings.HasSuffix(lower, ".tar.gz") || !bytes.HasPrefix(f.Content, []byte{0x1f, 0x8b}) {
			continue
		}
		p := f.Path[:len(f.Path)-len(".gz")]
		if have[p] || path.Clean(p) != p || !strings.HasPrefix(p, dir+"/") || strings.HasSuffix(p, "/") {
			continue
		}
		zr, err := gzip.NewReader(bytes.NewReader(f.Content))
		if err != nil {
			continue
		}
		payload, err := io.ReadAll(io.LimitReader(zr, skillGzipMax+1))
		if err != nil || len(payload) > skillGzipMax {
			continue
		}
		sum := sha256.Sum256(payload)
		have[p] = true
		add = append(add, SubstrateAttachedFile{Role: f.Role, Path: p, Size: int64(len(payload)), SHA256: hex.EncodeToString(sum[:]), Content: payload})
		if from == nil {
			from = map[string]string{}
		}
		from[p] = f.Path
	}
	if len(add) == 0 {
		return files, nil
	}
	return append(append(make([]SubstrateAttachedFile, 0, len(files)+len(add)), files...), add...), from
}

// skillArchiveMessage is the reason of a folder with an archive in it.
func skillArchiveMessage(file, name string) string {
	return fmt.Sprintf("DefenseClaw could not look inside %q in the skill %q", file, name)
}

// skillPendingAskMessage is the OSS ask for a use while the scan runs.
func skillPendingAskMessage(name string) string {
	return fmt.Sprintf("DefenseClaw is still checking the skill %q. Use it anyway?", name)
}

// skillAskConnectors are the connectors whose PreToolUse answer can ask the
// person (Claude Code: permissionDecision ask) and that reach the use gate
// (their Skill tool and skill reads run the folder pass).
var skillAskConnectors = map[string]bool{"claudecode": true}

// substrateSkillUseGate is the use gate of a PreToolUse call that uses a
// folder this call's own pass decided (the kit runs the pass for the Claude
// Code Skill tool and for reads of skill files). Managed installs and the
// strict tier refuse a use of a folder the pass refused (GAP-0931: the kit
// moves it, and the call that brought it does not run either), and refuse
// every PreToolUse call while a folder is still being checked (sk.held,
// GAP-0980).
// The OSS tiers add no block: a use of a folder still being scanned asks
// where the agent can ask (sk.ask) and a person is there, and else (other
// agents, unattended runs) is allowed with a MEDIUM alert, as rel (B5.4
// skill_pending). It returns the refusal message, or "".
func (st *substrateState) substrateSkillUseGate(ctx context.Context, env substrateEnvelope, sk *substrateSkillAnswer) string {
	if len(sk.pending) == 0 && len(sk.Quarantine) == 0 {
		return ""
	}
	if pre, _ := substrateMCPEvent(env.Event); !pre {
		return ""
	}
	if st.blocksUnscanned(env.Connector) {
		if len(sk.held) > 0 {
			// GAP-0980: a folder the agent can reach is still being checked
			// at the post's deadline. Every tool call is refused until it has
			// a verdict (the kit sends it again with each call), whatever the
			// connector and however the agent would use it.
			return skillHeldMessage(sk.held)
		}
		dirs := make([]string, 0, len(sk.Quarantine))
		for _, q := range sk.Quarantine {
			dirs = append(dirs, q.Path)
		}
		dir := skillUsedFolder(env, dirs)
		if dir == "" {
			return ""
		}
		for _, q := range sk.Quarantine {
			if path.Clean("/"+strings.TrimPrefix(q.Path, "/")) == dir {
				return skillUseRefusedMessage(path.Base(dir), q)
			}
		}
		return ""
	}
	if len(sk.pending) == 0 {
		return ""
	}
	dirs := make([]string, 0, len(sk.pending))
	for _, p := range sk.pending {
		dirs = append(dirs, p.Path)
	}
	dir := skillUsedFolder(env, dirs)
	if dir == "" {
		return ""
	}
	name := path.Base(dir)
	outcome := "allowed"
	// An unattended run never asks (D12, GAP-0935): it gets the alert.
	if reg, ok := substrateRegistrationFrom(ctx); skillAskConnectors[env.Connector] && (!ok || !reg.Unattended) {
		outcome, sk.ask = "asked", skillPendingAskMessage(name)
	}
	st.auditSkill(ctx, AuditSkillPending, "MEDIUM", env.Connector, dir, env.Facts, map[string]any{"reason": SkillReasonPending, "outcome": outcome})
	if outcome == "allowed" {
		st.alertOnce(ctx, "MEDIUM", "Substrate skill used while its scan runs: "+name, dir, env.Facts, nil)
	}
	return ""
}

// skillUseRefusedMessage is the hook reply for a use of a refused folder.
func skillUseRefusedMessage(name string, q SubstrateQuarantine) string {
	switch {
	case q.Code == SkillReasonPending:
		return skillPendingMessage(name)
	case strings.HasPrefix(q.Reason, "DefenseClaw "):
		return q.Reason
	}
	return fmt.Sprintf("DefenseClaw refused the skill %q: %s.", name, q.Reason)
}

// skillUsedFolder is the folder of dirs a PreToolUse call uses: the one the
// Skill tool names by its folder name or its SKILL.md frontmatter name (a
// plugin skill is "plugin:name"; case-insensitive), or the one holding a
// path the call names (Read file_path, NotebookRead notebook_path, as given
// or as the kit resolved it: relative paths and links); "" when the call
// uses none of them. These are the calls the kit runs the folder pass for
// (kit readTools, skillTools).
func skillUsedFolder(env substrateEnvelope, dirs []string) string {
	var ev struct {
		Tool  string         `json:"tool_name"`
		Input map[string]any `json:"tool_input"`
	}
	if json.Unmarshal(env.Payload, &ev) != nil {
		return ""
	}
	str := func(k string) string { s, _ := ev.Input[k].(string); return s }
	skill := ""
	if ev.Tool == "Skill" {
		if skill = str("skill"); skill == "" {
			skill = str("name")
		}
		if i := strings.LastIndex(skill, ":"); i >= 0 {
			skill = skill[i+1:]
		}
	}
	var named []string
	for _, k := range []string{"file_path", "notebook_path"} {
		if f := str(k); strings.HasPrefix(f, "/") {
			named = append(named, path.Clean(f))
		}
	}
	var folders map[string][]SubstrateAttachedFile
	if env.Facts != nil {
		for _, p := range env.Facts.Paths {
			for _, x := range []string{p.Abs, p.Resolved} {
				if strings.HasPrefix(x, "/") {
					named = append(named, path.Clean(x))
				}
			}
		}
		if skill != "" {
			folders = substrateSkillFolders(env.Facts)
		}
	}
	for _, d := range dirs {
		dir := path.Clean("/" + strings.TrimPrefix(d, "/"))
		if skill != "" && (strings.EqualFold(skill, path.Base(dir)) || strings.EqualFold(skill, skillFrontmatterName(dir, folders[dir]))) {
			return dir
		}
		for _, n := range named {
			if n == dir || strings.HasPrefix(n, dir+"/") {
				return dir
			}
		}
	}
	return ""
}

// skillFrontmatterName is the name: of the folder's SKILL.md frontmatter
// (the name the agent loads the skill by), read from its first 64 lines;
// "" when there is none.
func skillFrontmatterName(dir string, files []SubstrateAttachedFile) string {
	for _, f := range files {
		if path.Clean("/"+strings.TrimPrefix(f.Path, "/")) != dir+"/SKILL.md" {
			continue
		}
		lines := strings.SplitN(strings.TrimPrefix(string(f.Content), "\ufeff"), "\n", 65)
		if len(lines) == 0 || strings.TrimSpace(lines[0]) != "---" {
			return ""
		}
		for _, l := range lines[1:] {
			if strings.TrimSpace(l) == "---" {
				return ""
			}
			if k, v, ok := strings.Cut(l, ":"); ok && strings.TrimSpace(k) == "name" {
				return strings.Trim(strings.TrimSpace(v), `"'`)
			}
		}
	}
	return ""
}
