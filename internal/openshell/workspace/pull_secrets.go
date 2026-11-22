package workspace

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// translatedRef holds the baseline as the operator's folder had it at the
// upload: the files uploaded with their credentials replaced (B1 S9a) carry
// the values again, so the pull's changes, its review and the 3-way apply
// measure only what the agent did, never a placeholder against a value.
const translatedRef = "refs/defenseclaw/translated"

// landingRef is the result a branch is made from when the pull's changes
// to files with replaced credentials stay out of it.
const landingRef = "refs/defenseclaw/landing"

// placeholderRE finds what looks like a placeholder; copyTokens keeps the
// ones the copy made.
var placeholderRE = regexp.MustCompile(`DC_SECRET_[0-9]+`)

// idxEntry is one path of a tree to write; an empty oid removes the path.
type idxEntry struct{ mode, oid string }

// heldResult is the sandbox result made safe to land: held-back paths
// reset, and the files uploaded with replaced credentials translated back.
type heldResult struct {
	effective string
	// translated is the baseline with the values back ("" when no file was
	// uploaded with replaced credentials, or none could be read).
	translated string
	// dropped are held-back paths the sandbox changed.
	dropped []string
	// restored are the replaced files whose change lands in the folder.
	restored []string
	// put are, per restored file, the lines where --restore-secret-lines
	// put a value back on a line the agent changed.
	put map[string]map[int]bool
	// notes say what happened to each replaced file the agent touched.
	notes []string
}

// dropHeldBack resets every held-back path in result to its baseline
// state (the sandbox never saw those files, so any change to them is a
// blind overwrite or deletion of an operator secret) and translates the
// files uploaded with replaced credentials back (translateSecrets).
func dropHeldBack(ctx context.Context, base gitCmd, rec *CopyRecord, result string, restore bool) (*heldResult, error) {
	out := &heldResult{effective: result}
	if len(rec.HeldBack) == 0 && len(rec.SecretLines) == 0 {
		return out, nil
	}
	changes, err := diffTrees(ctx, base, rec.Baseline, result)
	if err != nil {
		return nil, err
	}
	entries := map[string]idxEntry{}
	held := toSet(rec.HeldBack)
	for _, c := range changes {
		if skipped(held, c.Path) {
			out.dropped = append(out.dropped, c.Path)
			entries[c.Path] = idxEntry{c.OldMode, c.OldOID}
		}
	}
	sort.Strings(out.dropped)
	baseEntries := map[string]idxEntry{}
	if len(rec.SecretLines) > 0 {
		// A change that stays out keeps the file as the pull's changes start
		// from it: after an apply, the result that apply brought (sinceRef),
		// so what it brought is never undone.
		applied := refCommit(ctx, base, appliedRef)
		if err := translateSecrets(ctx, base, rec, changes, held, restore, applied, entries, baseEntries, out); err != nil {
			return nil, err
		}
	}
	if len(baseEntries) > 0 {
		if out.translated, err = commitWith(ctx, base, rec, rec.Baseline, baseEntries, "defenseclaw: baseline as the folder had it, with the replaced credentials"); err != nil {
			return nil, err
		}
	}
	if len(entries) > 0 {
		if out.effective, err = commitWith(ctx, base, rec, result, entries, "defenseclaw: sandbox result without changes to held-back files"); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// translateSecrets puts the operator's values back into the agent's
// version of each file uploaded with replaced credentials. The value is
// read from the local file, only where its lines are still as uploaded;
// a placeholder is never written anywhere. A line the agent left as it was
// gets the local line; a changed line holding a placeholder keeps the
// local line unless restore (--restore-secret-lines) puts the value back on
// the agent's line. A change that cannot land that way is dropped, with a
// note: the local file changed since the upload, a placeholder is gone
// (restore takes the agent's lines as they are), repeated or moved, or
// another file holds a placeholder.
func translateSecrets(ctx context.Context, base gitCmd, rec *CopyRecord, changes []TreeChange, held map[string]struct{}, restore bool, applied string, entries, baseEntries map[string]idxEntry, out *heldResult) error {
	byFile := map[string][]SecretLine{}
	var files []string
	tokens := map[string]bool{}
	for _, l := range rec.SecretLines {
		if _, ok := byFile[l.Rel]; !ok {
			files = append(files, l.Rel)
		}
		byFile[l.Rel] = append(byFile[l.Rel], l)
		tokens[placeholderRE.FindString(l.Placeholder)] = true
	}
	sort.Strings(files)
	uploaded, err := lsTree(ctx, base, rec.Baseline, files)
	if err != nil {
		return err
	}
	changed := map[string]TreeChange{}
	oids := []string{}
	for _, e := range uploaded {
		oids = append(oids, e.oid)
	}
	for _, c := range changes {
		if skipped(held, c.Path) {
			continue
		}
		changed[c.Path] = c
		if c.NewOID != "" && !c.Binary {
			oids = append(oids, c.NewOID)
		}
		if c.OldOID != "" && !c.Binary {
			oids = append(oids, c.OldOID)
		}
	}
	blobs, err := blobReader{g: base}.read(ctx, oids, DefaultScanMaxFileBytes)
	if err != nil {
		return err
	}
	write := func(b []byte) (string, error) {
		g := base
		g.stdin = bytes.NewReader(b)
		return g.line(ctx, "hash-object", "-w", "--stdin")
	}
	note := func(format string, a ...any) { out.notes = append(out.notes, fmt.Sprintf(format, a...)) }

	// The baseline as uploaded, with the values back: what the folder had.
	local := map[string][]byte{}
	values := map[string]map[string][]byte{}
	for _, rel := range files {
		e, ok := uploaded[rel]
		if !ok {
			continue
		}
		vals, ok := secretValues(rec.Project, rel, byFile[rel])
		if !ok {
			continue
		}
		b, ok := withValues(blobs[e.oid], byFile[rel], vals)
		if !ok {
			continue
		}
		oid, err := write(b)
		if err != nil {
			return err
		}
		local[rel], values[rel] = b, vals
		baseEntries[rel] = idxEntry{e.mode, oid}
	}
	// keep leaves the file as the pull's changes start from it (after an
	// apply, as that apply left it; else as the folder had it at the
	// upload): the change is not applied.
	var since map[string]idxEntry
	if applied != "" {
		var paths []string
		for _, c := range changes {
			paths = append(paths, c.Path)
		}
		if since, err = lsTree(ctx, base, applied, append(paths, files...)); err != nil {
			return err
		}
	}
	keep := func(rel string) {
		switch e, ok := baseEntries[rel]; {
		case applied != "":
			entries[rel] = since[rel]
		case ok:
			entries[rel] = e
		default:
			if e, ok := uploaded[rel]; ok {
				entries[rel] = e
			}
		}
	}
	for _, rel := range files {
		c, isChanged := changed[rel]
		if !isChanged {
			// Unchanged: the result carries the folder's version, as the
			// translated baseline does, so nothing shows as changed.
			keep(rel)
			continue
		}
		if _, ok := local[rel]; !ok {
			keep(rel)
			note("%s changed in your folder since the upload: the agent's change to it is not brought back (the file held replaced credentials)", rel)
			continue
		}
		if c.NewOID == "" || c.Status == "D" {
			if restore {
				out.restored = append(out.restored, rel)
				note("%s was deleted by the agent; --restore-secret-lines deletes it here too", rel)
				continue
			}
			keep(rel)
			note("%s was deleted by the agent: not brought back, as it held replaced credentials (--restore-secret-lines takes the deletion)", rel)
			continue
		}
		agent, ok := blobs[c.NewOID]
		if !ok || looksBinary(agent) {
			keep(rel)
			note("%s: the agent's version could not be read as text; its change is not brought back (the file held replaced credentials)", rel)
			continue
		}
		e := uploaded[rel]
		t, kept, put, why := translateReplaced(blobs[e.oid], agent, byFile[rel], restore)
		if why == "" {
			var ok bool
			if t, ok = withValues(t, nil, values[rel]); !ok || copyTokens(t, tokens) > copyTokens(local[rel], tokens) {
				why = "it holds a placeholder of another file"
			}
		}
		if why != "" {
			keep(rel)
			note("%s: the agent's change is not brought back: %s", rel, why)
			continue
		}
		oid, err := write(t)
		if err != nil {
			return err
		}
		entries[rel] = idxEntry{c.NewMode, oid}
		out.restored = append(out.restored, rel)
		for _, n := range kept {
			note("%s: kept your line %d; the agent changed the line that holds a replaced credential (--restore-secret-lines takes the agent's line)", rel, n)
		}
		if len(put) > 0 {
			if out.put == nil {
				out.put = map[string]map[int]bool{}
			}
			out.put[rel] = map[int]bool{}
			for _, n := range put {
				out.put[rel][n] = true
			}
		}
	}
	// A placeholder in any other file the agent touched would land as text:
	// that change stays out.
	var others []string
	for p, c := range changed {
		if _, ok := byFile[p]; ok || c.NewOID == "" {
			continue
		}
		after, ok := blobs[c.NewOID]
		if !ok || copyTokens(after, tokens) == 0 {
			continue
		}
		if copyTokens(after, tokens) > copyTokens(blobs[c.OldOID], tokens) {
			others = append(others, p)
			if applied != "" {
				entries[p] = since[p]
			} else {
				entries[p] = idxEntry{c.OldMode, c.OldOID}
			}
		}
	}
	sort.Strings(others)
	for _, p := range others {
		note("%s: the agent's change is not brought back: it holds a placeholder of a replaced credential (DC_SECRET_<n>)", p)
	}
	sort.Strings(out.restored)
	return nil
}

// lsTree lists the entries of paths in commit.
func lsTree(ctx context.Context, g gitCmd, commit string, paths []string) (map[string]idxEntry, error) {
	out := map[string]idxEntry{}
	if len(paths) == 0 {
		return out, nil
	}
	raw, err := g.output(ctx, append([]string{"ls-tree", "-z", "--full-tree", commit, "--"}, paths...)...)
	if err != nil {
		return nil, err
	}
	for _, rec := range splitNUL(raw) {
		meta, p, ok := strings.Cut(rec, "\t")
		f := strings.Fields(meta)
		if ok && len(f) == 3 && f[1] == "blob" {
			out[p] = idxEntry{f[0], f[2]}
		}
	}
	return out, nil
}

// commitWith commits from's tree with entries set, on top of from.
func commitWith(ctx context.Context, base gitCmd, rec *CopyRecord, from string, entries map[string]idxEntry, msg string) (string, error) {
	tmp := filepath.Join(filepath.Dir(rec.BaseGit), "effective-"+randomSuffix()+".index")
	defer os.Remove(tmp)
	g := base
	g.index = tmp
	if err := g.run(ctx, "read-tree", from); err != nil {
		return "", err
	}
	paths := make([]string, 0, len(entries))
	for p := range entries {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	var info bytes.Buffer
	for _, p := range paths {
		if e := entries[p]; e.oid == "" || e.mode == "" {
			fmt.Fprintf(&info, "0 %s\t%s\n", strings.Repeat("0", len(from)), p)
		} else {
			fmt.Fprintf(&info, "%s %s\t%s\n", e.mode, e.oid, p)
		}
	}
	g.stdin = &info
	if err := g.run(ctx, "update-index", "--index-info"); err != nil {
		return "", err
	}
	g.stdin = nil
	tree, err := g.line(ctx, "write-tree")
	if err != nil {
		return "", err
	}
	return g.line(ctx, "commit-tree", tree, "-p", from, "-m", msg)
}

// secretValues reads the values of rel's replaced credentials from the
// local file, by placeholder: only while every line that held one is as
// it was at the upload (LinesSHA256), at its line or once elsewhere.
func secretValues(project, rel string, lines []SecretLine) (map[string][]byte, bool) {
	b, err := readSmallRegular(filepath.Join(project, filepath.FromSlash(rel)), DefaultScanMaxFileBytes)
	if err != nil {
		return nil, false
	}
	starts := []int{0}
	for i, c := range b {
		if c == '\n' {
			starts = append(starts, i+1)
		}
	}
	// block is the l.Lines lines from line i (0-based) when they hash to
	// what was uploaded.
	block := func(l SecretLine, i int) []byte {
		last := i + l.Lines - 1
		if i < 0 || l.Lines < 1 || last >= len(starts) {
			return nil
		}
		end := len(b)
		if last+1 < len(starts) {
			end = starts[last+1] - 1
		}
		sum := sha256.Sum256(b[starts[i]:end])
		if hex.EncodeToString(sum[:]) != l.LinesSHA256 {
			return nil
		}
		return b[starts[i]:end]
	}
	vals := map[string][]byte{}
	for _, l := range lines {
		found := block(l, l.Line-1)
		if found == nil {
			// Lines added or removed above it (an earlier apply did that):
			// the same lines once anywhere in the file.
			for i := range starts {
				if f := block(l, i); f != nil {
					if found != nil {
						return nil, false
					}
					found = f
				}
			}
		}
		if found == nil || l.Column < 0 || l.Length <= 0 || l.Column+l.Length > len(found) {
			return nil, false
		}
		vals[l.Placeholder] = found[l.Column : l.Column+l.Length]
	}
	return vals, true
}

// tokenAt lists where p starts in b, as a whole placeholder (DC_SECRET_1
// is not the start of DC_SECRET_12).
func tokenAt(b []byte, p string) []int {
	var at []int
	for i := 0; ; {
		j := bytes.Index(b[i:], []byte(p))
		if j < 0 {
			return at
		}
		k := i + j + len(p)
		if k >= len(b) || b[k] < '0' || b[k] > '9' {
			at = append(at, i+j)
		}
		i = i + j + 1
	}
}

// withValues replaces each placeholder in b with its value. With lines
// set, each of their placeholders must occur exactly once.
func withValues(b []byte, lines []SecretLine, vals map[string][]byte) ([]byte, bool) {
	for _, l := range lines {
		if len(tokenAt(b, l.Placeholder)) != 1 {
			return nil, false
		}
	}
	ps := make([]string, 0, len(vals))
	for p := range vals {
		ps = append(ps, p)
	}
	// The env form contains the token form: the longer one first.
	sort.Slice(ps, func(i, j int) bool { return len(ps[i]) > len(ps[j]) })
	for _, p := range ps {
		at := tokenAt(b, p)
		if len(at) == 0 {
			continue
		}
		var o bytes.Buffer
		prev := 0
		for _, i := range at {
			o.Write(b[prev:i])
			o.Write(vals[p])
			prev = i + len(p)
		}
		o.Write(b[prev:])
		b = o.Bytes()
	}
	return b, true
}

// copyTokens counts the copy's placeholders in b.
func copyTokens(b []byte, tokens map[string]bool) int {
	n := 0
	for _, m := range placeholderRE.FindAll(b, -1) {
		if tokens[string(m)] {
			n++
		}
	}
	return n
}

// translateReplaced turns the agent's version of a replaced file into the
// one to land, placeholders still in (withValues puts the values in):
// each line that holds a placeholder is the uploaded line when the agent
// left it, or kept so (kept: the local line numbers), or with restore the
// agent's line (put: its line numbers). why says why the change cannot
// land: a placeholder is gone (without restore), repeated or moved.
func translateReplaced(uploaded, agent []byte, lines []SecretLine, restore bool) (out []byte, kept, put []int, why string) {
	ul, al := splitKeep(uploaded), splitKeep(agent)
	lineOf := func(ls [][]byte, p string) []int {
		var at []int
		for i, l := range ls {
			if len(tokenAt(l, p)) > 0 {
				at = append(at, i)
			}
		}
		return at
	}
	type spot struct {
		up    int
		local int
	}
	onAgent := map[int][]spot{}
	ofUp := map[int]int{}
	for _, l := range lines {
		u := lineOf(ul, l.Placeholder)
		if len(u) != 1 || len(tokenAt(uploaded, l.Placeholder)) != 1 {
			return nil, nil, nil, "the uploaded copy does not hold " + l.Placeholder + " once"
		}
		ofUp[u[0]]++
		switch a := tokenAt(agent, l.Placeholder); {
		case len(a) > 1:
			return nil, nil, nil, "the agent's version holds " + l.Placeholder + " more than once"
		case len(a) == 0 && !restore:
			return nil, nil, nil, "the agent removed or rewrote line " + strconv.Itoa(l.Line) + ", which holds a replaced credential (--restore-secret-lines takes the agent's lines as they are)"
		case len(a) == 1:
			i := lineOf(al, l.Placeholder)[0]
			onAgent[i] = append(onAgent[i], spot{u[0], l.Line})
		}
	}
	for i, spots := range onAgent {
		u := spots[0].up
		same := true
		for _, s := range spots {
			same = same && s.up == u
		}
		switch {
		case same && len(spots) == ofUp[u] && bytes.Equal(trimEOL(al[i]), trimEOL(ul[u])):
			// Left as uploaded.
		case restore:
			put = append(put, i+1)
		case same && len(spots) == ofUp[u]:
			al[i] = append(append([]byte(nil), trimEOL(ul[u])...), al[i][len(trimEOL(al[i])):]...)
			kept = append(kept, spots[0].local)
		default:
			return nil, nil, nil, "the agent moved a replaced credential to another line"
		}
	}
	sort.Ints(kept)
	sort.Ints(put)
	return bytes.Join(al, nil), kept, put, ""
}

// splitKeep splits b into lines, each with its line end.
func splitKeep(b []byte) [][]byte {
	var out [][]byte
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			out = append(out, b)
			break
		}
		out = append(out, b[:i+1])
		b = b[i+1:]
	}
	return out
}

// trimEOL drops a line's end (\n or \r\n).
func trimEOL(l []byte) []byte {
	return bytes.TrimSuffix(bytes.TrimSuffix(l, []byte("\n")), []byte("\r"))
}

// dropPutFindings drops the review's secret findings on lines where
// --restore-secret-lines put a value back: the operator asked for them.
func dropPutFindings(found []ScanFinding, put map[string]map[int]bool) []ScanFinding {
	if len(put) == 0 {
		return found
	}
	out := found[:0]
	for _, f := range found {
		i := strings.LastIndexByte(f.Location, ':')
		n, err := strconv.Atoi(f.Location[i+1:])
		if i >= 0 && err == nil && put[f.Path][n] {
			continue
		}
		out = append(out, f)
	}
	return out
}

// landing is what a patch or a branch takes of the pull, whose changes
// start from start: the effective result without the changes to files
// uploaded with replaced credentials (Restored). Only the 3-way apply
// brings those into the folder; a patch file or a branch commit would put
// the value somewhere new.
func (p *PullResult) landing(ctx context.Context, base gitCmd, rec *CopyRecord, start string) (string, error) {
	if len(p.Restored) == 0 {
		return p.Effective, nil
	}
	at, err := lsTree(ctx, base, start, p.Restored)
	if err != nil {
		return "", err
	}
	entries := map[string]idxEntry{}
	for _, r := range p.Restored {
		entries[r] = at[r]
	}
	return commitWith(ctx, base, rec, p.Effective, entries, "defenseclaw: sandbox result without changes to files with replaced credentials")
}

// leftOut says what a patch or a branch leaves out (landing).
func (p *PullResult) leftOut(what string) []string {
	if len(p.Restored) == 0 {
		return nil
	}
	return []string{fmt.Sprintf("the %s leaves out the agent's changes to %s, which held replaced credentials (it would put them somewhere new); --apply brings them into your folder",
		what, strings.Join(firstN(p.Restored, 5), ", "))}
}
