package workspace

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
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
	// flags are review flags on replaced files (RiskSecretContext).
	flags []Flag
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
		// Binary ones too: a placeholder in another file must be seen
		// whatever git calls it (RV5-7).
		if c.NewOID != "" {
			oids = append(oids, c.NewOID)
		}
		if c.OldOID != "" {
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
	// movedTo names, per replaced file, another changed path that now
	// holds one of its placeholders: the agent moved or copied it there.
	movedTo := map[string]string{}
	for p, c := range changed {
		if _, ok := byFile[p]; ok || c.NewOID == "" {
			continue
		}
		after := blobs[c.NewOID]
		for _, rel := range files {
			for _, l := range byFile[rel] {
				if _, done := movedTo[rel]; !done && len(tokenAt(after, l.Placeholder)) > 0 {
					movedTo[rel] = p
				}
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
			if to, moved := movedTo[rel]; moved {
				// A move: the new path stays out (it holds placeholders),
				// so the deletion does too, or the file would be lost
				// (GAP-0755).
				keep(rel)
				note("%s was moved by the agent to %s: neither change is brought back, as the file held replaced credentials", rel, to)
				continue
			}
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
		t, kept, put, near, why := translateReplaced(blobs[e.oid], agent, byFile[rel], restore)
		// lands: the agent changed a non-blank line other than the
		// placeholder lines kept as uploaded, so its code lands in a file
		// that holds the value.
		lands := why == "" && !sameNonBlank(t, blobs[e.oid])
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
		for _, n := range near {
			note("%s: line %d holds your credential and the agent changed the lines next to it; check that the change does not send or print the value", rel, n)
			out.flags = append(out.flags, Flag{Path: rel, Label: rel + ":" + strconv.Itoa(n), Kind: RiskSecretContext, Severity: SeverityInfo,
				Detail: "the agent changed the lines next to a line that holds a replaced credential"})
		}
		if lands && len(near) == 0 {
			// The near-line flag only looks a few lines out; code that
			// wraps the whole file (or reads it from afar) is a change
			// anywhere in it, so the file gets one note (RV8-1).
			var ns []int
			for _, l := range byFile[rel] {
				ns = append(ns, l.Line)
			}
			sort.Ints(ns)
			ls, word := []string{}, "line"
			for i, n := range ns {
				if i == 0 || n != ns[i-1] {
					ls = append(ls, strconv.Itoa(n))
				}
			}
			if len(ls) > 1 {
				word = "lines"
			}
			note("%s holds your credential on %s %s and the agent changed this file; check that the change does not send or print the value", rel, word, strings.Join(ls, ", "))
			out.flags = append(out.flags, Flag{Path: rel, Label: rel, Kind: RiskSecretContext, Severity: SeverityInfo,
				Detail: "the agent changed a file that holds a replaced credential"})
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
		if !ok {
			// Over the scan cap, so not read into memory: look for a
			// placeholder by streaming it (RV5-7). One in it, old or new,
			// keeps the change out: the old one cannot be compared.
			found, err := streamHasPlaceholder(ctx, base, c.NewOID)
			if err != nil {
				return err
			}
			if !found {
				continue
			}
		} else if copyTokens(after, tokens) == 0 {
			continue
		}
		if !ok || copyTokens(after, tokens) > copyTokens(blobs[c.OldOID], tokens) {
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

// streamHasPlaceholder reports whether the blob holds DC_SECRET_, read in
// pieces so a file over the scan cap is not held in memory.
func streamHasPlaceholder(ctx context.Context, g gitCmd, oid string) (bool, error) {
	cmd, cleanup, err := g.command(ctx, []string{"cat-file", "blob", oid})
	if err != nil {
		return false, err
	}
	defer cleanup()
	out, err := cmd.StdoutPipe()
	if err != nil {
		return false, err
	}
	if err := cmd.Start(); err != nil {
		return false, err
	}
	const prefix = "DC_SECRET_"
	buf := make([]byte, 1<<20)
	tail := []byte{}
	found := false
	for !found {
		n, rerr := out.Read(buf)
		if n > 0 {
			win := append(tail, buf[:n]...)
			found = bytes.Contains(win, []byte(prefix))
			if k := len(prefix) - 1; len(win) > k {
				tail = append([]byte{}, win[len(win)-k:]...)
			} else {
				tail = win
			}
		}
		if rerr != nil {
			break
		}
	}
	if found {
		_ = cmd.Process.Kill()
	}
	_, _ = io.Copy(io.Discard, out)
	werr := cmd.Wait()
	if found {
		return true, nil
	}
	return false, werr
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
	tree, err := treeWith(ctx, base, rec, from, entries)
	if err != nil {
		return "", err
	}
	return base.line(ctx, "commit-tree", tree, "-p", from, "-m", msg)
}

// treeWith writes from's tree (a commit or a tree) with entries set, in
// base (base.git or the project).
func treeWith(ctx context.Context, base gitCmd, rec *CopyRecord, from string, entries map[string]idxEntry) (string, error) {
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
	return g.line(ctx, "write-tree")
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

// sameNonBlank reports whether a and b hold the same non-blank lines, in
// order. A blank line added or removed is no change, and neither is
// trailing space or a line end (\n or \r\n), but indentation is: taking
// the indent off a line under `if False:` runs it (RV9-2). A line that ends
// in a backslash, before or after the change, is compared with only its line
// end removed: a space after the backslash ends the continuation, so the
// next line runs on its own (GAP-0889).
func sameNonBlank(a, b []byte) bool {
	nb := func(x []byte) [][]byte {
		var out [][]byte
		for _, l := range splitKeep(x) {
			if len(bytes.TrimSpace(l)) > 0 {
				out = append(out, l)
			}
		}
		return out
	}
	la, lb := nb(a), nb(b)
	if len(la) != len(lb) {
		return false
	}
	for i := range la {
		x, y := trimEOL(la[i]), trimEOL(lb[i])
		if !bytes.HasSuffix(x, []byte("\\")) && !bytes.HasSuffix(y, []byte("\\")) {
			x, y = bytes.TrimRight(x, " \t\r\v\f"), bytes.TrimRight(y, " \t\r\v\f")
		}
		if !bytes.Equal(x, y) {
			return false
		}
	}
	return true
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

// secretContextWindow is how many non-blank lines on each side of a replaced
// credential line the review checks for an agent change (info flag only).
const secretContextWindow = 5

// translateReplaced turns the agent's version of a replaced file into the
// one to land, placeholders still in (withValues puts the values in):
// each line that holds a placeholder is the uploaded line when the agent
// left it, or kept so (kept: the local line numbers), or with restore the
// agent's line (put: its line numbers). why says why the change cannot
// land: a placeholder is gone (without restore), repeated or moved. near
// are the agent's line numbers of placeholder lines left in place with a
// line the agent added, removed or changed within secretContextWindow
// non-blank lines: the value lands, and the review names the line (the
// caller notes any other change to the file once, RV8-1) (RV6-3: an agent that wraps the line in place,
// in a string it sends, kept its anchors and landed with no note).
func translateReplaced(uploaded, agent []byte, lines []SecretLine, restore bool) (out []byte, kept, put, near []int, why string) {
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
	mu := matchLines(ul, al, func(l []byte) string {
		for _, s := range lines {
			if len(tokenAt(l, s.Placeholder)) > 0 {
				// A placeholder line compares by its placeholders.
				return "\x00" + strings.Join(placeholderRE.FindAllString(string(l), -1), " ")
			}
		}
		return string(trimEOL(l))
	})
	am := make([]bool, len(al))
	for _, a := range mu {
		if a >= 0 {
			am[a] = true
		}
	}
	// beside reports a line near up line u or agent line i that the agent
	// added, removed or changed. Blank lines are skipped and the nearest
	// secretContextWindow non-blank lines on each side count (RV7-1: a wrap
	// one blank or unchanged line further out landed with no flag).
	nearChange := func(ls [][]byte, at int, changed func(int) bool) bool {
		for step := -1; step <= 1; step += 2 {
			seen := 0
			for j := at + step; j >= 0 && j < len(ls) && seen < secretContextWindow; j += step {
				if len(bytes.TrimSpace(ls[j])) == 0 {
					continue
				}
				seen++
				if changed(j) {
					return true
				}
			}
		}
		return false
	}
	beside := func(u, i int) bool {
		return nearChange(ul, u, func(j int) bool { return mu[j] < 0 }) ||
			nearChange(al, i, func(j int) bool { return !am[j] })
	}
	onAgent := map[int][]spot{}
	ofUp := map[int]int{}
	for _, l := range lines {
		u := lineOf(ul, l.Placeholder)
		if len(u) != 1 || len(tokenAt(uploaded, l.Placeholder)) != 1 {
			return nil, nil, nil, nil, "the uploaded copy does not hold " + l.Placeholder + " once"
		}
		ofUp[u[0]]++
		switch a := tokenAt(agent, l.Placeholder); {
		case len(a) > 1:
			return nil, nil, nil, nil, "the agent's version holds " + l.Placeholder + " more than once"
		case len(a) == 0 && !restore:
			return nil, nil, nil, nil, "the agent removed or rewrote line " + strconv.Itoa(l.Line) + ", which holds a replaced credential (--restore-secret-lines takes the agent's lines as they are)"
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
		if same && mu[u] == i && beside(u, i) {
			near = append(near, i+1)
		}
		switch {
		case mu[u] != i:
			return nil, nil, nil, nil, "the agent moved a replaced credential to another place in the file"
		case same && len(spots) == ofUp[u] && bytes.Equal(trimEOL(al[i]), trimEOL(ul[u])):
			// Left as uploaded.
		case restore:
			put = append(put, i+1)
		case same && len(spots) == ofUp[u]:
			al[i] = append(append([]byte(nil), trimEOL(ul[u])...), al[i][len(trimEOL(al[i])):]...)
			kept = append(kept, spots[0].local)
		default:
			return nil, nil, nil, nil, "the agent moved a replaced credential to another line"
		}
	}
	sort.Ints(kept)
	sort.Ints(put)
	sort.Ints(near)
	return bytes.Join(al, nil), kept, put, near, ""
}

// maxLCSCells bounds the longest-common-subsequence step of matchLines:
// a gap between anchors larger than this many line pairs is left unmatched.
const maxLCSCells = 1 << 16

// matchLines pairs the lines two versions of a file share, as a line diff
// does (patience diff): the common start and end, then the lines that
// occur once in each, in an order both keep, as anchors, and the same
// again between them; a gap with no such line is matched by a longest
// common subsequence when it is at most maxLCSCells line pairs. Lines
// compare by key. mu[i] is the agent line that up line i is paired with,
// or -1 (removed or changed).
//
// The lines that hold a placeholder take part, compared by their
// placeholders, so a blank line or a brace added or removed above a
// credential line can't pair duplicate lines across it (RV6-2: the earlier
// anchoring left those lines out, and a blank line added above the line
// read as a moved credential and dropped the agent's whole change).
func matchLines(up, agent [][]byte, key func([]byte) string) []int {
	uk, ak := make([]string, len(up)), make([]string, len(agent))
	for i, l := range up {
		uk[i] = key(l)
	}
	for i, l := range agent {
		ak[i] = key(l)
	}
	mu := make([]int, len(up))
	for i := range mu {
		mu[i] = -1
	}
	lcs := func(u0, u1, a0, a1 int) {
		n, m := u1-u0, a1-a0
		if n*m > maxLCSCells {
			return
		}
		t := make([]int32, (n+1)*(m+1))
		at := func(i, j int) *int32 { return &t[i*(m+1)+j] }
		for i := n - 1; i >= 0; i-- {
			for j := m - 1; j >= 0; j-- {
				switch {
				case uk[u0+i] == ak[a0+j]:
					*at(i, j) = *at(i+1, j+1) + 1
				case *at(i+1, j) >= *at(i, j+1):
					*at(i, j) = *at(i+1, j)
				default:
					*at(i, j) = *at(i, j+1)
				}
			}
		}
		for i, j := 0, 0; i < n && j < m; {
			switch {
			case uk[u0+i] == ak[a0+j]:
				mu[u0+i] = a0 + j
				i, j = i+1, j+1
			case *at(i+1, j) >= *at(i, j+1):
				i++
			default:
				j++
			}
		}
	}
	var diff func(u0, u1, a0, a1 int)
	diff = func(u0, u1, a0, a1 int) {
		for u0 < u1 && a0 < a1 && uk[u0] == ak[a0] {
			mu[u0] = a0
			u0, a0 = u0+1, a0+1
		}
		for u1 > u0 && a1 > a0 && uk[u1-1] == ak[a1-1] {
			u1, a1 = u1-1, a1-1
			mu[u1] = a1
		}
		if u0 == u1 || a0 == a1 {
			return
		}
		type count struct{ u, a, at int }
		seen := map[string]*count{}
		for j := u0; j < u1; j++ {
			c := seen[uk[j]]
			if c == nil {
				c = &count{}
				seen[uk[j]] = c
			}
			c.u++
		}
		for j := a0; j < a1; j++ {
			if c := seen[ak[j]]; c != nil {
				c.a++
				c.at = j
			}
		}
		var cand [][2]int
		for j := u0; j < u1; j++ {
			if c := seen[uk[j]]; c.u == 1 && c.a == 1 {
				cand = append(cand, [2]int{j, c.at})
			}
		}
		anchors := increasing(cand)
		if len(anchors) == 0 {
			lcs(u0, u1, a0, a1)
			return
		}
		pu, pa := u0, a0
		for _, p := range anchors {
			diff(pu, p[0], pa, p[1])
			mu[p[0]] = p[1]
			pu, pa = p[0]+1, p[1]+1
		}
		diff(pu, u1, pa, a1)
	}
	diff(0, len(up), 0, len(agent))
	return mu
}

// increasing is the longest run of pairs (in order of their first
// element) whose second elements increase too.
func increasing(pairs [][2]int) [][2]int {
	var tops []int
	prev := make([]int, len(pairs))
	for i, p := range pairs {
		j := sort.Search(len(tops), func(k int) bool { return pairs[tops[k]][1] >= p[1] })
		prev[i] = -1
		if j > 0 {
			prev[i] = tops[j-1]
		}
		if j == len(tops) {
			tops = append(tops, i)
		} else {
			tops[j] = i
		}
	}
	out := make([][2]int, len(tops))
	for k, i := len(tops)-1, -1; k >= 0; k-- {
		if k == len(tops)-1 {
			i = tops[k]
		} else {
			i = prev[i]
		}
		out[k] = pairs[i]
	}
	return out
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
// start from start: the effective result with every file uploaded with
// replaced credentials as start has it. Only the 3-way apply brings the
// changes to those files (Restored) into the folder; a patch file or a
// branch commit would put the value somewhere new.
func (p *PullResult) landing(ctx context.Context, base gitCmd, rec *CopyRecord, start string) (string, error) {
	files := replacedFiles(rec)
	if len(files) == 0 {
		return p.Effective, nil
	}
	at, err := lsTree(ctx, base, start, files)
	if err != nil {
		return "", err
	}
	entries := map[string]idxEntry{}
	for _, r := range files {
		entries[r] = at[r]
	}
	return commitWith(ctx, base, rec, p.Effective, entries, "defenseclaw: sandbox result without changes to files with replaced credentials")
}

// replacedFiles lists, sorted, the files uploaded with replaced
// credentials.
func replacedFiles(rec *CopyRecord) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range rec.SecretLines {
		if !seen[l.Rel] {
			seen[l.Rel] = true
			out = append(out, l.Rel)
		}
	}
	sort.Strings(out)
	return out
}

// secretFreeTree is tree, in g (the project or base.git), with every file
// uploaded with replaced credentials as the copy's HEAD has it (absent
// when HEAD has none): a branch commit never holds such a file anew, with
// its value or a placeholder (GAP-0753).
func secretFreeTree(ctx context.Context, g gitCmd, rec *CopyRecord, tree string) (string, error) {
	files := replacedFiles(rec)
	if len(files) == 0 {
		return tree, nil
	}
	at := map[string]idxEntry{}
	if rec.Head != "" {
		var err error
		if at, err = lsTree(ctx, g, rec.Head, files); err != nil {
			return "", err
		}
	}
	entries := map[string]idxEntry{}
	for _, f := range files {
		entries[f] = at[f]
	}
	return treeWith(ctx, g, rec, tree, entries)
}

// leftOut says what a patch or a branch leaves out (landing).
func (p *PullResult) leftOut(what string) []string {
	if len(p.Restored) == 0 {
		return nil
	}
	return []string{fmt.Sprintf("the %s leaves out the agent's changes to %s, which held replaced credentials (it would put them somewhere new); --apply brings them into your folder",
		what, strings.Join(firstN(p.Restored, 5), ", "))}
}
