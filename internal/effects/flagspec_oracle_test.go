// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

// rel-1-0-10 GAP-0216: the reviewed flag specs (testdata/flagspec.tsv and the
// gnu rows of testdata/flagspec_restricted.tsv) are checked against the tools
// themselves, not against the table written by the same hand:
//
//   - TestFlagSpecRunOracle runs each tool in an empty folder (stdin empty,
//     HOME the folder, C locale, short timeout) with the flag followed by
//     arity and arity-1 values. The tool must report a missing argument
//     exactly when fewer values than the arity are given. A long switch given
//     --flag=v must be refused (it takes no value); a long valued flag given
//     --flag=v must not be. An "opt" switch must accept an attached value and
//     no value.
//   - TestFlagSpecHelpOracle parses --help (and man where installed): where the
//     tool documents the flag, the number of metavar words after it and the
//     optional [VALUE] form must agree with the spec, and a flag documented as
//     writing a file must not be reviewed as inert.
//
// Both need the GNU userland of the build boxes (dc-s7-bench*): they skip off
// Linux and skip a tool that is absent or not the expected implementation.

// oracleTool names a spec program's binaries and what --version must say.
type oracleTool struct {
	bins    []string
	version string // substring of the first --version line ("" = any)
	verArg  string
}

var oracleTools = map[string]oracleTool{
	"sed":     {bins: []string{"sed"}, version: "GNU sed"},
	"awk":     {bins: []string{"gawk", "mawk"}},
	"curl":    {bins: []string{"curl"}, version: "curl "},
	"wget":    {bins: []string{"wget"}, version: "GNU Wget"},
	"find":    {bins: []string{"find"}, version: "GNU findutils"},
	"grep":    {bins: []string{"grep"}, version: "GNU grep"},
	"rg":      {bins: []string{"rg"}, version: "ripgrep"},
	"fd":      {bins: []string{"fd", "fdfind"}},
	"cp":      {bins: []string{"cp"}, version: "GNU coreutils"},
	"install": {bins: []string{"install"}, version: "GNU coreutils"},
	"mv":      {bins: []string{"mv"}, version: "GNU coreutils"},
	"ln":      {bins: []string{"ln"}, version: "GNU coreutils"},
	"rm":      {bins: []string{"rm"}, version: "GNU coreutils"},
	"unlink":  {bins: []string{"unlink"}, version: "GNU coreutils"},
	"shred":   {bins: []string{"shred"}, version: "GNU coreutils"},
	"tee":     {bins: []string{"tee"}, version: "GNU coreutils"},
}

// oracleExempt are spec flags the run oracle cannot judge by value count,
// with the reason. Each still has its own corpus and table tests.
var oracleExempt = map[string]string{
	"find -exec":    "variable length: COMMAND ... ; or +",
	"find -execdir": "variable length: COMMAND ... ; or +",
	"find -ok":      "variable length: COMMAND ... ;",
	"find -okdir":   "variable length: COMMAND ... ;",
	"fd -x":         "variable length: the rest of the line",
	"fd -X":         "variable length: the rest of the line",
	"fd --exec":     "variable length: the rest of the line",
}

// findGlobal are the find options that come before the starting points.
var findGlobal = map[string]bool{"-H": true, "-L": true, "-P": true, "-D": true, "-O1": true, "-O2": true, "-O3": true}

// helpExempt are spec flags whose help entry names an operand that is not a
// value word (find's operators take expressions).
// find --help lists -regextype among the normal options with no metavar (man:
// "-regextype type"); the run oracle checks its arity.
var helpExempt = map[string]bool{"find -not": true, "find -a": true, "find -and": true, "find -o": true, "find -or": true,
	"find -regextype": true}

// ownParser are tools whose long switches do not use getopt_long's
// "doesn't allow an argument" (curl, find primaries, wget's on/off booleans).
var ownParser = map[string]bool{"curl": true, "find": true, "wget": true}

var (
	reMissingArg = regexp.MustCompile(`(?i)requires an argument|requires a value|requires parameter|missing argument|lacks argument|needs an argument|expects an argument|option requires`)
	reNoArgAllow = regexp.MustCompile(`(?i)doesn't allow an argument|does not allow an argument|doesn't take an argument|does not take an argument|takes no argument|unexpected argument|no value expected`)
)

type oracleFlag struct {
	prog, flag string
	arity      int
	optional   bool
	effect     string
}

// oracleSpecFlags is every flag of both spec files that the oracles check,
// read from the files themselves (not from the table or its test helpers).
func oracleSpecFlags(t *testing.T) []oracleFlag {
	t.Helper()
	var out []oracleFlag
	read := func(path string, cols, progCol, flagCol, arCol, effCol int, keep func([]string) bool) {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(b), "\n") {
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			c := strings.Split(line, "\t")
			if len(c) != cols {
				t.Fatalf("%s: bad line %q", path, line)
			}
			if !keep(c) {
				continue
			}
			f := oracleFlag{prog: c[progCol], flag: c[flagCol], effect: c[effCol]}
			switch c[arCol] {
			case "0":
			case "1":
				f.arity = 1
			case "2":
				f.arity = 2
			case "opt":
				f.optional = true
			default:
				t.Fatalf("%s: bad arity in %q", path, line)
			}
			out = append(out, f)
		}
	}
	read("testdata/flagspec.tsv", 4, 0, 1, 2, 3, func([]string) bool { return true })
	read("testdata/flagspec_restricted.tsv", 5, 0, 2, 3, 4, func(c []string) bool { return c[1] == "gnu" })
	sort.Slice(out, func(i, j int) bool {
		if out[i].prog != out[j].prog {
			return out[i].prog < out[j].prog
		}
		return out[i].flag < out[j].flag
	})
	return out
}

// oracleBins returns the installed binaries that implement prog.
func oracleBins(t *testing.T, prog string) []string {
	t.Helper()
	tool, ok := oracleTools[prog]
	if !ok {
		t.Fatalf("%s: no oracle tool entry", prog)
	}
	var out []string
	for _, b := range tool.bins {
		p, err := exec.LookPath(b)
		if err != nil {
			continue
		}
		if tool.version != "" {
			arg := tool.verArg
			if arg == "" {
				arg = "--version"
			}
			o, _ := exec.Command(p, arg).CombinedOutput()
			if !strings.Contains(string(o), tool.version) {
				continue
			}
		}
		out = append(out, p)
	}
	return out
}

func oracleRun(t *testing.T, bin string, args []string) (stderr string) {
	t.Helper()
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + dir, "LC_ALL=C", "LANG=C", "no_proxy=*", "http_proxy=http://127.0.0.1:9", "https_proxy=http://127.0.0.1:9"}
	var se strings.Builder
	cmd.Stderr = &se
	_ = cmd.Run()
	// The first lines carry the option error; a usage text that follows may
	// quote other options.
	lines := strings.SplitN(se.String(), "\n", 3)
	if len(lines) > 2 {
		lines = lines[:2]
	}
	return strings.Join(lines, "\n")
}

// oracleArgv places flag and its values where the tool parses options.
func oracleArgv(prog, flag string, vals []string) []string {
	fv := append([]string{flag}, vals...)
	switch prog {
	case "find":
		if findGlobal[flag] {
			return fv // before any starting point; "." would be read as the value
		}
		return append([]string{"."}, fv...)
	}
	return fv
}

// findMissing: find reports a value that is not there as an invalid argument
// to the flag, naming the word it took instead (the flag itself, or the last
// value given): "invalid argument `-inum' to `-inum'", "invalid argument
// `v0' to `-fprintf'". Only meaningful for the k-1 run.
func findMissing(prog, flag string, vals []string, se string) bool {
	if prog != "find" {
		return false
	}
	last := flag
	if len(vals) > 0 {
		last = vals[len(vals)-1]
	}
	return strings.Contains(se, "invalid argument `"+last+"' to `"+flag+"'")
}

func oracleVals(n int) []string {
	v := make([]string, n)
	for i := range v {
		v[i] = "v" + string(rune('0'+i))
	}
	return v
}

func TestFlagSpecRunOracle(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the oracles run against the GNU userland of the Linux build boxes")
	}
	checked, skipped := 0, map[string]bool{}
	for _, f := range oracleSpecFlags(t) {
		key := f.prog + " " + f.flag
		if _, ok := oracleExempt[key]; ok {
			continue
		}
		bins := oracleBins(t, f.prog)
		if len(bins) == 0 {
			skipped[f.prog] = true
			continue
		}
		for _, bin := range bins {
			name := filepath.Base(bin) + " " + f.flag
			// k values: no missing-argument error.
			if se := oracleRun(t, bin, oracleArgv(f.prog, f.flag, oracleVals(f.arity))); reMissingArg.MatchString(se) {
				t.Errorf("%s: spec arity %d, but %d value(s) is a missing argument: %q", name, f.arity, f.arity, se)
			}
			// k-1 values: a missing-argument error.
			if f.arity > 0 {
				vals := oracleVals(f.arity - 1)
				if se := oracleRun(t, bin, oracleArgv(f.prog, f.flag, vals)); !reMissingArg.MatchString(se) && !findMissing(f.prog, f.flag, vals, se) {
					t.Errorf("%s: spec arity %d, but %d value(s) is accepted (%q)", name, f.arity, f.arity-1, se)
				}
			}
			long := strings.HasPrefix(f.flag, "--")
			switch {
			case f.optional:
				attached := f.flag + "x"
				if long {
					attached = f.flag + "=x"
				}
				if se := oracleRun(t, bin, oracleArgv(f.prog, attached, nil)); reNoArgAllow.MatchString(se) || reMissingArg.MatchString(se) {
					t.Errorf("%s: spec opt, but an attached value is refused: %q", name, se)
				}
			case long && f.arity == 0 && !ownParser[f.prog]:
				// getopt_long refuses --switch=v (curl and find have their own parsers)
				if se := oracleRun(t, bin, oracleArgv(f.prog, f.flag+"=x", nil)); !reNoArgAllow.MatchString(se) {
					t.Errorf("%s: spec switch, but --flag=value is accepted (an optional value?): %q", name, se)
				}
			case long && f.arity == 1 && f.prog != "find":
				if se := oracleRun(t, bin, oracleArgv(f.prog, f.flag+"=x", nil)); reNoArgAllow.MatchString(se) || reMissingArg.MatchString(se) {
					t.Errorf("%s: spec arity 1, but --flag=value is refused: %q", name, se)
				}
			}
			checked++
		}
	}
	t.Logf("run oracle: %d flag checks; tools absent here: %v", checked, sortedKeys(skipped))
	if checked == 0 {
		t.Skip("no spec tool installed")
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// helpDoc is one documented option group: the aliases, the metavar words, and
// whether the value is optional.
type helpDoc struct {
	arity    int
	optional bool
	text     string // the rest of the line (the description, for the effect check)
}

// helpText is what the tool documents about its options: --help (curl: --help
// all; mawk: -W usage). manText is the man page's option definitions: the
// lines that start with an option at the definition indent (man prose and
// examples mention options in passing and are not read).
func helpText(bin string) string {
	var b strings.Builder
	args := [][]string{{"--help"}}
	switch filepath.Base(bin) {
	case "curl":
		args = [][]string{{"--help", "all"}}
	case "mawk":
		args = [][]string{{"-W", "usage"}}
	}
	for _, a := range args {
		o, _ := exec.Command(bin, a...).CombinedOutput()
		b.Write(o)
		b.WriteByte('\n')
	}
	return b.String()
}

var reManDef = regexp.MustCompile(`^ {1,8}-`)

func manText(bin string) string {
	man, err := exec.LookPath("man")
	if err != nil {
		return ""
	}
	cmd := exec.Command(man, "-P", "cat", filepath.Base(bin))
	cmd.Env = append(os.Environ(), "MANWIDTH=200", "MAN_KEEP_FORMATTING=0")
	o, err := cmd.Output()
	if err != nil {
		return ""
	}
	o = regexp.MustCompile(".\x08").ReplaceAll(o, nil) // overstrike (bold / underline)
	var b strings.Builder
	for _, line := range strings.Split(string(o), "\n") {
		if reManDef.MatchString(line) {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

var (
	reGap      = regexp.MustCompile(`\s{2,}|\t`)
	reAliasSep = regexp.MustCompile(`,\s+-`)
	reCapsMeta = regexp.MustCompile(`^[A-Z][A-Z0-9_|-]*(\[[^\]]*\])?,?$`)
)

// parseHelp reads option groups from help or man text. A segment of a line
// that starts with '-' (after an optional "label:") is an option group; its
// aliases are separated by ", " and share the metavar; in a find-style list
// (no commas) each flag owns the words up to the next flag.
func parseHelp(text string) map[string]helpDoc {
	docs := map[string]helpDoc{}
	for _, line := range strings.Split(text, "\n") {
		// Option definitions start near the left margin; deeper lines are the
		// wrapped descriptions, which name options in passing.
		if indent := len(strings.ReplaceAll(line, "\t", "        ")) - len(strings.TrimLeft(strings.ReplaceAll(line, "\t", "        "), " ")); indent > 8 {
			continue
		}
		line = reAliasSep.ReplaceAllString(line, ", -")
		segs := reGap.Split(strings.TrimSpace(line), -1)
		for si, seg := range segs {
			if c := strings.Index(seg, ": -"); c > 0 && !strings.Contains(seg[:c], " ") {
				seg = seg[c+2:]
			}
			if !strings.HasPrefix(seg, "-") {
				continue
			}
			rest := strings.Join(segs[si+1:], " ")
			if strings.Contains(seg, ", -") {
				parseAliasGroup(seg, rest, docs)
				continue
			}
			parseFlagList(seg, rest, docs)
		}
	}
	return docs
}

func addDoc(docs map[string]helpDoc, flag string, d helpDoc) {
	if flag == "" || flag == "-" || flag == "--" {
		return
	}
	if _, ok := docs[flag]; !ok {
		docs[flag] = d
	}
}

// splitFlagToken splits "-i[SUFFIX]", "--in-place[=SUFFIX]", "--file=FILE".
func splitFlagToken(tok string) (flag string, meta int, optional bool) {
	tok = strings.TrimRight(tok, ",")
	if i := strings.IndexByte(tok, '['); i > 1 {
		return tok[:i], 0, true
	}
	if i := strings.IndexByte(tok, '='); i > 1 {
		return tok[:i], 1, false
	}
	return tok, 0, false
}

// countMeta counts the metavar words at ws[i:]: a <word ...> group, an
// all-caps word, or a lower-case word that ends its alias part (the GNU
// "-e script," form). It stops at the first description word.
func countMeta(ws []string, i int) (n, next int) {
	for i < len(ws) {
		w := ws[i]
		switch {
		case strings.HasPrefix(w, "<"):
			for i < len(ws) && !strings.HasSuffix(strings.TrimRight(ws[i], ","), ">") {
				i++
			}
			return n + 1, i + 1 // curl: one <metavar>, then the description
		case w == "" || w[0] == '-' || w == ";" || w == "+":
			return n, i
		case reCapsMeta.MatchString(w) || strings.HasPrefix(w, "["):
			n++
			i++
		case i == len(ws)-1 || strings.HasSuffix(w, ","):
			return n + 1, i + 1
		default:
			return n, i
		}
	}
	return n, i
}

func parseAliasGroup(seg, rest string, docs map[string]helpDoc) {
	var flags []string
	d := helpDoc{text: rest}
	for _, part := range strings.Split(seg, ", ") {
		ws := strings.Fields(part)
		if len(ws) == 0 || !strings.HasPrefix(ws[0], "-") {
			continue
		}
		f, meta, opt := splitFlagToken(ws[0])
		if meta == 0 && !opt {
			meta, _ = countMeta(ws, 1)
		}
		if meta > d.arity {
			d.arity = meta
		}
		d.optional = d.optional || opt
		flags = append(flags, f)
	}
	for _, f := range flags {
		addDoc(docs, f, d)
	}
}

func parseFlagList(seg, rest string, docs map[string]helpDoc) {
	ws := strings.Fields(seg)
	for i := 0; i < len(ws); i++ {
		if !strings.HasPrefix(ws[i], "-") {
			continue
		}
		f, meta, opt := splitFlagToken(ws[i])
		next := i + 1
		if meta == 0 && !opt {
			meta, next = countMeta(ws, i+1)
		}
		addDoc(docs, f, helpDoc{arity: meta, optional: opt, text: rest})
		i = next - 1
	}
}

var reWritesFile = regexp.MustCompile(`(?i)\b(write|writes|save|saves|dump|dumps|log|logs|append|appends)\b[^.]*\b(file|FILE|<file>|filename)\b`)

func TestFlagSpecHelpOracle(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the oracles run against the GNU userland of the Linux build boxes")
	}
	byProg := map[string][]oracleFlag{}
	for _, f := range oracleSpecFlags(t) {
		byProg[f.prog] = append(byProg[f.prog], f)
	}
	documented, undocumented := 0, []string{}
	for _, prog := range sortedProgs(byProg) {
		for _, bin := range oracleBins(t, prog) {
			docs := parseHelp(helpText(bin))
			for f, d := range parseHelp(manText(bin)) {
				addDoc(docs, f, d) // man only for what --help does not list
			}
			for _, f := range byProg[prog] {
				if _, ok := oracleExempt[f.prog+" "+f.flag]; ok || helpExempt[f.prog+" "+f.flag] {
					continue
				}
				d, ok := docs[f.flag]
				if !ok {
					undocumented = append(undocumented, filepath.Base(bin)+" "+f.flag)
					continue
				}
				documented++
				name := filepath.Base(bin) + " " + f.flag
				if d.optional != f.optional {
					t.Errorf("%s: documented optional=%v, spec optional=%v", name, d.optional, f.optional)
				}
				if !d.optional && d.arity != f.arity {
					t.Errorf("%s: documented with %d metavar word(s), spec arity %d", name, d.arity, f.arity)
				}
				if f.arity > 0 && f.effect == "inert" && reWritesFile.MatchString(d.text) {
					t.Errorf("%s: documented as writing a file (%q), spec effect inert", name, d.text)
				}
			}
		}
	}
	t.Logf("help oracle: %d documented flag checks; %d spec flags not documented by the tool's help or man (checked by the run oracle only): %v",
		documented, len(undocumented), undocumented)
	if documented == 0 {
		t.Skip("no spec tool installed")
	}
}

func sortedProgs(m map[string][]oracleFlag) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
