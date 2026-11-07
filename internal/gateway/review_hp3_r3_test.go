// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/metrics"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// Round 3 review rows of fix/r107-bd-hookparse3 (IN-bd-hookparse3-REVIEW.md):
// ordinary scripts that reassign a variable inside loops and conditionals
// and then write a project file through it (must allow), the kept-candidate
// bound (must block), and the rel-1-0-6:GAP-0229 managed regression row
// (eval reassignment onto the keys link, then a write through the variable).
// want "" is a logged probe.

// hp3r3Conds is k independent unknown conditionals that each assign a
// distinct name: 2^k kept candidates before the 512 bound.
func hp3r3Conds(k int) string {
	var b strings.Builder
	for i := 1; i <= k; i++ {
		fmt.Fprintf(&b, "if [ -n \"$A%d\" ]; then a%d=1; fi; ", i, i)
	}
	return b.String()
}

// Static condition words avoid relying on a truncated dynamic client fact.
func hp3r3StaticConds(k int) string {
	var b strings.Builder
	for i := 1; i <= k; i++ {
		fmt.Fprintf(&b, "if [ -f a.txt ]; then a%d=1; fi; ", i)
	}
	return b.String()
}

var reviewHP3R3Rows = []struct{ name, command, want string }{
	// Benign: reassignment inside loops and conditionals, then a write
	// to a project file through the variable.
	{"r3-allow-for-bak", `for f in *.txt; do out=$f.bak; cp "$f" "$out"; done`, "allow"},
	{"r3-allow-for-bak-strip", `for f in *.txt; do out="${f%.txt}.bak"; cp -- "$f" "$out"; done`, "allow"},
	{"r3-allow-for-bak-list", `for f in *.txt; do out=$f.bak; cp "$f" "$out"; echo "$out" >> backups.list; done`, "allow"},
	{"r3-allow-logrotate", `log=build.log; for i in 3 2 1; do if [ -f "$log.$i" ]; then mv "$log.$i" "$log.$((i+1))"; fi; done; if [ -f "$log" ]; then mv "$log" "$log.1"; fi; : > "$log"`, "allow"},
	{"r3-allow-logrotate-size", `LOG=app.log; if [ "$(wc -c < "$LOG" 2>/dev/null || echo 0)" -gt 1000 ]; then mv "$LOG" "$LOG.old"; LOG=app.log; fi; date >> "$LOG"`, "allow"},
	{"r3-allow-build-outdir", `out=build; if [ -n "$DEBUG" ]; then out=build/debug; fi; mkdir -p "$out"; echo done >> "$out/build.log"`, "allow"},
	{"r3-allow-build-case", `mode=release; case "$1" in -d) mode=debug;; -p) mode=profile;; esac; echo "$mode" > build.mode`, "allow"},
	{"r3-allow-while-counter", `n=0; while [ $n -lt 3 ]; do n=$((n+1)); f=out$n.txt; echo $n > "$f"; done`, "allow"},
	{"r3-allow-group-dest", `dest=dist; { dest=dist/pkg; mkdir -p "$dest"; }; cp a.txt "$dest/"`, "allow"},
	{"r3-allow-andand-log", `log=run.log; [ -d logs ] && log=logs/run.log; echo start >> "$log"`, "allow"},
	{"r3-allow-tee-target", `target=a.txt; if [ -n "$NEW" ]; then target=a.txt.new; fi; cat a.txt | tee "$target"`, "allow"},
	{"r3-allow-while-read", `while read -r f; do out="$f.bak"; cp "$f" "$out"; done < list.txt`, "allow"},
	{"r3-allow-for-case-mkdir", `for d in src lib; do case $d in src) o=build/src;; lib) o=build/lib;; esac; mkdir -p "$o"; cp -r "$d"/. "$o"/; done`, "allow"},
	{"r3-allow-for-index", `i=0; for f in *.txt; do i=$((i+1)); printf "%s\n" "$f" > "list_$i.txt"; done`, "allow"},
	{"r3-allow-if-else-src", `if [ -f a.txt ]; then src=a.txt; else src=b.txt; fi; out=$src.orig; cp "$src" "$out"`, "allow"},
	{"r3-allow-loop-last", `out=a.txt; for i in 1 2; do out=part$i.txt; done; echo x > "$out"`, "allow"},
	{"r3-allow-multiline-build", "set -e\nBUILD=build\nif [ \"$1\" = clean ]; then\n  rm -rf \"$BUILD\"\nfi\nmkdir -p \"$BUILD\"\nfor src in *.txt; do\n  obj=\"$BUILD/${src%.txt}.o\"\n  cp \"$src\" \"$obj\"\n  echo \"$obj\" >> \"$BUILD/manifest\"\ndone\nLOG=\"$BUILD/build.log\"\ncase \"$MODE\" in\n  ci) LOG=\"$BUILD/ci.log\" ;;\nesac\ndate > \"$LOG\"", "allow"},
	{"r3-allow-cap-config", hp3r3Conds(10) + `out=config.mk; if [ -n "$X" ]; then out=config.local.mk; fi; echo "CC=gcc" > "$out"`, "allow"},
	{"r3-allow-cap-tee", hp3r3Conds(10) + `cat a.txt | tee -a "$a3.log"`, "allow"},
	{"r3-allow-reassign-off-link", `f=keylink; f=a.txt; echo m >> "$f"`, "allow"},
	{"r3-probe-if-true-off-link", `f=keylink; if true; then f=a.txt; fi; echo m >> "$f"`, "allow"},
	// rel-1-0-6:GAP-0312 / rel-1-0-2:GAP-0409: the kept tracker records an
	// assignment inside each compound form (static-word conditions, so no
	// truncated client evidence hides the kept reading), keeps the earlier
	// value when a branch may be skipped, and narrows only on true/false.
	{"r3-0312-for-inner-value", `f=a.txt; for i in 1 2; do f=keylink; done; echo m >> "$f"`, "block"},
	{"r3-0312-while-inner-value", `f=a.txt; while true; do f=keylink; break; done; echo m >> "$f"`, "block"},
	{"r3-0312-case-inner-value", `f=a.txt; case x in x) f=keylink;; esac; echo m >> "$f"`, "block"},
	{"r3-0312-and-inner-value", `f=a.txt; true && f=keylink; echo m >> "$f"`, "block"},
	{"r3-0312-or-inner-value", `f=a.txt; [ -f x.txt ] || f=keylink; echo m >> "$f"`, "block"},
	{"r3-0409-if-unknown-keeps-earlier", `f=keylink; if [ -f x.txt ]; then f=a.txt; fi; echo m >> "$f"`, "block"},
	{"r3-0409-while-false-keeps-earlier", `f=keylink; while false; do f=a.txt; done; echo m >> "$f"`, "block"},
	{"r3-0409-negated-true-keeps-earlier", `f=keylink; if ! true; then f=a.txt; fi; echo m >> "$f"`, "block"},
	{"r3-0312-allow-for-other", `f=a.txt; for i in 1 2; do f=b.txt; done; echo m >> "$f"`, "allow"},
	{"r3-0312-allow-case-other", `f=a.txt; case x in x) f=b.txt;; esac; echo m >> "$f"`, "allow"},
	// A redirect through a name assigned in a group after an if/else or a
	// for loop; the latter remains a pre-existing conservative block.
	{"r3-pre-ifelse-then-group-redirect", "if [ -f src/m0.c ]; then o0=build/m0.o; else o0=build/gen0.o; fi\n{ g4=logs/g4.log; echo \"$c4\" >> \"$g4\"; }", "allow"},
	{"r3-pre-for-then-group-redirect", "for f in src/*.c; do b1=\"${f%.c}.bak\"; cp \"$f\" \"$b1\"; done\n{ g4=logs/g4.log; echo \"$c4\" >> \"$g4\"; }", ""},
	// The 512 bound: a protected candidate must survive the cut.
	{"r3-cap-keylink-before", `f=keylink; if [ -n "$X" ]; then f=a.txt; fi; ` + hp3r3Conds(9) + `echo m >> "$f"`, "block"},
	{"r3-cap-keylink-before-tee", `f=keylink; if [ -n "$X" ]; then f=a.txt; fi; ` + hp3r3Conds(9) + `cat a.txt | tee -a "$f"`, "block"},
	{"r3-cap-keylink-else", `f=a.txt; if [ -n "$X" ]; then f=b.txt; else f=keylink; fi; ` + hp3r3Conds(9) + `echo m >> "$f"`, "block"},
	{"r3-cap-keylink-after", `f=a.txt; ` + hp3r3Conds(9) + `if [ -n "$X" ]; then f=keylink; fi; echo m >> "$f"`, "block"},
	{"r3-cap-static-keylink-after", `f=a.txt; ` + hp3r3StaticConds(6) + `if [ -f a.txt ]; then f=keylink; fi; echo m >> "$f"`, "block"},
	{"r3-cap-static-tee-after", `f=a.txt; ` + hp3r3StaticConds(6) + `if [ -f a.txt ]; then f=keylink; fi; cat a.txt | tee -a "$f"`, "block"},
	// Thirty-two candidates stay under the candidate cap. The no-op calls
	// consume the step budget just before the protected assignment.
	{"r4-step-cap-keylink-after", `f=a.txt; ` + hp3r3Conds(5) + strings.Repeat(":; ", 13) + `if true; then f=keylink; fi; echo m >> "$f"`, "block"},
	// rel-1-0-6:GAP-0357: after the step cap, a dynamic eval or a
	// compound assignment must invalidate the earlier ordinary value.
	{"r5-step-cap-eval-dynamic", `g=keylink; f=a.txt; ` + hp3r3Conds(5) + strings.Repeat(":; ", 20) + `eval f=; echo m >> "$f"`, "block"},
	{"r5-step-cap-andand-after", `f=a.txt; ` + hp3r3Conds(5) + strings.Repeat(":; ", 20) + `[ -n "$X" ] && f=keylink; echo m >> "$f"`, "block"},
	{"r5-step-cap-group-redirect", `f=a.txt; ` + hp3r3Conds(5) + strings.Repeat(":; ", 20) + `{ f=keylink; echo m >> "$f"; }`, "block"},
	{"r5-step-cap-while-read", `f=a.txt; ` + hp3r3Conds(5) + strings.Repeat(":; ", 20) + `while read -r f; do break; done < names.txt; echo m >> "$f"`, "block"},
	// rel-1-0-6:GAP-0349: compacting option states must keep a later
	// variable destination when it names a link to the protected file.
	{"r5-0349-if-defaults-keylink", hp3r4IfDefaults(10, `out=keylink; cp a.txt "$out"`), "block"},
	{"r5-0349-options-cases-keylink", hp3r3BuildCases(6) + `out=keylink; cp a.txt "$out"`, "block"},
	{"r3-under-cap-keylink-before", `f=keylink; if [ -n "$X" ]; then f=a.txt; fi; ` + hp3r3Conds(8) + `echo m >> "$f"`, "block"},
	// rel-1-0-6:GAP-0229 managed regression (sweep 9 mgd-rhel-ad E2): the
	// eval reassignment form onto the keys link, then a write through the
	// variable (gap0409_dynamic_redirect_link_test.go and fbef6f821b forms).
	{"r3-0229-eval-reassign-keylink", `f=other; eval f=keylink; echo marker >> "$f"`, "block"},
	{"r3-0229-eval-reassign-keylink-dccert", `f=other; eval f=keylink; echo dccert-block-marker >> "$f"`, "block"},
	{"r3-0229-eval-keylink-bare", `eval f=keylink; echo marker >> $f`, "block"},
	{"r3-0229-allow-eval-ordinary", `f=other; eval f=a.txt; echo marker >> "$f"`, ""},
}

// hp3r3PreExisting are rows that base 18d0d88333 answers the same way
// (block where the row wants allow): logged, not asserted, in the cells
// named ("all", "managed" or "peruser"). The fixture project holds keylink
// and sshlink, so an unknown write target there is judged conservatively.
var hp3r3PreExisting = map[string]string{
	"r3-allow-for-bak-list":      "all",
	"r3-allow-multiline-build":   "all",
	"r3-allow-cap-config":        "all",
	"r3-allow-cap-tee":           "all",
	"r3-allow-reassign-off-link": "peruser",
	"r3-probe-if-true-off-link":  "peruser",
	"r3-allow-group-dest":        "managed",
	"r3-allow-if-else-src":       "managed",
}

// hp3r3LimitOnly are rows past the statement cap whose protected target is a
// variable the reader does not prove: the verdict is the evaluation limit
// alone, an alert outside strict and a block in strict.
var hp3r3LimitOnly = map[string]bool{"r3-cap-keylink-before-tee": true, "r3-cap-static-tee-after": true}

func TestReviewHP3R3FourCell(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	strictFixture := f.strict(t)
	if err := os.Symlink("../.ssh", filepath.Join(f.project, "sshlink")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a.txt", "b.txt", "list.txt"} {
		if err := os.WriteFile(filepath.Join(f.project, name), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(f.project, "names.txt"), []byte("keylink\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	only := os.Getenv("HP3R3_ROWS")
	for _, row := range reviewHP3R3Rows {
		if only != "" && !strings.Contains(row.name, only) {
			continue
		}
		payload := f.payload(t, row.command)
		header := f.clientHeader(t, payload)
		for _, call := range everyMode(row.name, payload, header) {
			mode := os.FileMode(0o700)
			if call.managed {
				mode = 0
			}
			if err := os.Chmod(f.homes, mode); err != nil {
				t.Fatal(err)
			}
			call.verdict, call.body = f.serve(call)
			t.Logf("HP3R3ROW %s | %s | want %s", call.name, call.verdict, row.want)
			if hp3r3LimitOnly[row.name] {
				if call.verdict != "alert" {
					t.Errorf("%s: verdict %s, want alert; body %.200s", call.name, call.verdict, call.body)
				}
				strictCall := *call
				strictCall.verdict, strictCall.body = strictFixture.serve(&strictCall)
				if strictCall.verdict != row.want {
					t.Errorf("%s strict: verdict %s, want %s; body %.200s", call.name, strictCall.verdict, row.want, strictCall.body)
				}
				continue
			}
			if pre := hp3r3PreExisting[row.name]; pre == "all" || pre == "managed" && call.managed || pre == "peruser" && !call.managed {
				if call.verdict != row.want {
					t.Logf("HP3R3ROW %s: pre-existing (base 18d0d88333), logged", call.name)
				}
				continue
			}
			if row.want != "" && call.verdict != row.want {
				t.Errorf("%s: verdict %s, want %s; body %.200s", call.name, call.verdict, row.want, call.body)
			}
		}
		if err := os.Chmod(f.homes, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if data, err := os.ReadFile(f.keys); err != nil || string(data) != "# decoy\n" {
		t.Fatalf("decoy keys file changed: %q %v", data, err)
	}
}

// hp3r3Script is a benign script of n statements that mixes if/for/while/
// case/{ } with assignments; many=false reuses four names.
func hp3r3Script(n int, many bool) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		k := i
		if !many {
			k = i % 4
		}
		switch i % 6 {
		case 0:
			fmt.Fprintf(&b, "if [ -f src/m%d.c ]; then o%d=build/m%d.o; else o%d=build/gen%d.o; fi\n", i, k, i, k, i)
		case 1:
			fmt.Fprintf(&b, "for f in src/*.c; do b%d=\"${f%%.c}.bak\"; cp \"$f\" \"$b%d\"; done\n", k, k)
		case 2:
			fmt.Fprintf(&b, "while read -r line; do n%d=$line; done < list.txt\n", k)
		case 3:
			fmt.Fprintf(&b, "case \"$MODE\" in debug) c%d=-g ;; release) c%d=-O2 ;; *) c%d=-O0 ;; esac\n", k, k, k)
		case 4:
			fmt.Fprintf(&b, "{ g%d=logs/g%d.log; mkdir -p logs; }\n", k, i)
		case 5:
			fmt.Fprintf(&b, "out%d=build/step%d.txt; printf \"%%s\\n\" \"$o%d\" > \"$out%d\"\n", k, i, k, k)
		}
	}
	return b.String()
}

var hp3r3Ordinary = []string{
	"git status && git diff --stat",
	"go test ./... 2>&1 | tail -20",
	`for f in *.txt; do cp "$f" "$f.bak"; done`,
	`mkdir -p build && cp a.txt build/ && echo ok >> build/log.txt`,
	`out=build; if [ -n "$DEBUG" ]; then out=build/debug; fi; mkdir -p "$out"; echo done >> "$out/build.log"`,
	`npm run build > build.log 2>&1 || tail -50 build.log`,
	`cat a.txt | sort | uniq -c > counts.txt`,
	"sed -i s/foo/bar/ a.txt",
}

// hp3r3Config is k defaulted settings ([ -n "$Vi" ] || Vi=opti), then a
// write through a conditionally chosen name: 2^k kept candidates.
func hp3r3Config(k int) string {
	var b strings.Builder
	for i := 1; i <= k; i++ {
		fmt.Fprintf(&b, "[ -n \"$V%d\" ] || V%d=opt%d\n", i, i, i)
	}
	b.WriteString("out=config.mk\nif [ -n \"$LOCAL\" ]; then out=config.local.mk; fi\necho \"V1=$V1\" > \"$out\"\n")
	return b.String()
}

// hp3r3Cases is k three-arm case statements on distinct names (4^k).
func hp3r3Cases(k int) string {
	var b strings.Builder
	for i := 1; i <= k; i++ {
		fmt.Fprintf(&b, "case \"$OS\" in linux) P%d=a;; darwin) P%d=b;; *) P%d=c;; esac\n", i, i, i)
	}
	b.WriteString("out=build.env\necho \"P1=$P1\" > \"$out\"\n")
	return b.String()
}

// hp3r3BuildCases is k option cases on distinct names, the allowed
// r3-allow-build-case shape repeated (3^k kept candidates).
func hp3r3BuildCases(k int) string {
	var b strings.Builder
	for i := 1; i <= k; i++ {
		fmt.Fprintf(&b, "case \"$1\" in -d) m%d=debug;; -p) m%d=profile;; esac\n", i, i)
	}
	b.WriteString("echo \"$m1\" > build.mode\n")
	return b.String()
}

// hp3r3BuildLoops is k backup loops on distinct names, the allowed
// r3-allow-for-bak shape repeated (2^k kept candidates).
func hp3r3BuildLoops(k int) string {
	var b strings.Builder
	for i := 1; i <= k; i++ {
		fmt.Fprintf(&b, "for f in *.txt; do o%d=$f.bak%d; cp \"$f\" \"$o%d\"; done\n", i, i, i)
	}
	return b.String()
}

func hp3r3Input(spec string) string {
	parts := strings.Split(spec, ":")
	n, _ := strconv.Atoi(parts[1])
	switch parts[0] {
	case "gen":
		return hp3r3Script(n, parts[2] == "many")
	case "cond":
		return hp3r3Config(n)
	case "case":
		return hp3r3Cases(n)
	case "ord":
		return hp3r3Ordinary[n]
	case "bcase":
		return hp3r3BuildCases(n)
	case "bfor":
		return hp3r3BuildLoops(n)
	}
	return spec
}

func hp3r3P50(d []time.Duration) (time.Duration, time.Duration) {
	s := append([]time.Duration(nil), d...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[len(s)/2], s[len(s)-1]
}

// TestHP3R3Perf measures one cell of one input: HP3R3_INPUT (gen:N:many|few,
// cond:K, case:K, ord:I), HP3R3_CELL (client, or claudecode|codex/managed|
// peruser), HP3R3_REPS. client is the hook client reading (hookpaths.Resolve,
// the managed header); a cell is the gateway decision.
func TestHP3R3Perf(t *testing.T) {
	spec, cell := os.Getenv("HP3R3_INPUT"), os.Getenv("HP3R3_CELL")
	if spec == "" || cell == "" {
		t.Skip("set HP3R3_INPUT and HP3R3_CELL")
	}
	reps := 5
	if v, err := strconv.Atoi(os.Getenv("HP3R3_REPS")); err == nil && v > 0 {
		reps = v
	}
	f := newB36ManagedHookFixture(t)
	for _, name := range []string{"a.txt", "list.txt"} {
		if err := os.WriteFile(filepath.Join(f.project, name), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	command := hp3r3Input(spec)
	payload := f.payload(t, command)
	var peak atomic.Uint64
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		sample := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
		for {
			select {
			case <-stop:
				return
			case <-time.After(2 * time.Millisecond):
			}
			metrics.Read(sample)
			v := sample[0].Value.Uint64()
			for {
				old := peak.Load()
				if v <= old || peak.CompareAndSwap(old, v) {
					break
				}
			}
			if v > 6<<30 {
				fmt.Printf("HP3PERF input=%s cell=%s OVERCAP heap=%dMB\n", spec, cell, v>>20)
				os.Exit(4)
			}
		}
	}()
	var call *hookCall
	var header string
	if cell != "client" {
		if strings.HasSuffix(cell, "/managed") {
			header = f.clientHeader(t, payload)
		}
		for _, c := range everyMode("p", payload, header) {
			mode := "peruser"
			if c.managed {
				mode = "managed"
			}
			if c.connector+"/"+mode == cell {
				call = c
			}
		}
		if call == nil {
			t.Fatalf("no cell %s", cell)
		}
		mode := os.FileMode(0o700)
		if call.managed {
			mode = 0
		}
		if err := os.Chmod(f.homes, mode); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.Chmod(f.homes, 0o700) }()
	}
	runtime.GC()
	peak.Store(0)
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	alloc0 := ms.TotalAlloc
	verdict := "-"
	var took []time.Duration
	for r := 0; r < reps; r++ {
		start := time.Now()
		if call == nil {
			f.clientHeader(t, payload)
		} else {
			verdict, _ = f.serve(call)
		}
		took = append(took, time.Since(start))
	}
	runtime.ReadMemStats(&ms)
	p50, max := hp3r3P50(took)
	fmt.Printf("HP3PERF input=%s cell=%s bytes=%d verdict=%s reps=%d p50=%s max=%s alloc=%dMB peakheap=%dMB\n", spec, cell,
		len(command), verdict, reps, p50.Round(time.Microsecond), max.Round(time.Microsecond),
		(ms.TotalAlloc-alloc0)/uint64(reps)>>20, peak.Load()>>20)
	if strings.HasPrefix(spec, "gen:50:") && p50 > 300*time.Millisecond {
		t.Errorf("%s %s: p50 %s exceeds the 300 ms review ceiling", spec, cell, p50)
	}
}

// TestHP3R3Why prints the four cell answers of HP3R3_WHY (a command, or
// gen:N:many|few for the generator).
func TestHP3R3Why(t *testing.T) {
	command := os.Getenv("HP3R3_WHY")
	if command == "" {
		t.Skip("set HP3R3_WHY")
	}
	if strings.Contains(command, ":") && !strings.ContainsAny(command, " ;") {
		command = hp3r3Input(command)
	}
	f := newB36ManagedHookFixture(t)
	for _, name := range []string{"a.txt", "list.txt"} {
		if err := os.WriteFile(filepath.Join(f.project, name), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	payload := f.payload(t, command)
	header := f.clientHeader(t, payload)
	if targets, ok := hookpaths.Decode(header); ok {
		for k, v := range targets {
			fmt.Printf("HP3HDR %q=%q\n", k, v)
		}
	}
	for _, call := range everyMode("why", payload, header) {
		mode := os.FileMode(0o700)
		if call.managed {
			mode = 0
		}
		if err := os.Chmod(f.homes, mode); err != nil {
			t.Fatal(err)
		}
		call.verdict, call.body = f.serve(call)
		fmt.Printf("HP3WHY %s | %s | %.400s\n", call.name, call.verdict, call.body)
	}
	_ = os.Chmod(f.homes, 0o700)
}
