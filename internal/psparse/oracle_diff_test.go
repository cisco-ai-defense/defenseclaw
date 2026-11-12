// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package psparse

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// oracleScript is the reference-parser projection emitter. It runs under
// PowerShell 7 (System.Management.Automation.Language.Parser) and emits, per
// input line, the same Invocation projection shape that Project produces, so
// the two can be diffed one-to-one. It contains no backtick characters so it
// can live in a Go raw string literal.
const oracleScript = `
param([string]$InFile)
$ErrorActionPreference = 'Stop'
function Get-Kind($el) {
  switch ($el.GetType().Name) {
    'StringConstantExpressionAst'    { 'str' }
    'ExpandableStringExpressionAst'  { 'expand' }
    'VariableExpressionAst'          { if ($el.Splatted) { 'splat' } else { 'var' } }
    'ConstantExpressionAst'          { 'num' }
    'ScriptBlockExpressionAst'       { 'sb' }
    'SubExpressionAst'               { 'sub' }
    'ArrayExpressionAst'             { 'arr' }
    'ArrayLiteralAst'                { 'arrlit' }
    'HashtableAst'                   { 'hash' }
    'ParenExpressionAst'             { 'paren' }
    'InvokeMemberExpressionAst'      { 'member' }
    'MemberExpressionAst'            { 'member' }
    'IndexExpressionAst'             { 'index' }
    'TypeExpressionAst'              { 'type' }
    'ConvertExpressionAst'           { 'type' }
    'BinaryExpressionAst'            { 'op' }
    'UnaryExpressionAst'             { 'op' }
    'ParamBlockAst'                  { 'other' }
    default                          { 'other' }
  }
}
$lines = [System.IO.File]::ReadAllLines($InFile)
$i = -1
foreach ($line in $lines) {
  $i++
  if ([string]::IsNullOrEmpty($line)) { Write-Output ('{"i":' + $i + ',"err":true,"proj":[]}'); continue }
  $text = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($line))
  $errs = $null; $toks = $null
  try {
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$toks, [ref]$errs)
  } catch {
    Write-Output ('{"i":' + $i + ',"err":true,"proj":[]}'); continue
  }
  $hadErr = ($errs -ne $null -and $errs.Count -gt 0)
  $cmds = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
  $proj = New-Object System.Collections.ArrayList
  foreach ($c in $cmds) {
    $op = ''
    switch ($c.InvocationOperator.ToString()) { 'Ampersand' { $op = '&' } 'Dot' { $op = '.' } }
    $els = $c.CommandElements
    $name = ''; $nk = 'none'
    if ($els.Count -gt 0) {
      $n0 = $els[0]
      $tn = $n0.GetType().Name
      if ($tn -eq 'StringConstantExpressionAst') { $nk = 'lit'; $name = ([string]$n0.Value).ToLower() }
      elseif ($tn -eq 'ExpandableStringExpressionAst') { $nk = 'expand' }
      elseif ($tn -eq 'VariableExpressionAst') { $nk = 'var' }
      else { $nk = 'expr' }
    }
    $params = New-Object System.Collections.ArrayList
    $args = New-Object System.Collections.ArrayList
    for ($k = 1; $k -lt $els.Count; $k++) {
      $el = $els[$k]
      if ($el.GetType().Name -eq 'CommandParameterAst') {
        $pn = '-' + ([string]$el.ParameterName).ToLower()
        if ($el.Argument -ne $null) { $pn = $pn + ':' }
        [void]$params.Add($pn)
      } else {
        [void]$args.Add((Get-Kind $el))
      }
    }
    $rc = 0; if ($c.Redirections -ne $null) { $rc = $c.Redirections.Count }
    $redirs = New-Object System.Collections.ArrayList
    for ($r = 0; $r -lt $rc; $r++) { [void]$redirs.Add('r') }
    [void]$proj.Add([ordered]@{ op = $op; name = $name; nk = $nk; params = $params; args = $args; redirs = $redirs })
  }
  $obj = [ordered]@{ i = $i; err = $hadErr; proj = $proj }
  Write-Output ($obj | ConvertTo-Json -Compress -Depth 20)
}
`

type oracleLine struct {
	I    int         `json:"i"`
	Err  bool        `json:"err"`
	Proj []oracleInv `json:"proj"`
}

type oracleInv struct {
	Op     string   `json:"op"`
	Name   string   `json:"name"`
	NK     string   `json:"nk"`
	Params []string `json:"params"`
	Args   []string `json:"args"`
	Redirs []string `json:"redirs"`
}

type disagreement struct {
	Idx       int          `json:"idx"`
	Bucket    string       `json:"bucket"`
	OracleErr bool         `json:"oracle_err"`
	Text      string       `json:"text"`
	My        []Invocation `json:"my"`
	Oracle    []oracleInv  `json:"oracle"`
}

type corpusItem struct {
	Text    string
	Dialect Dialect
}

func loadCorpus(t *testing.T, paths []string) []corpusItem {
	t.Helper()
	seen := map[string]bool{}
	var items []corpusItem
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			t.Fatalf("open corpus %s: %v", p, err)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<22)
		for sc.Scan() {
			var row struct {
				Text    string `json:"text"`
				Dialect string `json:"dialect"`
			}
			if json.Unmarshal(sc.Bytes(), &row) != nil || strings.TrimSpace(row.Text) == "" {
				continue
			}
			if seen[row.Text] {
				continue
			}
			seen[row.Text] = true
			d := DialectPwsh7
			if row.Dialect == "ps51" || row.Dialect == "windowsps" {
				d = DialectWindowsPS51
			}
			items = append(items, corpusItem{Text: row.Text, Dialect: d})
		}
		f.Close()
	}
	return items
}

// TestOracleDifferential compares psparse's command/argument projection with
// the PowerShell reference parser over the corpora. It is skipped unless
// PSPARSE_ORACLE (path to pwsh) and PSPARSE_CORPUS (colon-separated JSONL
// paths) are set, so it never runs in CI where pwsh is absent.
func TestOracleDifferential(t *testing.T) {
	pwsh := os.Getenv("PSPARSE_ORACLE")
	corpusEnv := os.Getenv("PSPARSE_CORPUS")
	if pwsh == "" || corpusEnv == "" {
		t.Skip("set PSPARSE_ORACLE (pwsh path) and PSPARSE_CORPUS (JSONL paths) to run the differential")
	}
	items := loadCorpus(t, strings.Split(corpusEnv, ":"))
	// include the reviewer's hand-written valid-PowerShell grammar lines so the
	// node-level differential covers the same corpus as the value gate.
	seenExtra := map[string]bool{}
	for _, it := range items {
		seenExtra[it.Text] = true
	}
	for _, s := range revExtraLines {
		t := bq2(s)
		if !seenExtra[t] {
			seenExtra[t] = true
			items = append(items, corpusItem{Text: t, Dialect: DialectPwsh7})
		}
	}
	if len(items) == 0 {
		t.Fatal("empty corpus")
	}

	// Write base64-encoded command text, one per line, for the oracle.
	in, err := os.CreateTemp("", "psparse-in-*.b64")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(in.Name())
	bw := bufio.NewWriter(in)
	for _, it := range items {
		bw.WriteString(base64.StdEncoding.EncodeToString([]byte(it.Text)))
		bw.WriteByte('\n')
	}
	bw.Flush()
	in.Close()

	scriptFile, err := os.CreateTemp("", "psparse-oracle-*.ps1")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(scriptFile.Name())
	scriptFile.WriteString(oracleScript)
	scriptFile.Close()

	cmd := exec.Command(pwsh, "-NoProfile", "-NonInteractive", "-File", scriptFile.Name(), in.Name())
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("oracle run failed: %v (stderr tail: %s)", err, tailStderr(err))
	}
	oracle := map[int]oracleLine{}
	osc := bufio.NewScanner(strings.NewReader(string(out)))
	osc.Buffer(make([]byte, 1<<20), 1<<22)
	for osc.Scan() {
		line := strings.TrimSpace(osc.Text())
		if line == "" {
			continue
		}
		var ol oracleLine
		if json.Unmarshal([]byte(line), &ol) != nil {
			continue
		}
		oracle[ol.I] = ol
	}

	var (
		total, oracleClean, agreeAll, agreeClean int
		buckets                                  = map[string]int{}
		samples                                  = map[string][]int{}
		dump                                     []disagreement
	)
	for i, it := range items {
		total++
		ol, ok := oracle[i]
		if !ok {
			buckets["oracle-missing"]++
			continue
		}
		my := Project(mustParse(it.Text, it.Dialect))
		bucket := diffProjection(my, ol.Proj)
		if !ol.Err {
			oracleClean++
		}
		if bucket == "" {
			agreeAll++
			if !ol.Err {
				agreeClean++
			}
			continue
		}
		buckets[bucket]++
		if len(samples[bucket]) < 12 {
			samples[bucket] = append(samples[bucket], i)
		}
		dump = append(dump, disagreement{Idx: i, Bucket: bucket, OracleErr: ol.Err, Text: it.Text, My: my, Oracle: ol.Proj})
	}
	if dp := os.Getenv("PSPARSE_DUMP"); dp != "" {
		df, _ := os.Create(dp)
		enc := json.NewEncoder(df)
		for _, d := range dump {
			enc.Encode(d)
		}
		df.Close()
	}

	report := buildReport(total, oracleClean, agreeAll, agreeClean, buckets, samples, items, oracle)
	if rp := os.Getenv("PSPARSE_REPORT"); rp != "" {
		os.WriteFile(rp, []byte(report), 0o644)
	}
	t.Logf("\n%s", report)

	// Floor guard: once the number is known this is set via PSPARSE_MIN_AGREE
	// (percent of oracle-clean lines). Absent, the test only measures.
	if minStr := os.Getenv("PSPARSE_MIN_AGREE"); minStr != "" && oracleClean > 0 {
		var min int
		if _, err := fmtSscan(minStr, &min); err == nil {
			got := agreeClean * 100 / oracleClean
			if got < min {
				t.Errorf("oracle agreement on clean lines %d%% < floor %d%%", got, min)
			}
		}
	}
}

func mustParse(text string, d Dialect) *Script {
	sc, _ := Parse(text, Options{Dialect: d})
	return sc
}

// diffProjection returns "" when the two projections match structurally, else
// the name of the first disagreement bucket.
func diffProjection(my []Invocation, oracle []oracleInv) string {
	if len(my) != len(oracle) {
		return "count-mismatch"
	}
	for i := range my {
		m, o := my[i], oracle[i]
		if m.Op != o.Op {
			return "op-mismatch"
		}
		if m.NK != o.NK {
			return "namekind-mismatch"
		}
		if m.NK == "lit" && m.Name != o.Name {
			return "name-mismatch"
		}
		if !eqStr(m.Params, o.Params) {
			return "param-mismatch"
		}
		if m.Stop {
			// verbatim --% tail is a known divergence: the reference parser
			// still lists the tail as string elements. Accept name+params.
			continue
		}
		if !eqStr(m.Args, o.Args) {
			return "arg-mismatch"
		}
		if len(m.Redirs) != len(o.Redirs) {
			return "redir-mismatch"
		}
	}
	return ""
}

func eqStr(a, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return reflect.DeepEqual(a, b)
}

func buildReport(total, oracleClean, agreeAll, agreeClean int, buckets map[string]int, samples map[string][]int, items []corpusItem, oracle map[int]oracleLine) string {
	var b strings.Builder
	b.WriteString("=== psparse oracle differential ===\n")
	b.WriteString(sprintf("corpus lines:            %d\n", total))
	b.WriteString(sprintf("oracle parsed clean:     %d\n", oracleClean))
	if total > 0 {
		b.WriteString(sprintf("agreement (all lines):   %d / %d = %.2f%%\n", agreeAll, total, pct(agreeAll, total)))
	}
	if oracleClean > 0 {
		b.WriteString(sprintf("agreement (clean lines): %d / %d = %.2f%%\n", agreeClean, oracleClean, pct(agreeClean, oracleClean)))
	}
	b.WriteString("\ndisagreement classes:\n")
	keys := make([]string, 0, len(buckets))
	for k := range buckets {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return buckets[keys[i]] > buckets[keys[j]] })
	for _, k := range keys {
		b.WriteString(sprintf("  %-20s %d   sample idx: %v\n", k, buckets[k], samples[k]))
	}
	return b.String()
}

func pct(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) * 100 / float64(b)
}
