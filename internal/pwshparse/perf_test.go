// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package pwshparse_test

import (
	"encoding/base64"
	"fmt"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/psparse"
	"github.com/defenseclaw/defenseclaw/internal/pwshparse"
)

// TestParseLatencyVsPsparse compares the per-row parse latency of the port with the reader it replaces
// (internal/psparse) on the public fixture rows: for every row both parsers run alternately, the best of
// PWSHPERF_REPS (default 5) is kept, and the p50/p99/max of each parser are reported. Set PWSHPERF=1 to run
// it (timing runs belong under the box flock); PWSHPERF_MAX_RATIO fails the test above that p99 ratio.
func TestParseLatencyVsPsparse(t *testing.T) {
	if os.Getenv("PWSHPERF") == "" {
		t.Skip("PWSHPERF not set")
	}
	reps := 5
	if s := os.Getenv("PWSHPERF_REPS"); s != "" {
		fmt.Sscan(s, &reps)
	}
	ob := pwshparse.ReadGzB(t, "pub.b64.gz")
	var scripts []string
	for ob.Scan() {
		b, err := base64.StdEncoding.DecodeString(ob.Text())
		if err != nil {
			t.Fatal(err)
		}
		scripts = append(scripts, string(b))
	}
	// rows past 4 KiB are the nesting bombs and size probes; they are reported on their own
	var small []int
	for i, s := range scripts {
		if len(s) <= 4096 {
			small = append(small, i)
		}
	}
	treeOnly := os.Getenv("PWSHPERF_TREE") != ""
	measure := func(rows []int) (old, port []time.Duration) {
		for _, i := range rows {
			s := scripts[i]
			bo, bp := time.Duration(1<<62), time.Duration(1<<62)
			for r := 0; r < reps; r++ {
				t0 := time.Now()
				psparse.Parse(s, psparse.Options{Dialect: psparse.DialectUnknown})
				if d := time.Since(t0); d < bo {
					bo = d
				}
				t0 = time.Now()
				if treeOnly {
					pwshparse.ParseTree(s)
				} else {
					pwshparse.Parse(s)
				}
				if d := time.Since(t0); d < bp {
					bp = d
				}
			}
			old = append(old, bo)
			port = append(port, bp)
		}
		return
	}
	pct := func(ds []time.Duration, q float64) time.Duration {
		c := append([]time.Duration(nil), ds...)
		sort.Slice(c, func(i, j int) bool { return c[i] < c[j] })
		return c[int(float64(len(c)-1)*q)]
	}
	old, port := measure(small)
	fmt.Printf("rows<=4KiB %d reps %d\n", len(small), reps)
	fmt.Printf("%-10s p50 %-10v p99 %-10v p99.9 %-10v max %v\n", "psparse", pct(old, .5), pct(old, .99), pct(old, .999), pct(old, 1))
	fmt.Printf("%-10s p50 %-10v p99 %-10v p99.9 %-10v max %v\n", "pwshparse", pct(port, .5), pct(port, .99), pct(port, .999), pct(port, 1))
	ratio := float64(pct(port, .99)) / float64(pct(old, .99))
	fmt.Printf("p99 ratio pwshparse/psparse %.3f (p50 ratio %.3f)\n", ratio, float64(pct(port, .5))/float64(pct(old, .5)))
	if s := os.Getenv("PWSHPERF_MAX_RATIO"); s != "" {
		var m float64
		fmt.Sscan(s, &m)
		if ratio > m {
			t.Errorf("p99 ratio %.3f above %.3f", ratio, m)
		}
	}
}

// BenchmarkParseFixture parses every public fixture row up to 4 KiB per iteration (profiling aid).
func BenchmarkParseFixture(b *testing.B) {
	ob := pwshparse.ReadGzB(b, "pub.b64.gz")
	var scripts []string
	for ob.Scan() {
		raw, err := base64.StdEncoding.DecodeString(ob.Text())
		if err != nil {
			b.Fatal(err)
		}
		if len(raw) <= 4096 {
			scripts = append(scripts, string(raw))
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		for _, s := range scripts {
			pwshparse.Parse(s)
		}
	}
}
