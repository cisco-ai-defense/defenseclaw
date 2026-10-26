//go:build !windows

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

// Measurement only (not committed): DC_MEASURE_HOME=<home> go test -run TestZZMeasureHomeWalk -v
func TestZZMeasureHomeWalk(t *testing.T) {
	home := os.Getenv("DC_MEASURE_HOME")
	if home == "" {
		t.Skip("DC_MEASURE_HOME unset")
	}
	walk := func(root string, budget int) (int, int, bool, time.Duration) {
		old := privateInstallWalkMaxEntries
		privateInstallWalkMaxEntries = budget
		defer func() { privateInstallWalkMaxEntries = old }()
		start := time.Now()
		p, ok := walkPrivateNPMPrefixes(context.Background(), root, privateInstallWalk{open: unixPrivateWalkOpener(home), unreachable: unixPrivateWalkUnreachable, homeLinks: true})
		return budget - zzLastBudget, len(p), ok, time.Since(start)
	}
	used, n, ok, d := walk(home, 1<<19)
	t.Logf("SHIPPED budget=%d complete=%v prefixes=%d used=%d took=%s", 1<<19, ok, n, used, d)
	used, n, ok, d = walk(home, 1<<30)
	t.Logf("UNBOUNDED complete=%v prefixes=%d entries=%d took=%s", ok, n, used, d)
	var rows []struct {
		name string
		used int
	}
	var tops []string
	l1, _ := os.ReadDir(home)
	for _, e := range l1 {
		if !e.Type().IsDir() {
			continue
		}
		tops = append(tops, e.Name())
		l2, _ := os.ReadDir(filepath.Join(home, e.Name()))
		for _, f := range l2 {
			if f.Type().IsDir() {
				tops = append(tops, filepath.Join(e.Name(), f.Name()))
			}
		}
	}
	for _, rel := range tops {
		u, _, _, _ := walk(filepath.Join(home, rel), 1<<30)
		rows = append(rows, struct {
			name string
			used int
		}{rel, u})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].used > rows[j].used })
	for i, r := range rows {
		if i >= 60 || r.used < 2000 {
			break
		}
		t.Logf("TOP %9d %s", r.used, r.name)
	}
}
