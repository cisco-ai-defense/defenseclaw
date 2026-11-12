// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/effects"
)

type report struct {
	calls       int
	fullyKnown  int
	reasonHist  map[effects.ReasonCode]int
	byPlatform  map[string]*cell
	byDialect   map[effects.Dialect]*cell
	missTotal   map[string]int
	missExposed map[string]int
	missShape   map[string]int
}

type cell struct{ calls, known int }

func newReport() *report {
	return &report{
		reasonHist:  map[effects.ReasonCode]int{},
		byPlatform:  map[string]*cell{},
		byDialect:   map[effects.Dialect]*cell{},
		missTotal:   map[string]int{},
		missExposed: map[string]int{},
		missShape:   map[string]int{},
	}
}

func (r *report) observe(c corpusCase, res effects.Result) {
	r.calls++
	known := res.FullyKnown()
	if known {
		r.fullyKnown++
	}
	for _, u := range res.Unknowns {
		r.reasonHist[u.Code]++
	}
	for _, e := range res.Effects {
		for _, rs := range e.Reasons {
			r.reasonHist[rs.Code]++
		}
	}
	plat := c.Strata.Platform
	if plat == "" {
		plat = "unknown"
	}
	cp := r.byPlatform[plat]
	if cp == nil {
		cp = &cell{}
		r.byPlatform[plat] = cp
	}
	cp.calls++
	if known {
		cp.known++
	}
	cd := r.byDialect[res.Dialect]
	if cd == nil {
		cd = &cell{}
		r.byDialect[res.Dialect] = cd
	}
	cd.calls++
	if known {
		cd.known++
	}
}

// observeMiss records, for a phase-1 miss case, whether its aggregated effects
// expose a harmful shape, and which shape.
func (r *report) observeMiss(kind string, effs []effects.Effect) {
	r.missTotal[kind]++
	shapes := harmfulShapes(effs)
	if len(shapes) > 0 {
		r.missExposed[kind]++
		for _, s := range shapes {
			r.missShape[s]++
		}
	}
}

// harmfulShapes names the dangerous effect shapes present across a case's
// effects. It is a shadow-mode diagnostic, not a verdict.
func harmfulShapes(effs []effects.Effect) []string {
	var sensitiveRead, egress, write, exec, fetch bool
	var sensitiveWriteDelete, worldPerm bool
	writeKeys := map[string]bool{}
	execKeys := map[string]bool{}
	for _, e := range effs {
		switch e.Kind {
		case effects.KindRead:
			if isSensitive(e.Target.Path) {
				sensitiveRead = true
			}
		case effects.KindNetworkSend:
			egress = true
		case effects.KindNetworkFetch:
			fetch = true
		case effects.KindWrite, effects.KindAppend:
			write = true
			if k := e.Target.Key(); k != "" {
				writeKeys[k] = true
			}
			if isSensitive(e.Target.Path) {
				sensitiveWriteDelete = true
			}
		case effects.KindDelete:
			if isSensitive(e.Target.Path) {
				sensitiveWriteDelete = true
			}
		case effects.KindExec:
			exec = true
			if k := e.Target.Key(); k != "" {
				execKeys[k] = true
			}
		case effects.KindPermissionChange:
			worldPerm = true
		}
	}
	dropperSamePath := false
	for k := range writeKeys {
		if execKeys[k] {
			dropperSamePath = true
		}
	}
	var out []string
	if sensitiveRead && egress {
		out = append(out, "sensitive_read+egress")
	}
	if fetch && exec {
		out = append(out, "fetch+exec")
	}
	if dropperSamePath {
		out = append(out, "write+exec_same_path")
	} else if write && exec {
		out = append(out, "write+exec")
	}
	if sensitiveWriteDelete {
		out = append(out, "sensitive_write_or_delete")
	}
	if worldPerm {
		out = append(out, "permission_change")
	}
	if egress && !sensitiveRead {
		out = append(out, "egress")
	}
	return out
}

var sensitiveMarkers = []string{
	"/.ssh/", "id_rsa", "id_ed25519", "authorized_keys", "/.aws/", "credentials", "/.config/gh",
	".env", "/etc/shadow", "/etc/passwd", ".git-credentials", ".npmrc", ".pypirc", "/.kube/",
	".docker/config", "keychain", "/.gnupg/", ".netrc", "token", "secret", ".pem", ".pfx",
	"ntds.dit", "sam", "lsass",
}

func isSensitive(p string) bool {
	if p == "" {
		return false
	}
	lp := strings.ToLower(p)
	for _, m := range sensitiveMarkers {
		if strings.Contains(lp, m) {
			return true
		}
	}
	return false
}

func (r *report) print(label string) {
	fmt.Printf("=== s7 effects shadow report: %s ===\n", label)
	pct := func(n, d int) string {
		if d == 0 {
			return "n/a"
		}
		return fmt.Sprintf("%.1f%%", 100*float64(n)/float64(d))
	}
	fmt.Printf("tool calls: %d\n", r.calls)
	fmt.Printf("fully known: %d (%s)\n", r.fullyKnown, pct(r.fullyKnown, r.calls))

	fmt.Println("\nunknown reasons (count across all effects):")
	type kv struct {
		k effects.ReasonCode
		v int
	}
	var rs []kv
	for k, v := range r.reasonHist {
		rs = append(rs, kv{k, v})
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].v > rs[j].v })
	for _, e := range rs {
		fmt.Printf("  %-22s %d\n", e.k, e.v)
	}

	fmt.Println("\nby platform:")
	for _, p := range sortedKeys(r.byPlatform) {
		c := r.byPlatform[p]
		fmt.Printf("  %-16s calls=%-7d known=%s\n", p, c.calls, pct(c.known, c.calls))
	}
	fmt.Println("by dialect:")
	for d, c := range r.byDialect {
		fmt.Printf("  %-12s calls=%-7d known=%s\n", d, c.calls, pct(c.known, c.calls))
	}

	if len(r.missTotal) > 0 {
		fmt.Println("\nphase-1 miss exposure (effects reveal a harmful shape):")
		for _, k := range sortedKeys2(r.missTotal) {
			fmt.Printf("  %-18s %d/%d exposed (%s)\n", k, r.missExposed[k], r.missTotal[k], pct(r.missExposed[k], r.missTotal[k]))
		}
		fmt.Println("  shapes seen:")
		for _, s := range sortedKeys2(r.missShape) {
			fmt.Printf("    %-26s %d\n", s, r.missShape[s])
		}
	}
}

func sortedKeys(m map[string]*cell) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return k
}

func sortedKeys2(m map[string]int) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return k
}
