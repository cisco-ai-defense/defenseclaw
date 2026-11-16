// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"regexp"
	"sync"
)

// lazyRegexp is a package-level pattern compiled on its first use.
//
// Every program that links this package used to compile all of its
// package-level patterns before main: about 8.4 MB and 50,000 allocations
// on every start. The per-user hook transport (defenseclaw-hook-post) and
// the native hook link this package through hookpaths, so each hook call
// paid that before it sent a byte, about a third of the CPU of a call, and
// on a busy host calls took over two seconds (GAP-1225, GAP-1283). A pattern
// is now compiled once, by the first check that needs it, and shared after
// that (sync.Once, safe for concurrent checks in the gateway).
//
// MustCompile panicked at start for a pattern that does not compile; here it
// would panic at first use instead, so TestLazyRegexpsCompile compiles every
// pattern registered in lazyRegexps.
type lazyRegexp struct {
	expr string
	once sync.Once
	re   *regexp.Regexp
}

// lazyRegexps lists every lazyMustCompile pattern, for TestLazyRegexpsCompile.
var lazyRegexps []*lazyRegexp

// lazyMustCompile is regexp.MustCompile, deferred to the first use of the
// pattern.
func lazyMustCompile(expr string) *lazyRegexp {
	pattern := &lazyRegexp{expr: expr}
	lazyRegexps = append(lazyRegexps, pattern)
	return pattern
}

func (l *lazyRegexp) compiled() *regexp.Regexp {
	l.once.Do(func() { l.re = regexp.MustCompile(l.expr) })
	return l.re
}

func (l *lazyRegexp) MatchString(s string) bool { return l.compiled().MatchString(s) }

func (l *lazyRegexp) Match(b []byte) bool { return l.compiled().Match(b) }

func (l *lazyRegexp) FindStringSubmatch(s string) []string {
	return l.compiled().FindStringSubmatch(s)
}

func (l *lazyRegexp) FindStringSubmatchIndex(s string) []int {
	return l.compiled().FindStringSubmatchIndex(s)
}

func (l *lazyRegexp) FindStringIndex(s string) []int { return l.compiled().FindStringIndex(s) }

func (l *lazyRegexp) FindAllString(s string, n int) []string {
	return l.compiled().FindAllString(s, n)
}

func (l *lazyRegexp) FindAllStringIndex(s string, n int) [][]int {
	return l.compiled().FindAllStringIndex(s, n)
}

func (l *lazyRegexp) FindAllStringSubmatch(s string, n int) [][]string {
	return l.compiled().FindAllStringSubmatch(s, n)
}

func (l *lazyRegexp) ReplaceAllString(src, repl string) string {
	return l.compiled().ReplaceAllString(src, repl)
}
