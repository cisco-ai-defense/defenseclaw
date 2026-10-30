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

// Package lazyregexp is a regexp.MustCompile that compiles on first use.
//
// Every DefenseClaw binary links the whole product (the hook a coding agent
// starts for each tool call is the gateway binary), and package-level
// regexp.MustCompile calls ran at every start: over a thousand patterns,
// about 23 MB of the 38 MB the hook allocated before main and a large part
// of its 37 ms of package initialisation (r106 performance audit; the same
// class as GAP-1225 and GAP-1283 in internal/actionfacts). A pattern made
// with New is compiled by the first call that matches with it, once, and
// shared after that; a Regexp is safe for concurrent use.
//
// MustCompile panicked at start for a pattern that does not compile; a
// lazy pattern would panic at first use instead. In a test binary New
// compiles at once, so every package's tests still fail at start on a bad
// pattern, as before.
package lazyregexp

import (
	"io"
	"regexp"
	"sync"
	"testing"
)

// Regexp is a *regexp.Regexp compiled on first use.
type Regexp struct {
	str  string
	once sync.Once
	rx   *regexp.Regexp
}

var (
	registryMu sync.Mutex
	registry   []*Regexp
)

// New returns the lazily compiled form of regexp.MustCompile(str).
func New(str string) *Regexp {
	lr := &Regexp{str: str}
	if testing.Testing() {
		lr.Regexp()
	}
	registryMu.Lock()
	registry = append(registry, lr)
	registryMu.Unlock()
	return lr
}

// CompileAll compiles every pattern made with New so far. A long-running
// process (the gateway) calls it in the background after start so that its
// first hook does not compile the patterns it needs.
func CompileAll() {
	registryMu.Lock()
	all := append([]*Regexp(nil), registry...)
	registryMu.Unlock()
	for _, lr := range all {
		lr.Regexp()
	}
}

// Regexp returns the compiled pattern, compiling it on the first call.
func (r *Regexp) Regexp() *regexp.Regexp {
	r.once.Do(func() { r.rx = regexp.MustCompile(r.str) })
	return r.rx
}

func (r *Regexp) String() string { return r.str }

func (r *Regexp) Match(b []byte) bool               { return r.Regexp().Match(b) }
func (r *Regexp) MatchString(s string) bool         { return r.Regexp().MatchString(s) }
func (r *Regexp) MatchReader(rr io.RuneReader) bool { return r.Regexp().MatchReader(rr) }

func (r *Regexp) Find(b []byte) []byte                 { return r.Regexp().Find(b) }
func (r *Regexp) FindIndex(b []byte) []int             { return r.Regexp().FindIndex(b) }
func (r *Regexp) FindString(s string) string           { return r.Regexp().FindString(s) }
func (r *Regexp) FindStringIndex(s string) []int       { return r.Regexp().FindStringIndex(s) }
func (r *Regexp) FindSubmatch(b []byte) [][]byte       { return r.Regexp().FindSubmatch(b) }
func (r *Regexp) FindSubmatchIndex(b []byte) []int     { return r.Regexp().FindSubmatchIndex(b) }
func (r *Regexp) FindStringSubmatch(s string) []string { return r.Regexp().FindStringSubmatch(s) }
func (r *Regexp) FindStringSubmatchIndex(s string) []int {
	return r.Regexp().FindStringSubmatchIndex(s)
}
func (r *Regexp) FindReaderIndex(rr io.RuneReader) []int { return r.Regexp().FindReaderIndex(rr) }
func (r *Regexp) FindAll(b []byte, n int) [][]byte       { return r.Regexp().FindAll(b, n) }
func (r *Regexp) FindAllIndex(b []byte, n int) [][]int   { return r.Regexp().FindAllIndex(b, n) }
func (r *Regexp) FindAllString(s string, n int) []string { return r.Regexp().FindAllString(s, n) }
func (r *Regexp) FindAllStringIndex(s string, n int) [][]int {
	return r.Regexp().FindAllStringIndex(s, n)
}
func (r *Regexp) FindAllSubmatch(b []byte, n int) [][][]byte { return r.Regexp().FindAllSubmatch(b, n) }
func (r *Regexp) FindAllSubmatchIndex(b []byte, n int) [][]int {
	return r.Regexp().FindAllSubmatchIndex(b, n)
}
func (r *Regexp) FindAllStringSubmatch(s string, n int) [][]string {
	return r.Regexp().FindAllStringSubmatch(s, n)
}
func (r *Regexp) FindAllStringSubmatchIndex(s string, n int) [][]int {
	return r.Regexp().FindAllStringSubmatchIndex(s, n)
}

func (r *Regexp) ReplaceAll(src, repl []byte) []byte { return r.Regexp().ReplaceAll(src, repl) }
func (r *Regexp) ReplaceAllFunc(src []byte, repl func([]byte) []byte) []byte {
	return r.Regexp().ReplaceAllFunc(src, repl)
}
func (r *Regexp) ReplaceAllLiteral(src, repl []byte) []byte {
	return r.Regexp().ReplaceAllLiteral(src, repl)
}
func (r *Regexp) ReplaceAllString(src, repl string) string {
	return r.Regexp().ReplaceAllString(src, repl)
}
func (r *Regexp) ReplaceAllStringFunc(src string, repl func(string) string) string {
	return r.Regexp().ReplaceAllStringFunc(src, repl)
}
func (r *Regexp) ReplaceAllLiteralString(src, repl string) string {
	return r.Regexp().ReplaceAllLiteralString(src, repl)
}
func (r *Regexp) Expand(dst []byte, template []byte, src []byte, match []int) []byte {
	return r.Regexp().Expand(dst, template, src, match)
}
func (r *Regexp) ExpandString(dst []byte, template string, src string, match []int) []byte {
	return r.Regexp().ExpandString(dst, template, src, match)
}

func (r *Regexp) Split(s string, n int) []string { return r.Regexp().Split(s, n) }
func (r *Regexp) SubexpNames() []string          { return r.Regexp().SubexpNames() }
func (r *Regexp) SubexpIndex(name string) int    { return r.Regexp().SubexpIndex(name) }
func (r *Regexp) NumSubexp() int                 { return r.Regexp().NumSubexp() }
func (r *Regexp) LiteralPrefix() (string, bool)  { return r.Regexp().LiteralPrefix() }
