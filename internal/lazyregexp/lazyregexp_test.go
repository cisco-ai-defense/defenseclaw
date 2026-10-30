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

package lazyregexp

import (
	"regexp"
	"sync"
	"testing"
)

func TestLazyRegexpMatchesLikeRegexp(t *testing.T) {
	const expr = `^(?P<name>[a-z]+)-(?P<n>[0-9]{1,3})$`
	lazy, eager := New(expr), regexp.MustCompile(expr)
	for _, in := range []string{"perf-106", "Perf-106", "perf-1066", "a-1", ""} {
		if lazy.MatchString(in) != eager.MatchString(in) {
			t.Fatalf("MatchString(%q) differs", in)
		}
		if got, want := lazy.FindStringSubmatch(in), eager.FindStringSubmatch(in); len(got) != len(want) {
			t.Fatalf("FindStringSubmatch(%q) = %q, want %q", in, got, want)
		}
		if lazy.ReplaceAllString(in, "${n}") != eager.ReplaceAllString(in, "${n}") {
			t.Fatalf("ReplaceAllString(%q) differs", in)
		}
	}
	if lazy.String() != expr || lazy.SubexpIndex("n") != 2 || lazy.NumSubexp() != 2 {
		t.Fatal("pattern metadata differs from regexp")
	}
}

func TestLazyRegexpCompilesOnceUnderConcurrency(t *testing.T) {
	lazy := New(`x+`)
	var wg sync.WaitGroup
	seen := make([]*regexp.Regexp, 32)
	for i := range seen {
		wg.Add(1)
		go func() {
			defer wg.Done()
			seen[i] = lazy.Regexp()
		}()
	}
	wg.Wait()
	for _, re := range seen {
		if re != seen[0] {
			t.Fatal("concurrent first uses compiled more than one Regexp")
		}
	}
}

// A test binary compiles at New, so a bad pattern still fails a package's
// tests at start as regexp.MustCompile did.
func TestNewCompilesAtOnceInTests(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("New with an invalid pattern did not panic in a test binary")
		}
	}()
	New(`([`)
}

func TestCompileAllCompilesEveryPattern(t *testing.T) {
	lazy := &Regexp{str: `y+`}
	registryMu.Lock()
	registry = append(registry, lazy)
	registryMu.Unlock()
	CompileAll()
	if lazy.rx == nil {
		t.Fatal("CompileAll left a registered pattern uncompiled")
	}
}
