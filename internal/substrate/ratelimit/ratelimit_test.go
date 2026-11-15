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

package ratelimit

import (
	"fmt"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func TestFloodingActorIsLimitedAtItsOwnBucket(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	l := New(Config{PerActorRPS: 20, PerAtespaceRPS: 500, Now: c.now})
	admitted, limited := 0, 0
	for i := 0; i < 1000; i++ {
		release, err := l.Acquire("eng", "flood")
		if err != nil {
			if s, ok := IsLimited(err); !ok || s != ScopeActor {
				t.Fatalf("scope %v", err)
			}
			limited++
			continue
		}
		release()
		admitted++
	}
	if admitted != 40 || limited != 960 {
		t.Fatalf("admitted %d limited %d, want burst 40", admitted, limited)
	}
	// Ten other actors in the same atespace are not affected.
	for i := 0; i < 10; i++ {
		for j := 0; j < 20; j++ {
			release, err := l.Acquire("eng", fmt.Sprintf("quiet-%d", i))
			if err != nil {
				t.Fatalf("quiet actor %d request %d: %v", i, j, err)
			}
			release()
		}
	}
	// One second later the flooder gets its rate again.
	c.t = c.t.Add(time.Second)
	if _, err := l.Acquire("eng", "flood"); err != nil {
		t.Fatalf("after refill: %v", err)
	}
}

func TestInFlightCap(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	l := New(Config{PerActorRPS: 1000, PerActorInFlight: 3, Now: c.now})
	var releases []func()
	for i := 0; i < 3; i++ {
		r, err := l.Acquire("eng", "a")
		if err != nil {
			t.Fatal(err)
		}
		releases = append(releases, r)
	}
	if _, err := l.Acquire("eng", "a"); err == nil {
		t.Fatal("fourth concurrent request admitted")
	} else if s, _ := IsLimited(err); s != ScopeInFlight {
		t.Fatalf("scope %s", s)
	}
	releases[0]()
	releases[0]() // a second call is harmless
	if _, err := l.Acquire("eng", "a"); err != nil {
		t.Fatalf("after release: %v", err)
	}
}

func TestAtespaceFairShare(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	// 10 rps per atespace, actors may each do 100: the atespace binds.
	l := New(Config{PerActorRPS: 100, PerAtespaceRPS: 10, Now: c.now})
	// A heavy actor drains the atespace bucket.
	heavy := 0
	for i := 0; i < 50; i++ {
		if r, err := l.Acquire("eng", "heavy"); err == nil {
			r()
			heavy++
		}
	}
	// A light actor arrives: two active actors, fair share 5 a second.
	light := 0
	for i := 0; i < 5; i++ {
		if r, err := l.Acquire("eng", "light"); err == nil {
			r()
			light++
		}
	}
	if light != 5 {
		t.Fatalf("light actor got %d of 5 within its share", light)
	}
	if r, err := l.Acquire("eng", "heavy"); err == nil {
		r()
		t.Fatal("heavy actor past its share admitted")
	} else if s, _ := IsLimited(err); s != ScopeAtespace {
		t.Fatalf("scope %s", s)
	}
	// Another atespace is independent.
	if r, err := l.Acquire("web", "w1"); err != nil {
		t.Fatalf("other atespace: %v", err)
	} else {
		r()
	}
	if heavy != 10 {
		t.Fatalf("heavy actor got %d, want the atespace burst 10", heavy)
	}
}
