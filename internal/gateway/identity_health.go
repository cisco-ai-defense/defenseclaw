// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"sort"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// The identity member of /health on the standalone profile: which identity
// sources answered directory lookups since the gateway started, how long ago
// each last answered, and how many accounts fail or are served stale facts.
// Tokens, counts and ages only: no uid, SID, UPN, group or lookup error (the
// error can name an account), so every caller may read it. The lifecycle
// status and verify copy it into their identity block
// (enterprisestatus.ParseIdentityHealth).

// identitySourcesMax bounds the (source, directory) pairs the cache keeps.
const identitySourcesMax = 8

var identitySourceToken = lazyregexp.New(`^[a-z][a-z0-9_]{0,31}$`)

// identityHealthDirectories are the directory values /health names.
var identityHealthDirectories = map[string]bool{
	string(useridentity.DirectoryLocal): true, string(useridentity.DirectoryLDAP): true,
	string(useridentity.DirectoryActiveDirectory): true, string(useridentity.DirectoryEntraID): true,
	string(useridentity.DirectoryOkta): true, string(useridentity.DirectoryOther): true,
}

// identitySourceAnswer is when one (source, directory) pair last answered.
type identitySourceAnswer struct {
	source, directory string
	at                time.Time
}

// noteAnsweredLocked records that the source of facts answered at now. A
// new pair past identitySourcesMax replaces the one that answered longest
// ago. c.mu is held.
func (c *identityCache[T]) noteAnsweredLocked(facts T, now time.Time) {
	if c.describe == nil {
		return
	}
	source, directory := c.describe(facts)
	if !identitySourceToken.MatchString(source) {
		return
	}
	if !identityHealthDirectories[directory] {
		directory = ""
	}
	key := [2]string{source, directory}
	if c.answered == nil {
		c.answered = map[[2]string]time.Time{}
	}
	if _, known := c.answered[key]; !known && len(c.answered) >= identitySourcesMax {
		var oldest [2]string
		var oldestAt time.Time
		for pair, at := range c.answered {
			if oldestAt.IsZero() || at.Before(oldestAt) {
				oldest, oldestAt = pair, at
			}
		}
		delete(c.answered, oldest)
	}
	c.answered[key] = now
}

// answeredSources lists the pairs that answered, sorted by source then
// directory.
func (c *identityCache[T]) answeredSources() []identitySourceAnswer {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]identitySourceAnswer, 0, len(c.answered))
	for pair, at := range c.answered {
		out = append(out, identitySourceAnswer{source: pair[0], directory: pair[1], at: at})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].source != out[j].source {
			return out[i].source < out[j].source
		}
		return out[i].directory < out[j].directory
	})
	return out
}

// directorySourceAnswers reads the answered sources of the cache requests
// use. Tests replace it.
var directorySourceAnswers = func() []identitySourceAnswer { return peerDirectoryCache().answeredSources() }

// identityHealthSummary is the identity member of /health.
func identityHealthSummary(h identityCacheHealth, answers []identitySourceAnswer, now time.Time) map[string]any {
	sources := make([]map[string]any, 0, len(answers))
	for _, answer := range answers {
		age := max(int64(now.Sub(answer.at)/time.Second), 0)
		source := map[string]any{"source": answer.source, "last_ok_age_seconds": age}
		if answer.directory != "" {
			source["directory"] = answer.directory
		}
		sources = append(sources, source)
	}
	return map[string]any{"sources": sources, "failing": h.Failing, "stale": h.Stale}
}
