package gateway

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// A rebuilt judge and the judge it replaced use one store and one scope table
// for a live session; calls on both at once are safe (run under -race), and
// neither loses the session's task.
func TestIntentScopeSessionsSharedAcrossRebuildRace(t *testing.T) {
	old := newIntentTestJudge()
	ctx := ContextWithSessionID(context.Background(), "sess-race")
	old.ObserveSessionPromptScope(ctx, "deploy to build.corp.example", "deploy to build.corp.example")
	next := newIntentTestJudge()
	next.inheritToolJudgeContext(old)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			j := old
			if i%2 == 1 {
				j = next
			}
			for k := 0; k < 25; k++ {
				_ = j.toolJudgeContextSample(ctx, "Bash", fmt.Sprintf(`{"command":"make step-%d-%d"}`, i, k))
				_ = j.scopeFloorReason(ctx, "Bash", `{"command":"ls"}`, "")
				if k%10 == 0 {
					j.ObserveSessionPromptScope(ctx, "deploy to build.corp.example", "deploy to build.corp.example")
					j.SnapshotSessionGitRemotes(ctx, t.TempDir())
				}
			}
		}(i)
	}
	wg.Wait()
	if s := next.toolJudgeContextSample(ctx, "Bash", `{"command":"make done"}`); !strings.Contains(s, "deploy to build.corp.example") {
		t.Fatalf("the rebuilt judge lost the task:\n%s", s)
	}
}

// A session reset drops the scope state with the intent; the table keeps its
// bound and evicts the least recently seen session first.
func TestIntentScopeSessionsResetAndBound(t *testing.T) {
	j := newIntentTestJudge()
	ctx := ContextWithSessionID(context.Background(), "sess-reset")
	j.ObserveSessionPrompt(ctx, "upload to https://artifacts.corp.example/builds")
	key := judgeSessionKey(ctx)
	if _, ok := j.scopeSessions().get(key); !ok {
		t.Fatal("the prompt did not reach the scope table")
	}
	j.ResetToolJudgeSession(ctx, key)
	if _, ok := j.scopeSessions().get(key); ok {
		t.Fatal("a session reset must drop the scope state")
	}
	table := &intentScopeSessions{}
	base := time.Now()
	for i := 0; i < maxToolJudgeContextSessions+5; i++ {
		table.observe(fmt.Sprintf("s%d", i), "task", "", false, base.Add(time.Duration(i)*time.Millisecond))
	}
	if n := len(table.sessions); n != maxToolJudgeContextSessions {
		t.Fatalf("%d sessions, want the bound %d", n, maxToolJudgeContextSessions)
	}
	if _, ok := table.get("s0"); ok {
		t.Fatal("the least recently seen session should be gone")
	}
	if _, ok := table.get(fmt.Sprintf("s%d", maxToolJudgeContextSessions+4)); !ok {
		t.Fatal("the newest session must stay")
	}
}
