package gateway

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/intentstore"
)

// intentScopeSessions holds, per judge session key (judgeSessionKey), what the
// task-scope floor reads apart from the judge: the task of the turn, the scope
// targets every prompt of the session named, and the hosts of the git remotes
// read at its first event. The judge's intent store (intentstore.Store) keeps
// the task and the recent calls the judge sees; it has no place for targets or
// git hosts, and it cannot be read without recording a call, while the floor
// must run when the judge is late, busy, skipped or off (GAP-0372). Bounded like
// the store: maxToolJudgeContextSessions sessions, toolJudgeContextTTL.
//
// The table is per process. On a gateway with several replicas sharing one
// intent store, a replica that did not see a session's prompt has no entry: the
// floor then finds nothing for that session (the lane is shadow-only in 1.0.10).
type intentScopeSessions struct {
	mu       sync.Mutex
	sessions map[string]intentScopeSession
	// parents maps a child session's key to its parent's (GAP-0151): a
	// connector that gives a subagent its own session id announces the pair at
	// the subagent's start; the child's tool calls then read the parent's task.
	parents map[string]scopeParentLink
}

type scopeParentLink struct {
	parent   string
	lastSeen time.Time
}

type intentScopeSession struct {
	// task is the bounded task of the turn (toolJudgeUserIntentExcerpt); ""
	// when the turn has none (a blocked prompt, ClearSessionTask).
	task string
	// ownerTyped is set when the connector said the owner typed the turn
	// (withJudgeTurnSender with judgeTurnSenderOwner): only then does a task
	// of a connector whose turn text a remote party can write excuse calls
	// (GAP-1637). It is unset for a session this replica has not seen.
	ownerTyped bool
	// targets are the hosts, addresses and paths every user prompt of the
	// session named: the latest prompt alone does not carry them when it says
	// "continue".
	targets []string
	// gitHosts are the hosts of the git remotes of the session's working
	// folder, read once (gitRead) at its first event: a remote the agent adds
	// later does not clear its own send.
	gitHosts []string
	gitRead  bool
	lastSeen time.Time
}

// scopeSessions is the judge's table, made on first use (a judge built as a
// struct literal works too).
func (j *LLMJudge) scopeSessions() *intentScopeSessions {
	if s := j.scope.Load(); s != nil {
		return s
	}
	j.scope.CompareAndSwap(nil, &intentScopeSessions{})
	return j.scope.Load()
}

// observe starts a turn: task (possibly "") replaces the turn's task, and the
// targets scopeText names join the session's. The git read is kept.
func (t *intentScopeSessions) observe(key, task, scopeText string, ownerTyped bool, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.roomLocked(key, now)
	entry := t.sessions[key]
	entry.task, entry.ownerTyped, entry.lastSeen = task, ownerTyped, now
	if task != "" {
		entry.targets = mergeScopeTargets(entry.targets, scopeText)
	}
	t.sessions[key] = entry
}

func (t *intentScopeSessions) get(key string) (intentScopeSession, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	entry, ok := t.sessions[key]
	return entry, ok
}

func (t *intentScopeSessions) clearTask(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if entry, ok := t.sessions[key]; ok {
		entry.task = ""
		t.sessions[key] = entry
	}
}

// setGitHosts records the git read of a session that has an entry and no read yet.
func (t *intentScopeSessions) setGitHosts(key string, hosts []string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if entry, ok := t.sessions[key]; ok && !entry.gitRead {
		entry.gitHosts, entry.gitRead = hosts, true
		t.sessions[key] = entry
	}
}

func (t *intentScopeSessions) reset(key string) {
	t.mu.Lock()
	delete(t.sessions, key)
	delete(t.parents, key)
	t.mu.Unlock()
}

// link records that child is a subagent session of parent. The table is bounded
// like the sessions: expired links go first, then the least recently seen.
func (t *intentScopeSessions) link(child, parent string, now time.Time) {
	if child == "" || parent == "" || child == parent {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.parents == nil {
		t.parents = make(map[string]scopeParentLink)
	}
	if _, held := t.parents[child]; !held && len(t.parents) >= maxToolJudgeContextSessions {
		for k, l := range t.parents {
			if now.Sub(l.lastSeen) >= toolJudgeContextTTL {
				delete(t.parents, k)
			}
		}
		for len(t.parents) >= maxToolJudgeContextSessions {
			oldestKey, oldest := "", time.Time{}
			for k, l := range t.parents {
				if oldestKey == "" || l.lastSeen.Before(oldest) {
					oldestKey, oldest = k, l.lastSeen
				}
			}
			if oldestKey == "" {
				break
			}
			delete(t.parents, oldestKey)
		}
	}
	t.parents[child] = scopeParentLink{parent: parent, lastSeen: now}
}

// parentOf is the parent session key of a linked child, or "".
func (t *intentScopeSessions) parentOf(child string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	l, ok := t.parents[child]
	if !ok || time.Since(l.lastSeen) >= toolJudgeContextTTL {
		return ""
	}
	return l.parent
}

// roomLocked makes room for one more session: expired sessions go first, then
// the least recently seen ones. A session already held needs no room.
func (t *intentScopeSessions) roomLocked(key string, now time.Time) {
	if t.sessions == nil {
		t.sessions = make(map[string]intentScopeSession)
	}
	if _, held := t.sessions[key]; held || len(t.sessions) < maxToolJudgeContextSessions {
		return
	}
	for k, entry := range t.sessions {
		if now.Sub(entry.lastSeen) >= toolJudgeContextTTL {
			delete(t.sessions, k)
		}
	}
	for len(t.sessions) >= maxToolJudgeContextSessions {
		oldestKey, oldest := "", time.Time{}
		for k, entry := range t.sessions {
			if oldestKey == "" || entry.lastSeen.Before(oldest) {
				oldestKey, oldest = k, entry.lastSeen
			}
		}
		if oldestKey == "" {
			break
		}
		delete(t.sessions, oldestKey)
	}
}

// ObserveSessionPromptScope is ObserveSessionPrompt with the text that may name
// scope targets (hosts, addresses, paths) for the session apart from the task
// text: scopeText is "" for text that is not known to be what the owner typed
// (a tool result read by the generic prompt fallback, a remote chat party). An
// empty content starts a turn with no task.
func (j *LLMJudge) ObserveSessionPromptScope(ctx context.Context, content, scopeText string) {
	if j == nil {
		return
	}
	sessionID := judgeSessionKey(ctx)
	content = strings.TrimSpace(content)
	if sessionID == "" {
		return
	}
	sender := judgeTurnSenderFrom(ctx)
	if sender == judgeTurnSenderRemote {
		// A messaging platform's party wrote the turn: it starts a turn with
		// no task, for the judge and the decision model (GAP-1637).
		content, scopeText = "", ""
	}
	task := ""
	if content != "" {
		task = strings.Clone(toolJudgeUserIntentExcerpt(content))
	}
	if err := j.intentStore().ObservePrompt(ctx, sessionID, task); err != nil {
		j.warnIntentStore("ObservePrompt", "the user's intent is not recorded for the session's next tool calls", err)
	}
	j.scopeSessions().observe(sessionID, task, scopeText, judgeTurnOwnerTyped(ctx), time.Now())
	// A new turn starts a new tool chain: its target history goes with the
	// prior calls.
	j.judgeTargets().reset(sessionID)
	// The decision model's history keeps the prompt as a turn and is not
	// cleared by it. A blocked prompt comes here as "" (observeUserTurn), so
	// it never enters the history. Neither does a turn whose sender is not
	// known to be the owner: the decision model's state has no field to mark
	// it unverified, as the judge's SESSION_USER_INTENT is (GAP-1637).
	if content != "" && sender == judgeTurnSenderOwner {
		j.recordDecisionHistory(ctx, decisionHistoryEvent{kind: 'u', text: content})
	}
}

// ClearSessionTask drops the session's task and keeps its recent calls and
// scope targets: a prompt turned out not to be a task after calls had begun.
// The intent store keeps the calls; the judge sample leaves the task out while
// the scope table holds none for the turn (sessionTaskCleared).
func (j *LLMJudge) ClearSessionTask(ctx context.Context) {
	if j == nil {
		return
	}
	if sessionID := judgeSessionKey(ctx); sessionID != "" {
		j.scopeSessions().clearTask(sessionID)
	}
}

// LinkChildSession records that childKey (a judge session key) is a subagent
// session of parentKey. The child's tool calls are judged with the parent's
// task when the child has none of its own (GAP-0151).
func (j *LLMJudge) LinkChildSession(childKey, parentKey string) {
	if j == nil {
		return
	}
	j.scopeSessions().link(childKey, parentKey, time.Now())
}

// parentIntent is the task of the session childKey is a subagent of, read
// without recording anything, and the parent's key; "" when the session has no
// linked parent, the store cannot read, or the parent's turn has no task. The
// parent's own record is never written to (read-only fallback).
func (j *LLMJudge) parentIntent(ctx context.Context, childKey string) (string, string) {
	parent := j.scopeSessions().parentOf(childKey)
	if parent == "" || j.sessionTaskCleared(parent) {
		return "", ""
	}
	reader, ok := j.intentStore().(intentstore.Reader)
	if !ok {
		return "", ""
	}
	snap, found, err := reader.Lookup(ctx, parent)
	if err != nil || !found {
		return "", ""
	}
	return snap.UserIntent, parent
}

// sessionTaskCleared reports a session whose turn this process saw start and
// whose task it no longer holds (ClearSessionTask, or a turn with no task).
func (j *LLMJudge) sessionTaskCleared(sessionID string) bool {
	entry, ok := j.scopeSessions().get(sessionID)
	return ok && entry.task == ""
}

// sessionTaskFromOwner reports a session whose current turn this replica saw
// and whose connector said the owner typed it (judgeTurnOwnerTyped).
func (j *LLMJudge) sessionTaskFromOwner(sessionID string) bool {
	entry, ok := j.scopeSessions().get(sessionID)
	return ok && entry.ownerTyped
}

// sessionScopeTargets are the targets the session's prompts named, or nil.
func (j *LLMJudge) sessionScopeTargets(sessionID string) []string {
	entry, _ := j.scopeSessions().get(sessionID)
	return entry.targets
}

// inheritToolJudgeContext hands the judge a config or rule-pack change
// replaces over to its successor: the successor uses the same intent store,
// scope table and target history, so live sessions keep their task, recent
// calls and targets
// across the rebuild instead of being judged with none until their next
// prompt. A store or table the successor already has is kept.
func (j *LLMJudge) inheritToolJudgeContext(from *LLMJudge) {
	if j == nil || from == nil || j == from {
		return
	}
	store := from.intentStore()
	j.intentsMu.Lock()
	if j.intents == nil {
		j.intents = store
	}
	j.intentsMu.Unlock()
	j.scope.CompareAndSwap(nil, from.scopeSessions())
	j.targets.CompareAndSwap(nil, from.judgeTargets())
}
