// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// serialModelStandIn is a deliberately slow judge model server: one worker
// answers the requests in arrival order, each in delay, like a local model
// that serves one request at a time. A request whose caller gave up before
// its turn is dropped, as a server drops a closed connection.
type serialModelStandIn struct {
	delay time.Duration
	queue chan serialModelJob
	once  sync.Once
}

type serialModelJob struct {
	ctx  context.Context
	done chan error
}

func newSerialModelStandIn(delay time.Duration) *serialModelStandIn {
	return &serialModelStandIn{delay: delay, queue: make(chan serialModelJob, 1024)}
}

func (m *serialModelStandIn) start() {
	m.once.Do(func() {
		go func() {
			for job := range m.queue {
				if job.ctx.Err() != nil {
					job.done <- job.ctx.Err()
					continue
				}
				select {
				case <-time.After(m.delay):
					job.done <- nil
				case <-job.ctx.Done():
					job.done <- job.ctx.Err()
				}
			}
		}()
	})
}

func (m *serialModelStandIn) ChatCompletion(ctx context.Context, _ *ChatRequest) (*ChatResponse, error) {
	m.start()
	job := serialModelJob{ctx: ctx, done: make(chan error, 1)}
	m.queue <- job
	if err := <-job.done; err != nil {
		return nil, err
	}
	return &ChatResponse{Model: "stand-in", Choices: []ChatChoice{{Message: &ChatMessage{Content: "{}"}}}}, nil
}

func (m *serialModelStandIn) ChatCompletionStream(context.Context, *ChatRequest, func(StreamChunk)) (*ChatUsage, error) {
	return nil, errors.New("not implemented")
}

type judgePriorityRun struct {
	toolLatencies []time.Duration
	toolTimeouts  int
}

func (r judgePriorityRun) percentile(p float64) time.Duration {
	if len(r.toolLatencies) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), r.toolLatencies...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted[int(p*float64(len(sorted)-1))]
}

// runJudgePriorityWorkload plays turns of the issue's workload: a user
// prompt starts the three prompt judges (injection, PII, exfil), and the
// agent's next tool call reaches the tool judge shortly after. Each tool
// judge call has the hook deadline; the prompt judges run on the judge
// timeout. It returns the tool judge latencies and how many timed out.
func runJudgePriorityWorkload(t *testing.T, maxParallel, turns int, delay, hookDeadline time.Duration) judgePriorityRun {
	t.Helper()
	cfg := &config.JudgeConfig{
		Enabled: true, Injection: true, PII: true, PIIPrompt: true, Exfil: true, ToolInjection: true,
		Timeout: 60, MaxParallel: maxParallel,
	}
	model := newSerialModelStandIn(delay)
	judge := &LLMJudge{cfg: cfg, model: "stand-in", provider: model, rp: &guardrail.RulePack{}}
	if maxParallel > 0 {
		judge.calls = &judgeScheduler{limit: maxParallel}
	}
	var run judgePriorityRun
	var prompts sync.WaitGroup
	for turn := 0; turn < turns; turn++ {
		prompts.Add(1)
		go func() {
			defer prompts.Done()
			judge.RunJudges(context.Background(), "prompt",
				fmt.Sprintf("turn %d: please summarise the open pull requests and their reviewers", turn), "")
		}()
		time.Sleep(delay / 10)
		ctx, cancel := context.WithTimeout(context.Background(), hookDeadline)
		start := time.Now()
		v := judge.RunToolJudge(ctx, "Bash", fmt.Sprintf(`{"command":"git log --oneline -n %d -- README.md"}`, turn+5))
		elapsed := time.Since(start)
		timedOut := v.JudgeFailed && ctx.Err() != nil
		cancel()
		run.toolLatencies = append(run.toolLatencies, elapsed)
		if timedOut {
			run.toolTimeouts++
		}
		// The agent runs its tool, then the next turn starts once the
		// turn's prompt checks are done (a slow model is still busy).
		prompts.Wait()
	}
	return run
}

// #1395: under a queue of prompt-judge work on a slow model, the tool judge
// keeps within its deadline once guardrail.judge.max_parallel is set, and
// verdicts are unchanged (all calls here answer allow). The default
// (no limit) is measured too and logged for the comparison.
func TestJudgeToolCallStaysInsideItsDeadlineUnderPromptLoad(t *testing.T) {
	judgeHealth.reset()
	t.Cleanup(judgeHealth.reset)
	delay := 200 * time.Millisecond
	deadline := 750 * time.Millisecond // the 8 s hook timeout, scaled like the delay
	turns := 6
	if v, err := strconv.Atoi(os.Getenv("DEFENSECLAW_JUDGE_PRIORITY_TURNS")); err == nil && v > 0 {
		turns = v
	}
	if v, err := time.ParseDuration(os.Getenv("DEFENSECLAW_JUDGE_PRIORITY_DELAY")); err == nil && v > 0 {
		deadline = time.Duration(float64(deadline) * float64(v) / float64(delay))
		delay = v
	}
	before := runJudgePriorityWorkload(t, 0, turns, delay, deadline)
	after := runJudgePriorityWorkload(t, 1, turns, delay, deadline)
	t.Logf("judge stand-in %s per call, one at a time; tool deadline %s; %d turns", delay, deadline, turns)
	t.Logf("before (no max_parallel): tool judge p50 %s p95 %s max %s, %d/%d timed out",
		before.percentile(0.5), before.percentile(0.95), before.percentile(1), before.toolTimeouts, turns)
	t.Logf("after (max_parallel 1):   tool judge p50 %s p95 %s max %s, %d/%d timed out",
		after.percentile(0.5), after.percentile(0.95), after.percentile(1), after.toolTimeouts, turns)
	if after.toolTimeouts != 0 {
		t.Fatalf("with max_parallel 1, %d of %d tool judge calls timed out behind prompt checks", after.toolTimeouts, turns)
	}
	// At most the in-flight prompt check and the tool call itself.
	if limit := 2*delay + delay/2; after.percentile(1) > limit {
		t.Fatalf("with max_parallel 1 the slowest tool judge took %s, want under %s", after.percentile(1), limit)
	}
}
