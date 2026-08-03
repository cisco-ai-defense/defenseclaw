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

package semantic

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/semanticpb"
	"github.com/google/cel-go/cel"
)

func TestProgramEvalBoolAndConcurrentReuse(t *testing.T) {
	compiler, err := NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	program, code := compiler.Compile(
		`f.commands.exists(c, c.program == "cat")`,
	)
	if code != CompileOK {
		t.Fatalf("Compile() code = %q", code)
	}
	facts, projectionCode := Project(validActionFacts())
	if projectionCode != ProjectionOK {
		t.Fatalf("Project() code = %q", projectionCode)
	}

	result, evalCode := program.EvalBool(context.Background(), facts)
	if evalCode != EvalOK || !result.Matched || result.Cost == 0 {
		t.Fatalf("EvalBool() = (%+v, %q)", result, evalCode)
	}
	facts.Commands[0].Program = "echo"
	result, evalCode = program.EvalBool(context.Background(), facts)
	if evalCode != EvalOK || result.Matched {
		t.Fatalf("false EvalBool() = (%+v, %q)", result, evalCode)
	}
	facts.Commands[0].Program = "cat"

	const workers = 16
	codes := make(chan EvalCode, workers)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			result, code := program.EvalBool(context.Background(), facts)
			if code == EvalOK && !result.Matched {
				code = EvalError
			}
			codes <- code
		}()
	}
	group.Wait()
	close(codes)
	for code := range codes {
		if code != EvalOK {
			t.Fatalf("concurrent EvalBool() code = %q", code)
		}
	}
}

func TestProgramEvalFailureClassification(t *testing.T) {
	compiler, err := NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	program, code := compiler.Compile(
		`f.commands.exists(c, c.program == "missing")`,
	)
	if code != CompileOK {
		t.Fatalf("Compile() code = %q", code)
	}
	many := &semanticpb.Facts{
		Commands: make([]*semanticpb.CommandFact, maxCommands),
	}
	for index := range many.Commands {
		many.Commands[index] = &semanticpb.CommandFact{Program: "present"}
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, code := program.EvalBool(cancelled, many); code != EvalCancelled {
		t.Fatalf("cancelled EvalBool() code = %q", code)
	}
	expired, cancelDeadline := context.WithDeadline(
		context.Background(),
		time.Now().Add(-time.Second),
	)
	defer cancelDeadline()
	if _, code := program.EvalBool(expired, many); code != EvalDeadline {
		t.Fatalf("expired EvalBool() code = %q", code)
	}
	cancelledWithCause, cancelWithCause := context.WithCancelCause(
		context.Background(),
	)
	cancelWithCause(errors.New("private cancellation cause"))
	if _, code := program.EvalBool(cancelledWithCause, many); code != EvalCancelled {
		t.Fatalf("cause-cancelled EvalBool() code = %q", code)
	}
	expiredWithCause, cancelDeadlineCause := context.WithDeadlineCause(
		context.Background(),
		time.Now().Add(-time.Second),
		errors.New("private deadline cause"),
	)
	defer cancelDeadlineCause()
	if _, code := program.EvalBool(expiredWithCause, many); code != EvalDeadline {
		t.Fatalf("cause-expired EvalBool() code = %q", code)
	}
	if _, code := program.EvalBool(context.Background(), nil); code != EvalProjectionInvalid {
		t.Fatalf("nil projection code = %q", code)
	}
	if _, code := program.EvalBool(nil, many); code != EvalProjectionInvalid {
		t.Fatalf("nil context code = %q", code)
	}
	if _, code := (*Program)(nil).EvalBool(context.Background(), many); code != EvalError {
		t.Fatalf("nil program code = %q", code)
	}

	checked, issues := compiler.env.Compile(
		`f.commands.exists(c, c.program == "missing")`,
	)
	if issues != nil && issues.Err() != nil {
		t.Fatal(issues.Err())
	}
	raw, err := compiler.env.Program(
		checked,
		cel.InterruptCheckFrequency(1),
		cel.CostLimit(1),
	)
	if err != nil {
		t.Fatal(err)
	}
	costResult, costCode := (&Program{program: raw}).EvalBool(
		context.Background(),
		many,
	)
	if costCode != EvalCost || costResult.Cost == 0 {
		t.Fatalf("cost EvalBool() = (%+v, %q)", costResult, costCode)
	}
}
