// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"testing"
)

func TestCommandExitCode(t *testing.T) {
	cause := errors.New("install failed")
	for name, test := range map[string]struct {
		err  error
		want int
	}{
		"plain failure":   {err: cause, want: 1},
		"labelled":        {err: withExitCode(cause, 1603), want: 1603},
		"labelled deeper": {err: fmt.Errorf("context: %w", withExitCode(cause, 1603)), want: 1603},
		// The first code wins: an outer default must not overwrite the code an
		// inner failure deliberately chose.
		"already labelled": {err: withExitCode(withExitCode(cause, 3010), 1603), want: 3010},
	} {
		t.Run(name, func(t *testing.T) {
			if got := commandExitCode(test.err); got != test.want {
				t.Fatalf("commandExitCode = %d, want %d", got, test.want)
			}
			if !errors.Is(test.err, cause) {
				t.Fatal("labelling a failure must preserve its cause")
			}
		})
	}
}

func TestWithExitCodeKeepsSuccessUnlabelled(t *testing.T) {
	if err := withExitCode(nil, 1603); err != nil {
		t.Fatalf("withExitCode(nil) = %v, want nil", err)
	}
	if got := commandExitCode(nil); got != 1 {
		t.Fatalf("commandExitCode(nil) = %d, want the generic failure result", got)
	}
}
