// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

// ClaudeCodeManagedGuardInvocation is the command and arguments the managed
// Windows Claude Code policy registers for event and launcher: cmd.exe
// running the hook guard beside the launcher, which starts the launcher
// with hookArgs. ok is false when the guarded form does not apply (the
// writer then registers the launcher itself). Setup's hook image self test
// (GAP-0751) runs exactly this command from a newly staged launch folder
// before any agent config names it.
func ClaudeCodeManagedGuardInvocation(event, launcher string, hookArgs []string) (string, []string, bool) {
	command, args := claudeManagedGuardWrapperInvocation(event, launcher, hookArgs)
	if command == launcher {
		return launcher, hookArgs, false
	}
	return command, args, true
}
