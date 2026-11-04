// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookexec

// writeManagedHookDecisionRecord is a no-op outside Windows: a managed hook
// there resolves a real Home and logHookFailure keeps the durable record in
// Home/logs/hook-failures.jsonl.
func writeManagedHookDecisionRecord(string, string, string) {}

func managedHookDecisionRecordSource(serviceName string) string {
	if serviceName == "" {
		return managedHookDecisionRecordDefaultSource
	}
	return serviceName
}
