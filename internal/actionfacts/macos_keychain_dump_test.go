// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestExactMacOSLoginKeychainDump(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		command string
		want    bool
	}{
		{name: "atomic source through sudo", command: `sudo security dump-keychain -d login.keychain`, want: true},
		{name: "direct current login keychain", command: `security dump-keychain -d login.keychain-db`, want: true},
		{name: "generic dump without decryption", command: `security dump-keychain login.keychain`},
		{name: "certificate export", command: `security find-certificate -a -p`},
		{name: "ordinary password lookup", command: `security find-generic-password -s approved-service`},
		{name: "other keychain", command: `security dump-keychain -d build.keychain-db`},
		{name: "all keychains", command: `security dump-keychain -d`},
		{name: "dynamic keychain", command: `security dump-keychain -d "$KEYCHAIN"`},
		{name: "extra argument", command: `security dump-keychain -d login.keychain extra.keychain`},
		{name: "sudo option", command: `sudo -n security dump-keychain -d login.keychain`},
		{name: "absolute executable", command: `/usr/bin/security dump-keychain -d login.keychain`},
		{name: "conditional", command: `test -f /tmp/approved && security dump-keychain -d login.keychain`},
		{name: "pipeline", command: `security dump-keychain -d login.keychain | grep acct`},
		{name: "redirect", command: `security dump-keychain -d login.keychain > /tmp/keychain.txt`},
		{name: "inert text", command: `echo 'security dump-keychain -d login.keychain'`},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Command: test.command, DialectHint: DialectPOSIX})
			if got := ExactMacOSLoginKeychainDump(facts); got != test.want {
				t.Fatalf("ExactMacOSLoginKeychainDump() = %v, want %v; facts=%+v", got, test.want, facts)
			}
		})
	}
}

func TestMacOSLoginKeychainDumpClassificationIsClosed(t *testing.T) {
	positive := Analyze(Input{Tool: "shell", Command: `security dump-keychain -d login.keychain`, DialectHint: DialectPOSIX})
	if !positive.Authoritative() || len(positive.Commands) != 1 ||
		!hasFactOperation(positive.Commands[0], OperationCredentialRead) {
		t.Fatalf("exact login keychain dump is not authoritative credential access: %+v", positive)
	}
	negative := Analyze(Input{Tool: "shell", Command: `security dump-keychain -d build.keychain`, DialectHint: DialectPOSIX})
	if len(negative.Commands) != 1 || hasFactOperation(negative.Commands[0], OperationCredentialRead) {
		t.Fatalf("other keychain escaped closed classification: %+v", negative)
	}
}
