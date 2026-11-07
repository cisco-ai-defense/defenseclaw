//go:build !windows

package unixidentity

import (
	"errors"
	"reflect"
	"testing"
)

// The accounts at a home are read across the whole search policy: a local
// account and a directory account both answer, a vanished one is skipped,
// and every unclear answer is an error so the home is never taken for free.
func TestDSCLHomeAccounts(t *testing.T) {
	out := func(s string) func() (commandResult, error) {
		return func() (commandResult, error) { return commandResult{stdout: []byte(s)}, nil }
	}
	uids := map[string]commandResult{
		"alice": {stdout: []byte("UniqueID: 502\n")},
		"corp":  {stdout: []byte("UniqueID:\n 1000501\n")},
		"gone":  {exitCode: 56},
		"odd":   {stdout: []byte("RecordName: odd\n")},
	}
	read := func(name string) (commandResult, error) { return uids[name], nil }
	cases := []struct {
		name    string
		search  func() (commandResult, error)
		want    []HomeAccount
		wantErr bool
	}{
		{"no account", out(""), nil, false},
		{"a local account", out("alice\t\tNFSHomeDirectory = (\n    \"/Users/shared\"\n)\n"), []HomeAccount{{"alice", 502}}, false},
		{"a local and a directory account", out("alice\t\tNFSHomeDirectory = (\n    \"/Users/shared\"\n)\ncorp\t\tNFSHomeDirectory = (\n    \"/Users/shared\"\n)\n"), []HomeAccount{{"alice", 502}, {"corp", 1000501}}, false},
		{"an account that vanished between the reads", out("gone\t\tNFSHomeDirectory = (\n    \"/Users/shared\"\n)\n"), nil, false},
		{"an account with no uid", out("odd\t\tNFSHomeDirectory = (\n    \"/Users/shared\"\n)\n"), nil, true},
		{"the search fails", func() (commandResult, error) { return commandResult{}, errors.New("timed out") }, nil, true},
		{"the search exits non-zero", func() (commandResult, error) { return commandResult{exitCode: 14}, nil }, nil, true},
		{"a space-padded answer", out("alice  NFSHomeDirectory = (\n    \"/Users/shared\"\n)\n"), nil, true},
		{"a line that is not a record", out("alice\t\tNFSHomeDirectory = (\n    \"/Users/shared\"\n)\nsomething else\n"), nil, true},
		{"a record of another attribute", out("alice\t\tUniqueID = (\n    502\n)\n"), nil, true},
		{"blank lines around a record", out("\nalice\t\tNFSHomeDirectory = (\n    \"/Users/shared\"\n)\n\n"), []HomeAccount{{"alice", 502}}, false},
		{"a name that is not an account name", out("a/b\t\tNFSHomeDirectory = (\n)\n"), nil, true},
	}
	for _, tc := range cases {
		got, err := dsclHomeAccounts(tc.search, read)
		if (err != nil) != tc.wantErr || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %v, %v; want %v, error=%v", tc.name, got, err, tc.want, tc.wantErr)
		}
	}
	failedRead := func(string) (commandResult, error) { return commandResult{}, errors.New("timed out") }
	if _, err := dsclHomeAccounts(out("alice\t\tNFSHomeDirectory = (\n)\n"), failedRead); err == nil {
		t.Error("a failed uid read must be an error")
	}
}
