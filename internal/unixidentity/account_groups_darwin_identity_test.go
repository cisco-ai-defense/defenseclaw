//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"fmt"
	"os/user"
	"reflect"
	"strings"
	"testing"
)

func TestDarwinGroupMembershipUsesAccountUID(t *testing.T) {
	if err := validateTrustedTool(darwinDSMemberUtil); err != nil {
		t.Skip(err)
	}
	member := map[string]bool{"2100:80": true, "80001:6000": true}
	run := func(_ context.Context, path string, args []string, _ ...outputFilter) (commandResult, error) {
		if path != darwinDSMemberUtil || len(args) != 5 || args[0] != "checkmembership" || args[1] != "-u" || args[3] != "-g" {
			return commandResult{}, fmt.Errorf("unexpected membership query %q %q", path, args)
		}
		answer := "user is not a member of the group\n"
		if member[args[2]+":"+args[4]] {
			answer = "user is a member of the group\n"
		}
		return commandResult{stdout: []byte(answer)}, nil
	}
	for _, tc := range []struct {
		name    string
		account *user.User
		want    []string
	}{
		{"local", &user.User{Username: "alex", Uid: "2100", Gid: "20"}, []string{"20", "80"}},
		{"directory", &user.User{Username: "alex", Uid: "80001", Gid: "5000"}, []string{"5000", "6000"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := platformAccountGroupIDs(context.Background(), run, tc.account, strings.Fields("20 80 5000 6000"), nil, nil)
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("groups of uid %s = %v, %v; want %v", tc.account.Uid, got, err, tc.want)
			}
		})
	}
}
