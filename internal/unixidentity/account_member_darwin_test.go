//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"errors"
	"fmt"
	"os/user"
	"strconv"
	"testing"
)

// GAP-1825: the admin-group check asked Open Directory about every group the
// owner is in. It confirms the one group now, with the same answer.
func TestAccountInGroupConfirmsOnlyThatGroup(t *testing.T) {
	if err := validateTrustedTool(darwinDSMemberUtil); err != nil {
		t.Skip(err)
	}
	listed := []string{"20"}
	for gid := 1000; gid < 1175; gid++ {
		listed = append(listed, strconv.Itoa(gid))
	}
	listed = append(listed, "80")
	account := &user.User{Username: "dcm-std1", Uid: "502", Gid: "20"}
	for _, tc := range []struct {
		name   string
		ids    []string
		member bool
		want   bool
		runs   int
	}{
		{"listed and confirmed", listed, true, true, 1},
		{"listed, Open Directory says no", listed, false, false, 1},
		{"not listed", listed[:100], true, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runs := 0
			run := func(_ context.Context, path string, args []string, _ ...outputFilter) (commandResult, error) {
				if path != darwinDSMemberUtil || len(args) != 5 || args[0] != "checkmembership" || args[2] != "502" || args[4] != "80" {
					return commandResult{}, fmt.Errorf("unexpected command %q %q", path, args)
				}
				runs++
				if tc.member {
					return commandResult{stdout: []byte("user is a member of the group\n")}, nil
				}
				return commandResult{stdout: []byte("user is not a member of the group\n")}, nil
			}
			got, err := accountInGroup(context.Background(), run, account, tc.ids, nil, 80)
			if err != nil || got != tc.want || runs != tc.runs {
				t.Fatalf("member=%t err=%v after %d dsmemberutil runs; want %t after %d", got, err, runs, tc.want, tc.runs)
			}
		})
	}
	if got, err := accountInGroup(context.Background(), nil, account, nil, nil, 20); err != nil || !got {
		t.Fatalf("primary group: %t %v", got, err)
	}
	if _, err := accountInGroup(context.Background(), func(context.Context, string, []string, ...outputFilter) (commandResult, error) {
		return commandResult{}, errors.New("directory down")
	}, account, listed, nil, 80); err == nil {
		t.Fatal("a failed membership check answered")
	}
}
