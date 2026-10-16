//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"testing"
)

func TestOSUserGroupsBindToLocalUID(t *testing.T) {
	oldPasswd, oldGroup, oldNSS := localPasswdPath, localGroupPath, nsswitchPath
	t.Cleanup(func() { localPasswdPath, localGroupPath, nsswitchPath = oldPasswd, oldGroup, oldNSS })
	dir := t.TempDir()
	localPasswdPath, localGroupPath, nsswitchPath = filepath.Join(dir, "passwd"), filepath.Join(dir, "group"), filepath.Join(dir, "nsswitch.conf")
	for path, content := range map[string]string{
		localPasswdPath: "alex:x:2100:2100::/home/alex:/bin/sh\n",
		localGroupPath:  "local-primary:x:2100:\nlocal-team:x:7000:alex\n",
		nsswitchPath:    "passwd: files sss\ninitgroups: files sss\n",
	} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	account := &user.User{Username: "alex", Uid: "2100", Gid: "2100"}
	got, err := platformAccountGroupIDs(context.Background(), nil, account, []string{"2100", "5000", "7000"}, nil, nil)
	if err != nil || !reflect.DeepEqual(got, []string{"2100", "7000"}) {
		t.Fatalf("groups of local uid = %v, %v; want the local records", got, err)
	}
}
