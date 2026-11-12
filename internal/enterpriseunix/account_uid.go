// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// openCodePortLocalUIDs is the read of every uid the local account databases
// hold, duplicate names included (tests replace it).
var openCodePortLocalUIDs = unixidentity.LocalDatabaseUIDs

// openCodePortDirectoryShowsUnused is the check that the directory sources
// answer, so that their "no such account" is a fact (tests replace it).
var openCodePortDirectoryShowsUnused = unixidentity.DirectoryShowsUIDUnused

// UIDHasAccount reports whether any account of the host holds uid. It asks
// every source: the host account lookup by uid (getent on Linux, so NSS
// backends such as altfiles and systemd-userdb are included; the search
// policy and the local node with dscl on macOS) and the local account
// databases, every uid of them. One source that lists the uid is enough.
// "No account" needs affirmative evidence from every source: the local
// databases are all readable and none holds the uid, and each other source
// is asked for the uid by itself and shows it answers
// (unixidentity.DirectoryShowsUIDUnused), because the combined getent lookup
// can stop at a miss before a source (an NSS action), and getent exit 2 and an
// empty dscl answer are also what a directory that cannot be reached gives. A source that cannot answer is an error, never "no
// account": a caller that wants proof the uid is unused treats the error as no
// proof.
func (e *Env) UIDHasAccount(ctx context.Context, uid int) (bool, error) {
	if uid < 0 {
		return false, fmt.Errorf("uid %d is not a user id", uid)
	}
	if e.Runner == nil {
		return false, errors.New("no account lookup is available")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var failed []string
	var queries [][]string
	if e.GOOS == "darwin" {
		for _, node := range []string{".", "/Search"} {
			queries = append(queries, []string{"dscl", node, "-search", "/Users", "UniqueID", strconv.Itoa(uid)})
		}
	} else {
		queries = append(queries, []string{"getent", "passwd", strconv.Itoa(uid)})
	}
	for _, query := range queries {
		result, err := e.Runner.Run(ctx, query[0], query[1:]...)
		switch {
		case err == nil && strings.TrimSpace(string(result.Stdout)) != "":
			return true, nil
		case err == nil && e.GOOS == "darwin":
			// dscl prints nothing when no record has the uid.
		case err != nil && e.GOOS != "darwin" && result.ExitCode == 2:
			// getent: no such account.
		default:
			failed = append(failed, query[0]+": "+answerText(err))
		}
	}
	local, err := openCodePortLocalUIDs(ctx)
	if err != nil {
		failed = append(failed, "local account database: "+err.Error())
	}
	for _, held := range local {
		if held == uid {
			return true, nil
		}
	}
	if err := openCodePortDirectoryShowsUnused(ctx, uid); errors.Is(err, unixidentity.ErrUIDHeld) {
		return true, nil
	} else if err != nil {
		failed = append(failed, "directory: "+err.Error())
	}
	if len(failed) > 0 {
		return false, fmt.Errorf("the account lookup did not answer (%s)", strings.Join(failed, "; "))
	}
	return false, nil
}

// answerText is the reason a lookup gave no answer.
func answerText(err error) string {
	if err == nil {
		return "empty answer"
	}
	return err.Error()
}
