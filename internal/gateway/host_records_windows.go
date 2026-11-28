// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// readHostRecordLines reads the newest hook records of the Application event
// log since since: source is the gateway service's event source and the
// hook's records have event ID 3 (GAP-2042).
func readHostRecordLines(ctx context.Context, source string, since time.Time) (hostRecordRead, error) {
	if source == "" || strings.ContainsAny(source, `'"<>&[]`) {
		return hostRecordRead{}, errors.New("the gateway event source name is not usable in a query")
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return hostRecordRead{}, err
	}
	age := time.Since(since).Milliseconds()
	query := fmt.Sprintf("*[System[Provider[@Name='%s'] and (EventID=%d) and TimeCreated[timediff(@SystemTime) <= %d]]]",
		source, hookexec.ManagedHookDecisionEventID, age)
	out, capped, err := hostRecordCommand(ctx, filepath.Join(system, "wevtutil.exe"),
		"qe", "Application", "/q:"+query, "/f:xml", "/rd:true", "/c:"+strconv.Itoa(hostRecordReadMax+1))
	if err != nil {
		return hostRecordRead{}, err
	}
	return hostRecordRead{lines: parseEventLogRecords(hostRecordWhole(out, capped, "</Event>")), capped: capped}, nil
}

// hostRecordSource is the event source the managed hook writes under: the
// gateway service's own name, the default when it has none.
func hostRecordSource() string {
	return hookexec.ManagedHookDecisionRecordSource(os.Getenv("DEFENSECLAW_WINDOWS_SERVICE_NAME"))
}
