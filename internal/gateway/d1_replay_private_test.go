// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build d1corpus

package gateway

import (
	"crypto/sha256"
	"encoding/binary"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func d1ShardRows(t *testing.T, rows []d1ReplayRow) []d1ReplayRow {
	t.Helper()
	countText := os.Getenv("DC_D1_SHARD_COUNT")
	if countText == "" {
		return rows
	}
	count, countErr := strconv.Atoi(countText)
	index, indexErr := strconv.Atoi(os.Getenv("DC_D1_SHARD_INDEX"))
	if countErr != nil || indexErr != nil || count < 1 || index < 0 || index >= count {
		t.Fatal("invalid D1 shard configuration")
	}
	selected := make([]d1ReplayRow, 0, len(rows)/count+1)
	for _, row := range rows {
		digest := sha256.Sum256([]byte(row.ID))
		if int(binary.BigEndian.Uint32(digest[:4])%uint32(count)) == index {
			selected = append(selected, row)
		}
	}
	return selected
}

func TestD1BenignReplay(t *testing.T) {
	root := os.Getenv("DC_D1_CORPUS")
	if root == "" {
		t.Fatal("DC_D1_CORPUS must point to the private D1 corpus directory")
	}
	output := os.Getenv("DC_D1_OUTPUT")
	if output == "" {
		t.Fatal("DC_D1_OUTPUT must name the output TSV")
	}
	file, err := os.Create(output)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	for _, name := range []string{"corpus-shell.jsonl", "corpus-files.jsonl"} {
		d1Replay(t, d1ShardRows(t, d1ReadRows(t, filepath.Join(root, name))), file, false)
	}
}
