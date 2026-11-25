// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package safefile

// Darwin's O_EXEC bit combined with O_DIRECTORY is O_SEARCH (sys/fcntl.h).
// x/sys does not export the Darwin constant.
const directorySearchMode = 0x40000000
