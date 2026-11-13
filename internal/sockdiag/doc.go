// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package sockdiag finds one TCP socket of this network namespace by its exact
// four-tuple with a single NETLINK_SOCK_DIAG request (inet_diag,
// SOCK_DIAG_BY_FAMILY without NLM_F_DUMP), the kernel hash lookup that ss -K
// and the socket-destroy path use. It replaces a read of every row of
// /proc/self/net/tcp{,6}, whose cost grows with the sockets of the host, by a
// constant-time lookup that reports the same owner (sock_i_uid) and inode
// (sock_i_ino) the procfs row prints. It exists on Linux only; on other
// systems the package is empty.
//
// A caller takes only a positive answer as fact: an ESTABLISHED socket whose
// family, ports and addresses are exactly the ones asked for, in the one
// message the kernel sent for this request. Every other outcome (no such
// socket, a listener or TIME_WAIT entry the kernel's lookup fell back to,
// netlink unavailable, a refused request, a short, truncated, foreign or
// extra message) is an error, and the caller reads the procfs table as it
// did before.
package sockdiag
