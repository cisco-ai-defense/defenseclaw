// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package devicekeys

// keepSecretOutOfCrashDumps runs before the first tenant secret is read. It
// turns off what the OS lets a process turn off of its own crash dumps, so
// a crash of the process that holds the secret (status, verify and
// account-keys, as root or an elevated administrator) leaves no core or
// heap dump with it (private #13 review, should-change 4). Local
// administrators stay inside the trust boundary: a dump an administrator
// configures for every process (Windows LocalDumps, a Linux core_pattern
// with suid_dumpable) is theirs. Tests replace it.
var keepSecretOutOfCrashDumps = disableCrashDumps
