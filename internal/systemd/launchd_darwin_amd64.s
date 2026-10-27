// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

#include "textflag.h"

// Trampolines to the libSystem functions launchd_darwin.go imports
// (golang.org/x/sys/unix uses the same form).

TEXT libc_launch_activate_socket_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_launch_activate_socket(SB)
GLOBL	·launchActivateSocketTrampolineAddr(SB), RODATA, $8
DATA	·launchActivateSocketTrampolineAddr(SB)/8, $libc_launch_activate_socket_trampoline<>(SB)

TEXT libc_free_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_free(SB)
GLOBL	·freeTrampolineAddr(SB), RODATA, $8
DATA	·freeTrampolineAddr(SB)/8, $libc_free_trampoline<>(SB)
