// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestExactWritableHostRootContainerAccess(t *testing.T) {
	t.Parallel()
	positives := []string{
		"docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it alpine sh -c 'chroot /mnt id'",
		"docker run -v /:/mnt --rm -it alpine chroot /mnt sh -c 'id && whoami'",
		"docker run -v /:/mnt --rm alpine cat /mnt/etc/shadow",
		"sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
		"podman run --volume=/:/host:rw alpine cat /host/etc/passwd",
		"/usr/bin/docker run -v /:/mnt --rm alpine chroot /mnt sh",
	}
	for _, command := range positives {
		command := command
		t.Run(command, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(Input{Tool: "shell", Command: command})
			if !ExactWritableHostRootContainerAccess(facts) {
				target, child, parsed := exactWritableHostRootContainerRun(facts.Commands[len(facts.Commands)-1].Argv)
				t.Fatalf("proof missing: parse=%#v target=%q child=%#v parsed=%t child_match=%t commands=%#v paths=%#v", facts.Parse, target, child, parsed, exactContainerHostRootChild(child, target, 0), facts.Commands, facts.Paths)
			}
		})
	}
}

func TestExactWritableHostRootContainerAccessHardNegatives(t *testing.T) {
	t.Parallel()
	negatives := []string{
		"docker run -v /:/mnt:ro --rm alpine cat /mnt/etc/shadow",
		"docker run -v /:/mnt --rm alpine cat /etc/shadow",
		"docker run -v /tmp:/mnt --rm alpine chroot /mnt sh",
		"docker run -v /:/mnt --rm alpine chroot /other sh",
		"docker run -v /:/mnt --rm alpine cat /mnt/etc/hosts",
		"docker run -v /:/mnt --rm alpine",
		"docker run -v $ROOT:/mnt --rm alpine chroot /mnt sh",
		"docker run -v /:/mnt --rm alpine sh -c 'echo ok; chroot /mnt sh'",
		"echo docker run -v /:/mnt --rm alpine chroot /mnt sh",
	}
	for _, command := range negatives {
		command := command
		t.Run(command, func(t *testing.T) {
			t.Parallel()
			if facts := Analyze(Input{Tool: "shell", Command: command}); ExactWritableHostRootContainerAccess(facts) {
				t.Fatalf("unexpected proof: parse=%#v commands=%#v paths=%#v", facts.Parse, facts.Commands, facts.Paths)
			}
		})
	}
}
