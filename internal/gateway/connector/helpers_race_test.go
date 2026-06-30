// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"fmt"
	"sync"
	"testing"
)

func TestWithUserHomeDirConcurrentReaders(t *testing.T) {
	original := userHomeDir()
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(3)
	writer := func(prefix string) {
		defer wg.Done()
		<-start
		for i := 0; i < 1000; i++ {
			home := fmt.Sprintf("/tmp/%s-%d", prefix, i)
			if err := WithUserHomeDir(home, func() error {
				if got := userHomeDir(); got != home {
					return fmt.Errorf("userHomeDir = %q, want %q", got, home)
				}
				return nil
			}); err != nil {
				t.Errorf("WithUserHomeDir: %v", err)
				return
			}
		}
	}
	go writer("home-a")
	go writer("home-b")
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 5000; i++ {
			_ = userHomeDir()
		}
	}()
	close(start)
	wg.Wait()
	if got := userHomeDir(); got != original {
		t.Fatalf("userHomeDir after concurrent scopes = %q, want original %q", got, original)
	}
}
