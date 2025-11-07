package controller_test

import (
	"sync"
	"testing"
	"time"

	"github.com/Goofygiraffe06/zinc/internal/controller"
)

func TestVerificationRegistry_RegisterAndNotify(t *testing.T) {
	t.Helper()

	tests := []struct {
		name  string
		nonce string
	}{
		{
			name:  "basic register and notify",
			nonce: "test-nonce-123",
		},
		{
			name:  "nonce with special chars",
			nonce: "nonce+with+special@chars#123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := controller.NewVerificationRegistry()

			// Register a wait channel
			waitCh := registry.Register(tt.nonce)

			// Verify channel was registered
			if registry.Count() != 1 {
				t.Errorf("Expected count=1 after register, got %d", registry.Count())
			}

			// Fire notification in goroutine
			go func() {
				time.Sleep(10 * time.Millisecond) // Small delay to ensure we're waiting
				registry.Notify(tt.nonce)
			}()

			// Wait for notification with timeout
			select {
			case <-waitCh:
				// Success - notification received
			case <-time.After(1 * time.Second):
				t.Fatal("Timeout waiting for notification")
			}

			// Cleanup
			registry.Delete(tt.nonce)

			// Verify cleanup
			if registry.Count() != 0 {
				t.Errorf("Expected count=0 after delete, got %d", registry.Count())
			}
		})
	}
}

func TestVerificationRegistry_NotifyBeforeRegister(t *testing.T) {
	t.Helper()
	registry := controller.NewVerificationRegistry()
	nonce := "early-notification"

	// Notify before anyone is waiting (should be no-op)
	registry.Notify(nonce)

	// Now register and verify we don't get a stale notification
	waitCh := registry.Register(nonce)

	select {
	case <-waitCh:
		t.Fatal("Should not have received notification from early Notify call")
	case <-time.After(100 * time.Millisecond):
		// Expected - no notification received
	}

	registry.Delete(nonce)
}

func TestVerificationRegistry_MultipleWaiters(t *testing.T) {
	t.Helper()
	registry := controller.NewVerificationRegistry()

	nonce1 := "waiter-1"
	nonce2 := "waiter-2"
	nonce3 := "waiter-3"

	// Register multiple waiters
	wait1 := registry.Register(nonce1)
	wait2 := registry.Register(nonce2)
	wait3 := registry.Register(nonce3)

	if registry.Count() != 3 {
		t.Errorf("Expected count=3, got %d", registry.Count())
	}

	// Notify only waiter-2
	registry.Notify(nonce2)

	// Verify only waiter-2 receives notification
	select {
	case <-wait2:
		// Expected
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Waiter-2 should have been notified")
	}

	// Verify others are still waiting
	select {
	case <-wait1:
		t.Fatal("Waiter-1 should not have been notified")
	case <-wait3:
		t.Fatal("Waiter-3 should not have been notified")
	case <-time.After(100 * time.Millisecond):
		// Expected - others still waiting
	}

	// Cleanup all
	registry.Delete(nonce1)
	registry.Delete(nonce2)
	registry.Delete(nonce3)

	if registry.Count() != 0 {
		t.Errorf("Expected count=0 after cleanup, got %d", registry.Count())
	}
}

func TestVerificationRegistry_ConcurrentRegisterNotify(t *testing.T) {
	t.Helper()
	registry := controller.NewVerificationRegistry()

	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines * 2) // Register + Notify per goroutine

	// Concurrent register and notify operations
	for i := 0; i < numGoroutines; i++ {
		nonce := string(rune('A'+i%26)) + string(rune('0'+i%10)) // Generate unique nonces

		// Register in goroutine
		go func(n string) {
			defer wg.Done()
			waitCh := registry.Register(n)

			select {
			case <-waitCh:
				// Success
			case <-time.After(2 * time.Second):
				t.Errorf("Timeout waiting for notification on nonce %s", n)
			}

			registry.Delete(n)
		}(nonce)

		// Notify in separate goroutine
		go func(n string) {
			defer wg.Done()
			time.Sleep(50 * time.Millisecond) // Give register time to happen
			registry.Notify(n)
		}(nonce)
	}

	wg.Wait()

	// All should be cleaned up
	if registry.Count() != 0 {
		t.Errorf("Expected count=0 after concurrent test, got %d", registry.Count())
	}
}

func TestVerificationRegistry_DeleteWithoutRegister(t *testing.T) {
	t.Helper()
	registry := controller.NewVerificationRegistry()

	// Delete non-existent nonce (should be safe no-op)
	registry.Delete("non-existent")

	if registry.Count() != 0 {
		t.Errorf("Expected count=0, got %d", registry.Count())
	}
}

func TestVerificationRegistry_DoubleDelete(t *testing.T) {
	t.Helper()
	registry := controller.NewVerificationRegistry()
	nonce := "double-delete-test"

	waitCh := registry.Register(nonce)

	// First delete
	registry.Delete(nonce)

	// Channel should be closed
	select {
	case _, ok := <-waitCh:
		if ok {
			t.Fatal("Channel should be closed after delete")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Should have received close signal")
	}

	// Second delete (should be safe no-op)
	registry.Delete(nonce)

	if registry.Count() != 0 {
		t.Errorf("Expected count=0, got %d", registry.Count())
	}
}

func TestVerificationRegistry_NotifyAfterDelete(t *testing.T) {
	t.Helper()
	registry := controller.NewVerificationRegistry()
	nonce := "notify-after-delete"

	waitCh := registry.Register(nonce)
	registry.Delete(nonce)

	// Notify after delete (should be no-op)
	registry.Notify(nonce)

	// Verify channel is closed (from delete, not notify)
	select {
	case _, ok := <-waitCh:
		if ok {
			t.Fatal("Channel should be closed")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Should have received close signal")
	}
}

func TestVerificationRegistry_MultipleNotifications(t *testing.T) {
	t.Helper()
	registry := controller.NewVerificationRegistry()
	nonce := "multi-notify"

	waitCh := registry.Register(nonce)

	// Send multiple notifications (only first should be received)
	go func() {
		time.Sleep(10 * time.Millisecond)
		registry.Notify(nonce)
		registry.Notify(nonce) // Second notify should be no-op
		registry.Notify(nonce) // Third notify should be no-op
	}()

	// Should receive exactly one notification
	select {
	case <-waitCh:
		// Success - received notification
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for notification")
	}

	// No more notifications should be pending
	select {
	case <-waitCh:
	case <-time.After(100 * time.Millisecond):
		// Expected - no more notifications
	}

	registry.Delete(nonce)
}
