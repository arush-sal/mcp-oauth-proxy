package proxy

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/obot-platform/mcp-oauth-proxy/pkg/types"
)

// waitForGoroutines polls runtime.NumGoroutine until it drops to at most want
// or the deadline elapses, returning the last observed count. It gives the Go
// runtime a chance to retire goroutines that have just returned.
func waitForGoroutines(want int, timeout time.Duration) int {
	deadline := time.Now().Add(timeout)
	var n int
	for time.Now().Before(deadline) {
		runtime.GC()
		n = runtime.NumGoroutine()
		if n <= want {
			return n
		}
		time.Sleep(5 * time.Millisecond)
	}
	return n
}

// TestStartCleanupGoroutineExitsOnContextCancel guards the leak fix: the
// token-cleanup goroutine started in Start must return when the proxy context
// is cancelled. Before the fix it ran `for range ticker.C`, which blocks
// forever after cancellation (Ticker.Stop does not close the channel), leaking
// one goroutine per Start.
func TestStartCleanupGoroutineExitsOnContextCancel(t *testing.T) {
	p := newTestProxy(t, &types.Config{})

	// Let any goroutines from construction settle, then record a baseline.
	base := waitForGoroutines(0, 200*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	if err := p.Start(ctx); err != nil {
		t.Fatalf("Start returned error: %v", err)
	}

	// The cleanup goroutine should now be running.
	after := runtime.NumGoroutine()
	if after <= base {
		t.Fatalf("expected goroutine count to rise after Start: base=%d after=%d", base, after)
	}

	// Cancelling the caller context tears down p.ctx via the AfterFunc wired in
	// Start, which must unblock and return the cleanup goroutine.
	cancel()

	final := waitForGoroutines(base, 2*time.Second)
	if final > base {
		t.Fatalf("cleanup goroutine leaked after context cancel: base=%d final=%d", base, final)
	}
}

// TestCleanupExpiredTokensTickAction exercises the action run on each tick of
// the cleanup loop so the tick body is covered independently of the select
// timing (the leak fix itself is structural: select on p.ctx.Done()).
func TestCleanupExpiredTokensTickAction(t *testing.T) {
	p := newTestProxy(t, &types.Config{})
	if err := p.db.CleanupExpiredTokens(); err != nil {
		t.Fatalf("CleanupExpiredTokens returned error: %v", err)
	}
}
