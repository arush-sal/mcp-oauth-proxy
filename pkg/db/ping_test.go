package db

import (
	"context"
	"testing"
)

func TestStorePing(t *testing.T) {
	store, err := New("")
	if err != nil {
		t.Skipf("skipping: db init error: %v", err)
	}
	defer store.Close()

	if err := store.Ping(context.Background()); err != nil {
		t.Fatalf("Ping on open store failed: %v", err)
	}

	// After Close, Ping must fail.
	_ = store.Close()
	if err := store.Ping(context.Background()); err == nil {
		t.Fatalf("Ping after Close expected an error, got nil")
	}
}
