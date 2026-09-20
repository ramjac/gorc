package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

// TestServeWithGracefulShutdownForceClosesAfterTimeout verifies that a
// handler which never returns on its own (simulating a stuck request)
// doesn't hang serveWithGracefulShutdown forever: once the graceful
// shutdown grace period elapses, the server is force-closed so the serve
// goroutine unblocks instead of waiting indefinitely.
func TestServeWithGracefulShutdownForceClosesAfterTimeout(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	release := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		w.WriteHeader(http.StatusOK)
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: handler}

	const gracePeriod = 100 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- serveWithGracefulShutdown(ctx, srv, gracePeriod, func() error {
			return srv.Serve(listener)
		})
	}()

	client := &http.Client{Timeout: 2 * time.Second}
	go func() {
		_, _ = client.Get("http://" + listener.Addr().String() + "/")
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("handler was never invoked")
	}

	// Request shutdown while the handler is still blocked. The handler
	// intentionally never releases on its own, so only the force-close
	// path (triggered once gracePeriod elapses) should unblock serve.
	cancel()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected error from serveWithGracefulShutdown: %v", err)
		}
	case <-time.After(gracePeriod + 2*time.Second):
		t.Fatal("serveWithGracefulShutdown did not return after the grace period elapsed; a hung handler blocked shutdown indefinitely")
	}

	close(release)
}
