package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	os.Exit(run())
}

func run() int {
	var (
		selfSignedAddr = flag.String("self-signed-addr", "127.0.0.1:9443", "address for the self-signed HTTPS listener")
		caAddr         = flag.String("ca-addr", "127.0.0.1:9444", "address for the CA-signed HTTPS listener")
		mtlsAddr       = flag.String("mtls-addr", "127.0.0.1:9445", "address for the mTLS HTTPS listener")
	)
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger := log.New(os.Stdout, "todoapi: ", log.LstdFlags)
	server, err := newDemoServer(*selfSignedAddr, *caAddr, *mtlsAddr, logger)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	logger.Printf("generated certificates in %s", server.certs.Dir)
	logger.Printf("self-signed listener: https://%s", server.selfSignedAddr)
	logger.Printf("ca-signed listener: https://%s", server.caAddr)
	logger.Printf("mTLS listener: https://%s", server.mtlsAddr)
	logger.Printf("press Ctrl+C to stop")

	if err := server.serve(ctx); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func serveServer(ctx context.Context, srv *http.Server, logger *log.Logger, certFile, keyFile string) error {
	return serveWithGracefulShutdown(ctx, srv, shutdownTimeout, func() error {
		logger.Printf("serving %s", srv.Addr)
		return srv.ListenAndServeTLS(certFile, keyFile)
	})
}

// serveWithGracefulShutdown runs serveFunc (which blocks until the server
// stops) and, on ctx cancellation, attempts a graceful shutdown before
// force-closing the server if that shutdown doesn't complete within
// gracePeriod. This keeps a still-active handler from hanging SIGTERM
// indefinitely.
func serveWithGracefulShutdown(ctx context.Context, srv *http.Server, gracePeriod time.Duration, serveFunc func() error) error {
	errCh := make(chan error, 1)
	go func() {
		errCh <- serveFunc()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), gracePeriod)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			// Graceful shutdown didn't finish within the timeout (e.g. a
			// handler is still active); force-close so the serve goroutine
			// unblocks instead of hanging indefinitely on SIGTERM.
			_ = srv.Close()
		}
		err := <-errCh
		if errors.Is(err, http.ErrServerClosed) {
			return ctx.Err()
		}
		return err
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
