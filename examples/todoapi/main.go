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
	errCh := make(chan error, 1)
	go func() {
		logger.Printf("serving %s", srv.Addr)
		errCh <- srv.ListenAndServeTLS(certFile, keyFile)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
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
