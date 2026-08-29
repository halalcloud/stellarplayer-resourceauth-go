package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	resourceauth "github.com/halalcloud/stellarplayer-resourceauth-go"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	issuer := strings.TrimSpace(os.Getenv("RESOURCE_OAUTH_ISSUER"))
	audience := strings.TrimSpace(os.Getenv("RESOURCE_OAUTH_AUDIENCE"))
	if issuer == "" || audience == "" {
		logger.Error("RESOURCE_OAUTH_ISSUER and RESOURCE_OAUTH_AUDIENCE are required")
		os.Exit(2)
	}

	handler, err := newHandler(ctx, logger, issuer, audience)
	if err != nil {
		logger.Error("initialize resource authentication", "error", err)
		os.Exit(1)
	}
	server := &http.Server{
		Addr:              "127.0.0.1:18082",
		Handler:           handler,
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	serveErrors := make(chan error, 1)
	go func() {
		serveErrors <- server.ListenAndServe()
	}()

	select {
	case err := <-serveErrors:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("resource server stopped", "error", err)
			os.Exit(1)
		}
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Error("resource server shutdown failed", "error", err)
			os.Exit(1)
		}
	}
}

func newHandler(
	ctx context.Context,
	logger *slog.Logger,
	issuer string,
	audience string,
) (http.Handler, error) {
	verifier, err := resourceauth.NewRemoteVerifier(ctx, resourceauth.RemoteVerifierOptions{
		Issuer: issuer, Audience: audience, MaxTokenTTL: 15 * time.Minute,
		RefreshInterval: 5 * time.Minute,
	})
	if err != nil {
		return nil, err
	}
	authenticator, err := resourceauth.NewAuthenticator(verifier)
	if err != nil {
		return nil, err
	}
	go verifier.Run(ctx, logger)

	router := http.NewServeMux()
	router.HandleFunc("GET /health/live", func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	})
	router.Handle(
		"GET /api/me",
		authenticator.Authenticate(
			resourceauth.RequireScopes("profile.read")(http.HandlerFunc(me)),
		),
	)
	return router, nil
}

func me(writer http.ResponseWriter, request *http.Request) {
	principal, ok := resourceauth.PrincipalFromContext(request.Context())
	if !ok {
		http.Error(writer, "principal missing", http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(writer).Encode(map[string]string{
		"subject_id": principal.SubjectID.String(),
		"client_id":  principal.ClientID,
	})
}
