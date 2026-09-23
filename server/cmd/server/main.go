package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"muiltdesk/server/internal/platform"
	"muiltdesk/server/internal/store"

	"github.com/redis/go-redis/v9"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	addr := os.Getenv("MUILTDESK_ADDR")
	if addr == "" {
		if port := os.Getenv("PORT"); port != "" {
			addr = "0.0.0.0:" + port
		} else {
			addr = "0.0.0.0:8080"
		}
	}

	key := make([]byte, 32)
	if raw := os.Getenv("MUILTDESK_JWT_KEY"); raw != "" {
		var err error
		key, err = base64.StdEncoding.DecodeString(raw)
		if err != nil || len(key) < 32 {
			slog.Error("MUILTDESK_JWT_KEY must be base64 of at least 32 random bytes")
			os.Exit(1)
		}
	} else {
		if _, err := rand.Read(key); err != nil {
			panic(err)
		}
		slog.Warn("using ephemeral JWT key; tokens expire on restart")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Persistence layer initialization
	var st store.Store
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL != "" {
		slog.Info("connecting to PostgreSQL database", "url_set", true)
		pgStore, err := store.NewPostgresStore(ctx, dbURL)
		if err != nil {
			slog.Error("failed to connect to PostgreSQL; check connection string", "error", err)
			os.Exit(1)
		}
		st = pgStore
	} else {
		slog.Info("using in-memory store (volatile mode)")
		st = store.NewMemoryStore()
	}

	// Redis decorator initialization
	redisURL := os.Getenv("REDIS_URL")
	if redisURL != "" {
		slog.Info("connecting to Redis presence cache", "url_set", true)
		opts, err := redis.ParseURL(redisURL)
		if err != nil {
			slog.Warn("invalid REDIS_URL; continuing without Redis presence", "error", err)
		} else {
			rStore, err := store.NewRedisStore(st, opts)
			if err != nil {
				slog.Warn("failed to connect to Redis; continuing without Redis presence", "error", err)
			} else {
				st = rStore
			}
		}
	}

	service := platform.NewWithStore(key, st)

	var iceURLs []string
	if raw := os.Getenv("MUILTDESK_ICE_URLS"); raw != "" {
		for _, url := range strings.Split(raw, ",") {
			if value := strings.TrimSpace(url); value != "" {
				iceURLs = append(iceURLs, value)
			}
		}
	}
	if len(iceURLs) > 0 {
		if err := service.ConfigureICE(iceURLs, os.Getenv("MUILTDESK_TURN_SECRET")); err != nil {
			slog.Error("invalid ICE configuration", "error", err)
			os.Exit(1)
		}
	}

	cert, keyfile := os.Getenv("MUILTDESK_TLS_CERT"), os.Getenv("MUILTDESK_TLS_KEY")
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		slog.Error("invalid listen address", "addr", addr)
		os.Exit(1)
	}

	ip := net.ParseIP(strings.Trim(host, "[]"))
	if (ip == nil || !ip.IsLoopback()) && (cert == "" || keyfile == "") {
		slog.Warn("listening on non-loopback address without TLS. Ensure reverse-proxy TLS termination (e.g. Caddy).")
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           service.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS13},
	}

	go func() {
		<-ctx.Done()
		slog.Info("shutting down server gracefully...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		_ = st.Close()
	}()

	slog.Info("MuiltDesk production API server started", "addr", addr)

	if cert != "" && keyfile != "" {
		err = srv.ListenAndServeTLS(cert, keyfile)
	} else {
		err = srv.ListenAndServe()
	}

	if err != nil && err != http.ErrServerClosed {
		slog.Error("server stopped with error", "error", err)
		os.Exit(1)
	}
}
