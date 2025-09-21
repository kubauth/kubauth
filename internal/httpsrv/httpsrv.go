/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package httpsrv

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/go-logr/logr"
	"github.com/rs/cors"
	"kubauth/internal/httpsrv/certwatcher"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"time"
)

type Config struct {
	BindAddr       string   `yaml:"bindAddr"`
	BindPort       int      `yaml:"bindPort"`
	Tls            bool     `yaml:"tls"`
	CertDir        string   `yaml:"certDir"`       // CertDir is the directory that contains the server key and certificate.
	CertName       string   `yaml:"certName"`      // CertName is the server certificate name. Defaults to tls.crt.
	KeyName        string   `yaml:"keyName"`       // KeyName is the server key name. Defaults to tls.key.
	DumpExchanges  int      `yaml:"dumpExchanges"` // 0: No dump, <5 -> One debug message, >5 -> full message
	AllowedOrigins []string `yaml:"allowedOrigins"`
}

type HttpServer interface {
	Start(ctx context.Context) error
}

type httpServer struct {
	name   string
	config *Config
	router http.Handler
}

var _ HttpServer = &httpServer{}

func New(name string, config *Config, router http.Handler) HttpServer {

	if len(config.AllowedOrigins) > 0 {
		c := cors.New(cors.Options{
			AllowedOrigins: config.AllowedOrigins,
		})
		router = c.Handler(router)
	}
	if config.DumpExchanges > 0 {
		router = LoggingMiddleware(router, config.DumpExchanges)
	}
	return &httpServer{
		name:   name,
		config: config,
		router: router,
	}
}

func (hs *httpServer) Start(ctx context.Context) error {
	logger := logr.FromContextAsSlogLogger(ctx).With("name", hs.name)
	if logger == nil {
		return errors.New("no logger provided in context. Use logr.NewContextWithSlogLogger()")
	}

	var listener net.Listener
	var err error
	if !hs.config.Tls {
		listener, err = net.Listen("tcp", fmt.Sprintf("%s:%d", hs.config.BindAddr, hs.config.BindPort))
		if err != nil {
			return fmt.Errorf("httpServer %s: Error on net.Listen(): %w", hs.name, err)
		}
	} else {
		if hs.config.CertDir == "" {
			return fmt.Errorf("httpServer %s: CertDir is not defined while 'tls'' is true", hs.name)
		}
		certPath := filepath.Join(hs.config.CertDir, hs.config.CertName)
		keyPath := filepath.Join(hs.config.CertDir, hs.config.KeyName)
		certWatcher, err := certwatcher.New(certPath, keyPath, logger)
		if err != nil {
			return fmt.Errorf("httpServer %s: Error on certwatcher.New(): %w", hs.name, err)
		}
		go func() {
			if err := certWatcher.Start(ctx); err != nil {
				logger.Error("certificate watcher error", slog.Any("error", err))
			}
		}()

		cfg := &tls.Config{
			NextProtos:     []string{"h2"},
			GetCertificate: certWatcher.GetCertificate,
		}

		listener, err = tls.Listen("tcp", fmt.Sprintf("%s:%d", hs.config.BindAddr, hs.config.BindPort), cfg)
		if err != nil {
			return fmt.Errorf("httpServer %s: Error on tls.Listen(): %w", hs.name, err)
		}
	}

	logger.Info("Listening", "bindAddr", hs.config.BindAddr, "port", hs.config.BindPort, "tls", hs.config.Tls, "name", hs.name)

	srv := &http.Server{
		Handler:      hs.router,
		BaseContext:  func(net.Listener) context.Context { return ctx },
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	idleConsClosed := make(chan struct{})
	go func() {
		<-ctx.Done()
		logger.Info("shutting down server")

		// TODO: use a context with reasonable timeout
		if err := srv.Shutdown(context.Background()); err != nil {
			// Error from closing listeners, or context timeout
			logger.Error("error shutting down the HTTP server", slog.Any("error", err))
		}
		close(idleConsClosed)
	}()

	err = srv.Serve(listener)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("httpServer %s: Error on srv.Serve(): %w", hs.name, err)
	}
	logger.Info("httpServer %s shutdown", hs.name)
	<-idleConsClosed
	return nil

}
