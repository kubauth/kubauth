/*
Copyright (c) Kubotal 2025.

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

package logger

import (
	"context"
	"fmt"
	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"kubauth/cmd/logger/authenticator"
	"kubauth/internal/global"
	"kubauth/internal/handlers"
	"kubauth/internal/handlers/protector"
	"kubauth/internal/handlers/validator"
	"kubauth/internal/httpclient"
	"kubauth/internal/httpsrv"
	"kubauth/internal/misc"
	"log/slog"
	"net/http"
	"os"
)

var loggerParams struct {
	logConfig     misc.LogConfig
	displayFlags  bool
	httpConfig    httpsrv.Config
	bfaProtection bool
	idpHttpConfig httpclient.Config
}

func init() {
	Cmd.PersistentFlags().StringVarP(&loggerParams.logConfig.Mode, "logMode", "", "text", "Log mode ('text' or 'json')")
	Cmd.PersistentFlags().StringVarP(&loggerParams.logConfig.Level, "logLevel", "l", "INFO", "Log level(DEBUG, INFO, WARN, ERROR)")
	Cmd.PersistentFlags().BoolVar(&loggerParams.displayFlags, "displayFlags", true, "Dump flags values")

	Cmd.PersistentFlags().BoolVarP(&loggerParams.httpConfig.Tls, "tls", "t", false, "enable TLS")
	Cmd.PersistentFlags().IntVar(&loggerParams.httpConfig.DumpExchanges, "dumpExchanges", 0, "Dump http server req/resp (0, 1, 2 or 3)")
	Cmd.PersistentFlags().StringVarP(&loggerParams.httpConfig.BindAddr, "bindAddr", "a", "127.0.0.1", "Bind Address")
	Cmd.PersistentFlags().IntVarP(&loggerParams.httpConfig.BindPort, "bindPort", "p", global.DefaultPorts.Logger.Entry, "Bind port")
	Cmd.PersistentFlags().StringVarP(&loggerParams.httpConfig.CertDir, "certDir", "", "", "Certificate Directory")
	Cmd.PersistentFlags().StringVar(&loggerParams.httpConfig.CertName, "certName", "tls.crt", "Certificate Directory")
	Cmd.PersistentFlags().StringVar(&loggerParams.httpConfig.KeyName, "keyName", "tls.key", "Certificate Directory")

	Cmd.PersistentFlags().BoolVar(&loggerParams.bfaProtection, "bfaProtection", false, "Activate Brut Force Attack protection")

	// Idp (Identity provider) config
	Cmd.PersistentFlags().StringVar(&loggerParams.idpHttpConfig.BaseURL, "idpBaseURL", fmt.Sprintf("http://localhost:%d", global.DefaultPorts.Merger.Entry), "The Identity provider base URL")
	Cmd.PersistentFlags().StringArrayVar(&loggerParams.idpHttpConfig.RootCaPaths, "idpRootCAPath", []string{}, "The Identity provider root CA paths (Several values possible)")
	Cmd.PersistentFlags().BoolVar(&loggerParams.idpHttpConfig.InsecureSkipVerify, "idpInsecureSkipVerify", false, "If set, skip the CA certificate verification")

}

var Cmd = &cobra.Command{
	Use:   "logger",
	Short: "Login logger",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {

		logger, err := misc.NewLogger(&loggerParams.logConfig)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Unable to load logging configuration: %v\n", err)
			os.Exit(2)
		}

		logger.Info("Starting logger module", slog.String("logLevel", loggerParams.logConfig.Level), slog.String("version", global.Version), slog.String("build", global.BuildTs))

		// Inject logger into context
		ctx := logr.NewContextWithSlogLogger(context.Background(), logger)

		// Create HTTP router
		mux := http.NewServeMux()

		authenticator, err := authenticator.New(&loggerParams.idpHttpConfig)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Unable to create authenticator: %v\n", err)
			os.Exit(2)
		}

		identityHandler := &handlers.IdentityHandler{
			Validators:    []validator.Validator{validator.OnlyGetValidator{}},
			Authenticator: authenticator,
			Protector:     protector.New(loggerParams.bfaProtection, ctx),
		}

		mux.Handle("/v1/identity", identityHandler)

		// Create and start HTTP server
		httpServer := httpsrv.New("ldapConnector", &loggerParams.httpConfig, mux)

		if err := httpServer.Start(ctx); err != nil {
			logger.Error("Error starting HTTP server", "error", err)
			os.Exit(1)
		}

	},
}
