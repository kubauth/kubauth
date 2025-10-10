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
	kubauthv1alpha1 "kubauth/api/kubauth/v1alpha1"
	"kubauth/cmd/logger/authenticator"
	"kubauth/internal/global"
	"kubauth/internal/handlers"
	"kubauth/internal/handlers/protector"
	"kubauth/internal/handlers/validator"
	"kubauth/internal/httpclient"
	"kubauth/internal/httpsrv"
	"kubauth/internal/k8sapi"
	"kubauth/internal/misc"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
)

var loggerParams struct {
	logConfig     misc.LogConfig
	displayFlags  bool
	httpConfig    httpsrv.Config
	bfaProtection bool
	idpHttpConfig httpclient.Config
	namespace     string

	loginLifetime time.Duration
	cleanupPeriod time.Duration
}

var (
	scheme = runtime.NewScheme()
)

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
	Cmd.PersistentFlags().StringVarP(&loggerParams.namespace, "namespace", "n", "kubauth-audit", "Namespace to store login records in")

	Cmd.PersistentFlags().DurationVar(&loggerParams.loginLifetime, "loginLifetime", time.Hour*8, "Login logs lifetime")
	Cmd.PersistentFlags().DurationVar(&loggerParams.cleanupPeriod, "cleanupPeriod", time.Minute*5, "Login logs cleanup period")

	//utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(kubauthv1alpha1.AddToScheme(scheme))

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

		logger.Info("Starting logger module", slog.String("logLevel", loggerParams.logConfig.Level), slog.String("version", global.Version), slog.String("build", global.BuildTs), slog.String("idp", loggerParams.idpHttpConfig.BaseURL))
		if loggerParams.displayFlags {
			sb := new(strings.Builder)
			cmd.PersistentFlags().VisitAll(func(f *pflag.Flag) {
				_, _ = fmt.Fprintf(sb, "--%s=%q\n", f.Name, f.Value)
			})
			fmt.Printf("Flags:\n%s", sb.String())
		}
		if loggerParams.namespace == "" {
			logger.Error("namespace must be specified and non null")
			os.Exit(1)
		}

		if loggerParams.httpConfig.BindAddr != "127.0.0.1" && loggerParams.httpConfig.BindAddr != "localhost" {
			fmt.Printf("**** WARNING ****: This enpoint is not protected and externaly accessible. It should be accessible only from side containers")
		}

		// Inject logger into context
		ctx := logr.NewContextWithSlogLogger(context.Background(), logger)

		kubeClient, err := k8sapi.GetKubeClientFromConfig(ctrl.GetConfigOrDie(), scheme)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Unable to create kubernetes client: %v\n", err)
			os.Exit(1)
		}

		// Create HTTP router
		mux := http.NewServeMux()

		authenticator, err := authenticator.New(&loggerParams.idpHttpConfig, kubeClient, loggerParams.namespace)
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

		// Start login logs cleanup process if cleanup period is configured
		if loggerParams.cleanupPeriod > 0 {
			logger.Info("Starting login logs cleanup process",
				"loginLifetime", loggerParams.loginLifetime,
				"cleanupPeriod", loggerParams.cleanupPeriod,
				"namespace", loggerParams.namespace)
			go startLoginLogsCleaner(ctx, kubeClient, logger)
		} else {
			logger.Info("Login logs cleanup disabled (cleanupPeriod is 0)")
		}

		// Create and start HTTP server
		httpServer := httpsrv.New("ldapConnector", &loggerParams.httpConfig, mux)

		if err := httpServer.Start(ctx); err != nil {
			logger.Error("Error starting HTTP server", "error", err)
			os.Exit(1)
		}

	},
}
