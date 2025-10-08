package ldap

import (
	"context"
	"fmt"
	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"kubauth/cmd/ldap/authenticator"
	"kubauth/cmd/ldap/config"
	"kubauth/internal/global"
	"kubauth/internal/handlers"
	"kubauth/internal/handlers/protector"
	"kubauth/internal/handlers/validator"
	"kubauth/internal/httpsrv"
	"kubauth/internal/misc"
	"log/slog"
	"net/http"
	"os"
)

var ldapParams struct {
	logConfig     misc.LogConfig
	displayFlags  bool
	httpConfig    httpsrv.Config
	bfaProtection bool
	configFile    string
}

func init() {
	Cmd.PersistentFlags().StringVarP(&ldapParams.logConfig.Mode, "logMode", "", "text", "Log mode ('text' or 'json')")
	Cmd.PersistentFlags().StringVarP(&ldapParams.logConfig.Level, "logLevel", "l", "INFO", "Log level(DEBUG, INFO, WARN, ERROR)")
	Cmd.PersistentFlags().BoolVar(&ldapParams.displayFlags, "displayFlags", true, "Dump flags values")

	Cmd.PersistentFlags().BoolVarP(&ldapParams.httpConfig.Tls, "tls", "t", false, "enable TLS")
	Cmd.PersistentFlags().IntVar(&ldapParams.httpConfig.DumpExchanges, "dumpExchanges", 0, "Dump http server req/resp (0, 1, 2 or 3)")
	Cmd.PersistentFlags().StringVarP(&ldapParams.httpConfig.BindAddr, "bindAddr", "a", "127.0.0.1", "Bind Address")
	Cmd.PersistentFlags().IntVarP(&ldapParams.httpConfig.BindPort, "bindPort", "p", global.DefaultPorts.Ldap.Entry, "Bind port")
	Cmd.PersistentFlags().StringVarP(&ldapParams.httpConfig.CertDir, "certDir", "", "", "Certificate Directory")
	Cmd.PersistentFlags().StringVar(&ldapParams.httpConfig.CertName, "certName", "tls.crt", "Certificate Directory")
	Cmd.PersistentFlags().StringVar(&ldapParams.httpConfig.KeyName, "keyName", "tls.key", "Certificate Directory")

	Cmd.PersistentFlags().BoolVar(&ldapParams.bfaProtection, "bfaProtection", false, "Activate Brut Force Attack protection")

	Cmd.PersistentFlags().StringVarP(&ldapParams.configFile, "configFile", "c", "./config.yaml", "Config file path")

}

var Cmd = &cobra.Command{
	Use:   "ldap",
	Short: "LDAP connector",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {

		logger, err := misc.NewLogger(&ldapParams.logConfig)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Unable to load logging configuration: %v\n", err)
			os.Exit(2)
		}

		logger.Info("Starting LDAP connector", slog.String("logLevel", ldapParams.logConfig.Level), slog.String("version", global.Version), slog.String("build", global.BuildTs))

		config := &config.Config{}

		configPath, err := misc.LoadConfig(ldapParams.configFile, config)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Unable to load configuration from %s: %v\n", configPath, err)
			os.Exit(2)
		}

		// Inject logger into context
		ctx := logr.NewContextWithSlogLogger(context.Background(), logger)

		// Create HTTP router
		mux := http.NewServeMux()

		authenticator, err := authenticator.New(&config.Ldap, configPath)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Unable to create authenticator: %v\n", err)
			os.Exit(2)
		}

		identityHandler := &handlers.IdentityHandler{
			Validators:    []validator.Validator{validator.OnlyGetValidator{}},
			Authenticator: authenticator,
			Protector:     protector.New(ldapParams.bfaProtection, ctx),
		}

		mux.Handle("/v1/identity", identityHandler)

		// Create and start HTTP server
		httpServer := httpsrv.New("ldapConnector", &ldapParams.httpConfig, mux)

		if err := httpServer.Start(ctx); err != nil {
			logger.Error("Error starting HTTP server", "error", err)
			os.Exit(1)
		}

	},
}
