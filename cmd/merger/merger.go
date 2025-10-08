package merger

import (
	"context"
	"fmt"
	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"kubauth/cmd/merger/authenticator"
	"kubauth/cmd/merger/config"
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

/*
	For a given user, each provider provide this set of info;
		Name: 	string
		Emails: []string{},
		Groups: []string{},
		Claims: map[string]interface{}{},

	Loop is from upper priority to lower one
	All 'append' operation detect duplicate.
	For each provider in the loop, if user exists:

		if credentialAuthority and if user password exists, set user password status and the uid
		if claimAuthority:
			- provider's claim pattern is applied.
			- Current claims are merged on top of provider's one. And become current one
		- If groupAuthority:
			- Groups pattern is applied
			- Groups are appended
		- if nameAuthority and name not already set, name is set
		- Emails are appended if emailAuthority

	Groups are sorted at the end

	if one provider set 'disabled' status, user is disabled

	It is up to each provider to set/modify name, emails[] and groups[] from claim values, if appropriate.

	On other side, it is up to the OIDC server to set claims from resulting CommonName[], email[] and groups[]

*/

var mergerParams struct {
	logConfig     misc.LogConfig
	displayFlags  bool
	httpConfig    httpsrv.Config
	bfaProtection bool
	configFile    string
}

func init() {
	Cmd.PersistentFlags().StringVarP(&mergerParams.logConfig.Mode, "logMode", "", "text", "Log mode ('text' or 'json')")
	Cmd.PersistentFlags().StringVarP(&mergerParams.logConfig.Level, "logLevel", "l", "INFO", "Log level(DEBUG, INFO, WARN, ERROR)")
	Cmd.PersistentFlags().BoolVar(&mergerParams.displayFlags, "displayFlags", true, "Dump flags values")

	Cmd.PersistentFlags().BoolVarP(&mergerParams.httpConfig.Tls, "tls", "t", false, "enable TLS")
	Cmd.PersistentFlags().IntVar(&mergerParams.httpConfig.DumpExchanges, "dumpExchanges", 0, "Dump http server req/resp (0, 1, 2 or 3)")
	Cmd.PersistentFlags().StringVarP(&mergerParams.httpConfig.BindAddr, "bindAddr", "a", "127.0.0.1", "Bind Address")
	Cmd.PersistentFlags().IntVarP(&mergerParams.httpConfig.BindPort, "bindPort", "p", global.DefaultPorts.Merger.Entry, "Bind port")
	Cmd.PersistentFlags().StringVarP(&mergerParams.httpConfig.CertDir, "certDir", "", "", "Certificate Directory")
	Cmd.PersistentFlags().StringVar(&mergerParams.httpConfig.CertName, "certName", "tls.crt", "Certificate Directory")
	Cmd.PersistentFlags().StringVar(&mergerParams.httpConfig.KeyName, "keyName", "tls.key", "Certificate Directory")

	Cmd.PersistentFlags().BoolVar(&mergerParams.bfaProtection, "bfaProtection", false, "Activate Brut Force Attack protection")

	Cmd.PersistentFlags().StringVarP(&mergerParams.configFile, "configFile", "c", "./config.yaml", "Config file path")

}

var Cmd = &cobra.Command{
	Use:   "merger",
	Short: "Merge identity providers result",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {

		logger, err := misc.NewLogger(&mergerParams.logConfig)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Unable to load logging configuration: %v\n", err)
			os.Exit(2)
		}

		logger.Info("Starting merger connector", slog.String("logLevel", mergerParams.logConfig.Level), slog.String("version", global.Version), slog.String("build", global.BuildTs))

		config := &config.Config{}

		configPath, err := misc.LoadConfig(mergerParams.configFile, config)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Unable to load configuration from %s: %v\n", configPath, err)
			os.Exit(2)
		}

		// Inject logger into context
		ctx := logr.NewContextWithSlogLogger(context.Background(), logger)

		// Create HTTP router
		mux := http.NewServeMux()

		authenticator, err := authenticator.New(config)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Unable to create authenticator: %v\n", err)
			os.Exit(2)
		}

		identityHandler := &handlers.IdentityHandler{
			Validators:    []validator.Validator{validator.OnlyGetValidator{}},
			Authenticator: authenticator,
			Protector:     protector.New(mergerParams.bfaProtection, ctx),
		}

		mux.Handle("/v1/identity", identityHandler)

		// Create and start HTTP server
		httpServer := httpsrv.New("mergerConnector", &mergerParams.httpConfig, mux)

		if err := httpServer.Start(ctx); err != nil {
			logger.Error("Error starting HTTP server", "error", err)
			os.Exit(1)
		}

	},
}
