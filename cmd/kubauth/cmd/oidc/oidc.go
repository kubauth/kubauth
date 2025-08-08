package oidc

import (
	"context"
	"fmt"
	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"html/template"
	"kubauth/cmd/kubauth/cmd/oidc/config"
	"kubauth/cmd/kubauth/cmd/oidc/handlers"
	"kubauth/cmd/kubauth/cmd/oidc/oidcserver"
	"kubauth/cmd/kubauth/cmd/oidc/userdb"
	"kubauth/cmd/kubauth/global"
	"kubauth/internal/httpsrv"
	"kubauth/internal/misc"
	"log/slog"
	"net/http"
	"os"
	"path"
)

var logConfig = &misc.LogConfig{}

func init() {
	Cmd.PersistentFlags().StringVarP(&logConfig.Mode, "logMode", "", "text", "Log mode (dev or json)")
	Cmd.PersistentFlags().StringVarP(&logConfig.Level, "logLevel", "l", "INFO", "Log level(DEBUG, INFO, WARN, ERROR)")
	Cmd.PersistentFlags().BoolVarP(&config.Conf.HttpConfig.Tls, "tls", "t", false, "enable TLS")
	Cmd.PersistentFlags().BoolVarP(&config.Conf.HttpConfig.DumpExchange, "dumpExchange", "", false, "Dump http server req/resp in DEBUG mode")
	Cmd.PersistentFlags().StringVarP(&config.Conf.HttpConfig.BindAddr, "bindAddr", "a", "0.0.0.0", "Bind Address")
	Cmd.PersistentFlags().IntVarP(&config.Conf.HttpConfig.BindPort, "bindPort", "p", 8080, "Bind port")
	Cmd.PersistentFlags().StringVarP(&config.Conf.HttpConfig.CertDir, "certDir", "", "", "Certificate Directory")
	Cmd.PersistentFlags().StringArrayVarP(&config.Conf.HttpConfig.AllowedOrigins, "allowedOrigins", "", []string{}, "Allowed Origins")
	Cmd.PersistentFlags().StringVarP(&config.Conf.Issuer, "issuer", "i", "http://localhost:8080", "Issuer URL")
	Cmd.PersistentFlags().StringVarP(&config.Conf.Resources, "resources", "", "resources", "Resources folders")

}

var Cmd = &cobra.Command{
	Use:   "oidc",
	Short: "OIDC/oauth server",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		logger, err := misc.NewLogger(logConfig)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		logger.Info("Starting OIDC Server", slog.String("logLevel", logConfig.Level), slog.String("version", global.Version), slog.String("build", global.BuildTs))

		//testClientStorage()

		router := http.NewServeMux()
		router.Handle("GET /favicon.ico", handlers.FaviconHandler(path.Join(config.Conf.Resources, "static", "favicon.ico")))

		userDb := userdb.NewUserDb()

		_ = oidcserver.NewOIDCServer(router, userDb, template.Must(template.ParseFiles(path.Join(config.Conf.Resources, "templates", "login.gohtml"))))

		server := httpsrv.New("oidcSrv", &config.Conf.HttpConfig, router)
		ctx := logr.NewContextWithSlogLogger(context.Background(), logger)

		err = server.Start(ctx)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "%error on server launchv\n", err)
			os.Exit(1)
		}
		//log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%s", config.Conf.HttpConfig.BindAddr, config.Conf.HttpConfig.BindPort), nil))
	},
}
