package oidc

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"html/template"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	kubauthv1alpha1 "kubauth/api/kubauth/v1alpha1"
	oidcControllers "kubauth/cmd/kubauth/cmd/oidc/controllers"
	"kubauth/cmd/kubauth/cmd/oidc/handlers"
	"kubauth/cmd/kubauth/cmd/oidc/oidcserver"
	"kubauth/cmd/kubauth/cmd/oidc/storage"
	"kubauth/cmd/kubauth/cmd/oidc/userdb"
	oidcWebhooks "kubauth/cmd/kubauth/cmd/oidc/webhooks"
	"kubauth/cmd/kubauth/global"
	"kubauth/internal/httpsrv"
	"kubauth/internal/misc"
	"log/slog"
	"net/http"
	"os"
	"path"
	"path/filepath"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/certwatcher"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

var flags struct {
	logConfig misc.LogConfig

	oidcHttpConfig httpsrv.Config
	Issuer         string
	Resources      string

	probeAddr            string
	enableLeaderElection bool // Must be true, as memory storage require a single context
	enableHTTP2          bool

	enableWebhook   bool
	webhookCertPath string
	webhookCertName string
	webhookCertKey  string

	metricsAddr     string
	secureMetrics   bool
	metricsCertPath string
	metricsCertName string
	metricsCertKey  string

	clientNamespace string
}

var (
	scheme = runtime.NewScheme()
)

func init() {
	Cmd.PersistentFlags().StringVarP(&flags.logConfig.Mode, "logMode", "", "text", "Log mode (dev or json)")
	Cmd.PersistentFlags().StringVarP(&flags.logConfig.Level, "logLevel", "l", "INFO", "Log level(DEBUG, INFO, WARN, ERROR)")

	Cmd.PersistentFlags().StringVar(&flags.probeAddr, "healthProbeBindAddress", ":8110", "The address the probe endpoint binds to.")
	Cmd.PersistentFlags().BoolVar(&flags.enableLeaderElection, "leaderElect", true, "Enable leader election for controller manager. Must be set, as memory storage require a single instance")
	Cmd.PersistentFlags().BoolVar(&flags.enableHTTP2, "enableHttp2", false, "If set, HTTP/2 will be enabled for the metrics and webhook servers")
	Cmd.PersistentFlags().BoolVar(&flags.enableWebhook, "enableWebhook", true, "If set the webhook server will be enabled")
	Cmd.PersistentFlags().StringVar(&flags.webhookCertPath, "webhookCertPath", "", "The directory that contains the webhook certificate.")
	Cmd.PersistentFlags().StringVar(&flags.webhookCertName, "webhookCertName", "tls.crt", "The name of the webhook certificate file.")
	Cmd.PersistentFlags().StringVar(&flags.webhookCertKey, "webhookCertKey", "tls.key", "The name of the webhook key file.")
	Cmd.PersistentFlags().StringVar(&flags.metricsAddr, "metricsBindAddress", "0", "The address the metrics endpoint binds to. Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	Cmd.PersistentFlags().BoolVar(&flags.secureMetrics, "metricsSecure", true, "If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	Cmd.PersistentFlags().StringVar(&flags.metricsCertPath, "metricsCertPath", "", "The directory that contains the metrics server certificate.")
	Cmd.PersistentFlags().StringVar(&flags.metricsCertName, "metricsCertName", "tls.crt", "The name of the metrics server certificate file.")
	Cmd.PersistentFlags().StringVar(&flags.metricsCertKey, "metricsCertKey", "tls.key", "The name of the metrics server key file.")
	Cmd.PersistentFlags().StringVar(&flags.clientNamespace, "clientNamespace", "", "The namespace hosting OidcClient resources.")

	// OIDC config
	Cmd.PersistentFlags().BoolVarP(&flags.oidcHttpConfig.Tls, "tls", "t", false, "enable TLS")
	Cmd.PersistentFlags().BoolVarP(&flags.oidcHttpConfig.DumpExchange, "dumpExchange", "", false, "Dump http server req/resp in DEBUG mode")
	Cmd.PersistentFlags().StringVarP(&flags.oidcHttpConfig.BindAddr, "bindAddr", "a", "0.0.0.0", "Bind Address")
	Cmd.PersistentFlags().IntVarP(&flags.oidcHttpConfig.BindPort, "bindPort", "p", 8101, "Bind port")
	Cmd.PersistentFlags().StringVarP(&flags.oidcHttpConfig.CertDir, "certDir", "", "", "Certificate Directory")
	//Cmd.PersistentFlags().StringArrayVarP(&flags.oidcHttpConfig.AllowedOrigins, "allowedOrigins", "", []string{}, "Allowed Origins")
	Cmd.PersistentFlags().StringVarP(&flags.Issuer, "issuer", "i", "http://localhost:8101", "Issuer URL")
	Cmd.PersistentFlags().StringVarP(&flags.Resources, "resources", "", "resources", "Resources folders")

	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(kubauthv1alpha1.AddToScheme(scheme))
}

var Cmd = &cobra.Command{
	Use:   "oidc",
	Short: "OIDC/oauth server",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		var tlsOpts []func(*tls.Config)

		var err error
		logger, err := misc.NewLogger(&flags.logConfig)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Unable to load logging configuration: %v\n", err)
			os.Exit(2)
		}
		ctrl.SetLogger(logr.FromSlogHandler(logger.Handler()))
		setupLog := ctrl.Log.WithName("setup")

		logger.Info("Starting OIDC Server", slog.String("logLevel", flags.logConfig.Level), slog.String("version", global.Version), slog.String("build", global.BuildTs))

		if flags.clientNamespace == "" {
			setupLog.Error(nil, "clientNamespace must be specified and non null")
			os.Exit(1)
		}

		// if the enable-http2 flag is false (the default), http/2 should be disabled
		// due to its vulnerabilities. More specifically, disabling http/2 will
		// prevent from being vulnerable to the HTTP/2 Stream Cancellation and
		// Rapid Reset CVEs. For more information see:
		// - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
		// - https://github.com/advisories/GHSA-4374-p667-p6c8
		disableHTTP2 := func(c *tls.Config) {
			setupLog.Info("disabling http/2")
			c.NextProtos = []string{"http/1.1"}
		}

		if !flags.enableHTTP2 {
			tlsOpts = append(tlsOpts, disableHTTP2)
		}

		// Create watchers for metrics and webhooks certificates
		var metricsCertWatcher, webhookCertWatcher *certwatcher.CertWatcher

		// Initial webhook TLS options
		webhookTLSOpts := tlsOpts

		if len(flags.webhookCertPath) > 0 {
			setupLog.Info("Initializing webhook certificate watcher using provided certificates",
				"webhook-cert-path", flags.webhookCertPath, "webhook-cert-name", flags.webhookCertName, "webhook-cert-key", flags.webhookCertKey)

			var err error
			webhookCertWatcher, err = certwatcher.New(
				filepath.Join(flags.webhookCertPath, flags.webhookCertName),
				filepath.Join(flags.webhookCertPath, flags.webhookCertKey),
			)
			if err != nil {
				setupLog.Error(err, "Failed to initialize webhook certificate watcher")
				os.Exit(1)
			}

			webhookTLSOpts = append(webhookTLSOpts, func(config *tls.Config) {
				config.GetCertificate = webhookCertWatcher.GetCertificate
			})
		}

		webhookServer := webhook.NewServer(webhook.Options{
			TLSOpts: webhookTLSOpts,
		})

		// Metrics endpoint is enabled in 'config/default/kustomization.yaml'. The Metrics options configure the server.
		// More info:
		// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.21.0/pkg/metrics/server
		// - https://book.kubebuilder.io/reference/metrics.html
		metricsServerOptions := metricsserver.Options{
			BindAddress:   flags.metricsAddr,
			SecureServing: flags.secureMetrics,
			TLSOpts:       tlsOpts,
		}

		if flags.secureMetrics {
			// FilterProvider is used to protect the metrics endpoint with authn/authz.
			// These configurations ensure that only authorized users and service accounts
			// can access the metrics endpoint. The RBAC are configured in 'config/rbac/kustomization.yaml'. More info:
			// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.21.0/pkg/metrics/filters#WithAuthenticationAndAuthorization
			metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
		}

		// If the certificate is not specified, controller-runtime will automatically
		// generate self-signed certificates for the metrics server. While convenient for development and testing,
		// this setup is not recommended for production.
		if len(flags.metricsCertPath) > 0 {
			setupLog.Info("Initializing metrics certificate watcher using provided certificates",
				"metrics-cert-path", flags.metricsCertPath, "metrics-cert-name", flags.metricsCertName, "metrics-cert-key", flags.metricsCertKey)

			var err error
			metricsCertWatcher, err = certwatcher.New(
				filepath.Join(flags.metricsCertPath, flags.metricsCertName),
				filepath.Join(flags.metricsCertPath, flags.metricsCertKey),
			)
			if err != nil {
				setupLog.Error(err, "to initialize metrics certificate watcher", "error", err)
				os.Exit(1)
			}

			metricsServerOptions.TLSOpts = append(metricsServerOptions.TLSOpts, func(config *tls.Config) {
				config.GetCertificate = metricsCertWatcher.GetCertificate
			})
		}

		ctx := logr.NewContextWithSlogLogger(context.Background(), logger)

		mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
			Scheme:                 scheme,
			Metrics:                metricsServerOptions,
			WebhookServer:          webhookServer,
			HealthProbeBindAddress: flags.probeAddr,
			LeaderElection:         flags.enableLeaderElection,
			LeaderElectionID:       "33b8e6ab.kubotal.io",
			BaseContext:            func() context.Context { return ctx },
		})
		if err != nil {
			setupLog.Error(err, "unable to start manager")
			os.Exit(1)
		}

		// ------------------------------------- Create our storage
		storage := storage.NewMemoryStore()

		// Setup OidcClient Reconciler
		oidcClientReconciler := &oidcControllers.OidcClientReconciler{
			Client:  mgr.GetClient(),
			Scheme:  mgr.GetScheme(),
			Storage: storage,
		}

		err = ctrl.NewControllerManagedBy(mgr).
			For(&kubauthv1alpha1.OidcClient{}).
			Named("kubauth-oidcClient").
			Complete(oidcClientReconciler)

		if flags.enableWebhook {
			if err := oidcWebhooks.SetupOidcClientWebhookWithManager(mgr); err != nil {
				setupLog.Error(err, "unable to create webhook", "webhook", "OidcClient")
				os.Exit(1)
			}
		}
		// +kubebuilder:scaffold:builder

		if metricsCertWatcher != nil {
			setupLog.Info("Adding metrics certificate watcher to manager")
			if err := mgr.Add(metricsCertWatcher); err != nil {
				setupLog.Error(err, "unable to add metrics certificate watcher to manager")
				os.Exit(1)
			}
		}

		if webhookCertWatcher != nil {
			setupLog.Info("Adding webhook certificate watcher to manager")
			if err := mgr.Add(webhookCertWatcher); err != nil {
				setupLog.Error(err, "unable to add webhook certificate watcher to manager")
				os.Exit(1)
			}
		}

		if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
			setupLog.Error(err, "unable to set up health check")
			os.Exit(1)
		}
		if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
			setupLog.Error(err, "unable to set up ready check")
			os.Exit(1)
		}

		// ---------------------- Setup our OIDC server
		router := http.NewServeMux()
		router.Handle("GET /favicon.ico", handlers.FaviconHandler(path.Join(flags.Resources, "static", "favicon.ico")))

		userDb := userdb.NewUserDb()

		(&oidcserver.OIDCServer{
			Issuer:        flags.Issuer,
			Storage:       storage,
			UserDb:        userDb,
			Resources:     flags.Resources,
			LoginTemplate: template.Must(template.ParseFiles(path.Join(flags.Resources, "templates", "login.gohtml"))),
		}).Setup(router)

		server := httpsrv.New("oidcSrv", &flags.oidcHttpConfig, router)

		err = mgr.Add(server)
		if err != nil {
			setupLog.Error(err, "unable to add oidc server to the manager")
			os.Exit(1)
		}

		// ------------------------------- Everything is setup. Start manager
		setupLog.Info("starting manager")
		if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
			setupLog.Error(err, "problem running manager")
			os.Exit(1)
		}
	},
}
