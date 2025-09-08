package oidc

import (
	"context"
	"crypto/tls"
	"fmt"
	"html/template"
	kubauthv1alpha1 "kubauth/api/kubauth/v1alpha1"
	oidcControllers "kubauth/cmd/kubauth/cmd/oidc/controllers"
	"kubauth/cmd/kubauth/cmd/oidc/handlers"
	"kubauth/cmd/kubauth/cmd/oidc/oidcserver"
	"kubauth/cmd/kubauth/cmd/oidc/oidcstorage"
	"kubauth/cmd/kubauth/cmd/oidc/sessioncodec"
	"kubauth/cmd/kubauth/cmd/oidc/sessionstore"
	"kubauth/cmd/kubauth/cmd/oidc/userdb/idprovider"
	oidcWebhooks "kubauth/cmd/kubauth/cmd/oidc/webhooks"
	"kubauth/cmd/kubauth/global"
	"kubauth/internal/httpclient"
	"kubauth/internal/httpsrv"
	"kubauth/internal/k8sapi"
	"kubauth/internal/misc"
	"log/slog"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/cache"

	scsV2 "github.com/alexedwards/scs/v2"
	"github.com/spf13/pflag"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/certwatcher"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

var flags struct {
	logConfig    misc.LogConfig
	displayFlags bool

	probeAddr            string
	enableLeaderElection bool // Must be true, as memory storage require a single context
	enableHTTP2          bool

	enableWebhook   bool
	webhookPort     int
	webhookCertPath string
	webhookCertName string
	webhookCertKey  string

	metricsAddr     string
	secureMetrics   bool
	metricsCertPath string
	metricsCertName string
	metricsCertKey  string

	// OIDC config
	oidcClientNamespace   string
	oidcHttpConfig        httpsrv.Config
	issuer                string
	resources             string
	postLogoutURL         string
	accessTokenLifespan   time.Duration
	refreshTokenLifespan  time.Duration
	jwtKeySecretName      string
	jwtKeySecretNamespace string

	// SSO Config
	ssoNamespace  string
	stickySso     bool
	ssoLifetime   time.Duration
	cleanupPeriod time.Duration

	// Idp (Identity provider) config
	idpHttpConfig httpclient.Config
}

var (
	scheme = runtime.NewScheme()
)

func init() {
	Cmd.PersistentFlags().StringVarP(&flags.logConfig.Mode, "logMode", "", "text", "Log mode ('text' or 'json')")
	Cmd.PersistentFlags().StringVarP(&flags.logConfig.Level, "logLevel", "l", "INFO", "Log level(DEBUG, INFO, WARN, ERROR)")
	Cmd.PersistentFlags().BoolVar(&flags.displayFlags, "displayFlags", true, "Dump flags values")

	Cmd.PersistentFlags().StringVar(&flags.probeAddr, "healthProbeBindAddress", ":8110", "The address the probe endpoint binds to.")
	Cmd.PersistentFlags().BoolVar(&flags.enableLeaderElection, "leaderElect", true, "Enable leader election for controller manager. Must be set, as memory storage require a single instance")
	Cmd.PersistentFlags().BoolVar(&flags.enableHTTP2, "enableHttp2", false, "If set, HTTP/2 will be enabled for the metrics and webhook servers")
	Cmd.PersistentFlags().BoolVar(&flags.enableWebhook, "enableWebhook", true, "If set the webhook server will be enabled")
	Cmd.PersistentFlags().IntVar(&flags.webhookPort, "webhookPort", 9443, "The port webhooks server in bound on.")
	Cmd.PersistentFlags().StringVar(&flags.webhookCertPath, "webhookCertPath", "", "The directory that contains the webhook certificate.")
	Cmd.PersistentFlags().StringVar(&flags.webhookCertName, "webhookCertName", "tls.crt", "The name of the webhook certificate file.")
	Cmd.PersistentFlags().StringVar(&flags.webhookCertKey, "webhookCertKey", "tls.key", "The name of the webhook key file.")
	Cmd.PersistentFlags().StringVar(&flags.metricsAddr, "metricsBindAddress", "0", "The address the metrics endpoint binds to. Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	Cmd.PersistentFlags().BoolVar(&flags.secureMetrics, "metricsSecure", true, "If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	Cmd.PersistentFlags().StringVar(&flags.metricsCertPath, "metricsCertPath", "", "The directory that contains the metrics server certificate.")
	Cmd.PersistentFlags().StringVar(&flags.metricsCertName, "metricsCertName", "tls.crt", "The name of the metrics server certificate file.")
	Cmd.PersistentFlags().StringVar(&flags.metricsCertKey, "metricsCertKey", "tls.key", "The name of the metrics server key file.")

	// OIDC config
	Cmd.PersistentFlags().StringVar(&flags.oidcClientNamespace, "oidcClientNamespace", "", "The namespace hosting OidcClient resources.")
	Cmd.PersistentFlags().BoolVarP(&flags.oidcHttpConfig.Tls, "tls", "t", false, "enable TLS")
	Cmd.PersistentFlags().IntVar(&flags.oidcHttpConfig.DumpExchanges, "dumpExchanges", 0, "Dump http server req/resp (0, 1, 2 or 3")
	Cmd.PersistentFlags().StringVarP(&flags.oidcHttpConfig.BindAddr, "bindAddr", "a", "0.0.0.0", "Bind Address")
	Cmd.PersistentFlags().IntVarP(&flags.oidcHttpConfig.BindPort, "bindPort", "p", 8101, "Bind port")
	Cmd.PersistentFlags().StringVar(&flags.oidcHttpConfig.CertDir, "certDir", "", "Certificate Directory")
	Cmd.PersistentFlags().StringVar(&flags.oidcHttpConfig.CertName, "certName", "tls.crt", "Certificate Directory")
	Cmd.PersistentFlags().StringVar(&flags.oidcHttpConfig.KeyName, "keyName", "tls.key", "Certificate Directory")
	//Cmd.PersistentFlags().StringArrayVarP(&flags.oidcHttpConfig.AllowedOrigins, "allowedOrigins", "", []string{}, "Allowed Origins")
	Cmd.PersistentFlags().StringVarP(&flags.issuer, "issuer", "i", "http://localhost:8101", "issuer URL")
	Cmd.PersistentFlags().StringVar(&flags.resources, "resources", "resources", "resources folders")
	Cmd.PersistentFlags().StringVar(&flags.postLogoutURL, "postLogoutURL", "", "Where to redirect user on logout (last resort default)")
	Cmd.PersistentFlags().DurationVar(&flags.accessTokenLifespan, "accessTokenLifespan", time.Hour*1, "AccessToken lifespan")
	Cmd.PersistentFlags().DurationVar(&flags.refreshTokenLifespan, "refreshTokenLifespan", time.Hour*1, "RefreshToken lifespan")
	Cmd.PersistentFlags().StringVar(&flags.jwtKeySecretName, "jwtKeySecretName", "jwt-signing-key", "The secret name storing the JWT signing key")
	Cmd.PersistentFlags().StringVar(&flags.jwtKeySecretNamespace, "jwtKeySecretNamespace", "", "The namespace to store the secret hosting the JWT signing key")

	// SSO Config
	Cmd.PersistentFlags().StringVar(&flags.ssoNamespace, "ssoNamespace", "", "The namespace hosting SSO sessions")
	Cmd.PersistentFlags().BoolVar(&flags.stickySso, "stickySso", false, "If set ssoSession will persists on browser restart.")
	Cmd.PersistentFlags().DurationVar(&flags.ssoLifetime, "ssoLifetime", time.Hour*8, "SSO Session absolute lifetime")
	Cmd.PersistentFlags().DurationVar(&flags.cleanupPeriod, "cleanupPeriod", time.Minute*5, "SSO Session cleanup period")

	// Idp (Identity provider) config
	Cmd.PersistentFlags().StringVar(&flags.idpHttpConfig.BaseURL, "idpBaseURL", "http://localhost:8201", "The Identity provider base URL")
	Cmd.PersistentFlags().StringArrayVar(&flags.idpHttpConfig.RootCaPaths, "idpRootCAPath", []string{}, "The Identity provider root CA paths (Several values possible)")
	Cmd.PersistentFlags().BoolVar(&flags.idpHttpConfig.InsecureSkipVerify, "idpInsecureSkipVerify", false, "If set, skip the CA certificate verification")

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

		logger.Info("Starting Kubauth OIDC Server", slog.String("logLevel", flags.logConfig.Level), slog.String("version", global.Version), slog.String("build", global.BuildTs))
		if flags.displayFlags {
			sb := new(strings.Builder)
			cmd.PersistentFlags().VisitAll(func(f *pflag.Flag) {
				_, _ = fmt.Fprintf(sb, "--%s=%q\n", f.Name, f.Value)
			})
			fmt.Printf("Flags:\n%s", sb.String())
		}

		if flags.oidcClientNamespace == "" {
			setupLog.Error(nil, "oidcClientNamespace must be specified and non null")
			os.Exit(1)
		}
		if flags.ssoNamespace == "" {
			setupLog.Error(nil, "ssoNamespace must be specified and non null")
			os.Exit(1)
		}
		if flags.postLogoutURL == "" {
			setupLog.Error(nil, "postLogoutURL must be specified and non null")
			os.Exit(1)
		}
		if flags.jwtKeySecretNamespace == "" {
			setupLog.Error(nil, "jwtKeySecretNamespace must be specified and non null")
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
			Port:    flags.webhookPort,
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
			Cache: cache.Options{
				DefaultNamespaces: map[string]cache.Config{
					flags.oidcClientNamespace: {},
				},
			},
		})
		if err != nil {
			setupLog.Error(err, "unable to start manager")
			os.Exit(1)
		}

		userDb, err := idprovider.New(&flags.idpHttpConfig)
		if err != nil {
			setupLog.Error(err, "unable to initialize user db")
			os.Exit(1)
		}
		//userDb := memory.NewUserDb()

		// ------------------------------------- Create our storage
		storage := oidcstorage.NewMemoryStore(userDb)

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

		// Setup SSO session manager
		// We need to set up our own dedicated kubeClient, as mgr.GetClient() is dedicated to cache data from oidc client namespace
		kubeClient, err := k8sapi.GetKubeClientFromConfig(ctrl.GetConfigOrDie(), scheme)
		if err != nil {
			setupLog.Error(err, "unable to create kube client")
			os.Exit(1)
		}

		// Session manager only for /oauth2/login
		sm := scsV2.New()
		// IdleTimeout is meaningless, as this session is cross application
		//s.SessionManager.IdleTimeout = time.Minute * 10
		// Use Kubernetes-backed store for SSO sessions
		sm.Store = sessionstore.NewKubeSsoStore(kubeClient, flags.ssoNamespace)
		sm.Codec = sessioncodec.JSONCodec{} // Use custom JSON codec to serialize session data as a JSON string
		sm.Lifetime = flags.ssoLifetime
		sm.Cookie.Name = "kubauth_login"
		sm.Cookie.HttpOnly = true
		sm.Cookie.SameSite = http.SameSiteLaxMode
		sm.Cookie.Persist = flags.stickySso // Session lifecycle is browser based or not
		sm.HashTokenInStore = true
		// Secure cookie only if issuer is https
		if strings.HasPrefix(flags.issuer, "https://") {
			sm.Cookie.Secure = true
		}

		// Add SSO session cleanup runnable if enabled (similar to scs memstore)
		if flags.cleanupPeriod > 0 {
			if err := mgr.Add(sessionstore.NewKubeSsoCleaner(kubeClient, flags.ssoNamespace, flags.cleanupPeriod)); err != nil {
				setupLog.Error(err, "unable to add SsoCleaner to the manager")
				os.Exit(1)
			}
		}

		// ---------------------- Setup our OIDC server
		router := http.NewServeMux()
		router.Handle("GET /favicon.ico", handlers.FaviconHandler(path.Join(flags.resources, "static", "favicon.ico")))

		err = (&oidcserver.OIDCServer{
			Issuer:                  flags.issuer,
			Storage:                 storage,
			UserDb:                  userDb,
			Resources:               flags.resources,
			LoginTemplate:           template.Must(template.ParseFiles(path.Join(flags.resources, "templates", "login.gohtml"))),
			IndexTemplate:           template.Must(template.ParseFiles(path.Join(flags.resources, "templates", "index.gohtml"))),
			SessionManager:          sm,
			PostLogoutURL:           flags.postLogoutURL,
			KubeClient:              kubeClient,
			JWTSigningKeySecretName: flags.jwtKeySecretName,
			JWTSigningKeySecretNS:   flags.jwtKeySecretNamespace,
			AccessTokenLifespan:     flags.accessTokenLifespan,
			RefreshTokenLifespan:    flags.refreshTokenLifespan,
		}).Setup(ctx, router)
		if err != nil {
			setupLog.Error(err, "unable to setup oidc server")
			os.Exit(1)
		}

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
