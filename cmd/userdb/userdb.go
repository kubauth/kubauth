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

package oidc

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	kubauthv1alpha1 "kubauth/api/kubauth/v1alpha1"
	"kubauth/cmd/userdb/handlers"
	"kubauth/cmd/userdb/webhooks"
	"kubauth/internal/global"
	"kubauth/internal/httpsrv"
	"kubauth/internal/misc"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/certwatcher"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"strings"
)

var flags struct {
	logConfig    misc.LogConfig
	displayFlags bool

	HttpConfig httpsrv.Config

	probeAddr            string
	enableLeaderElection bool // Should be false, as we are stateless
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

	usersNamespace string
}

var (
	scheme = runtime.NewScheme()
)

func init() {
	Cmd.PersistentFlags().StringVarP(&flags.logConfig.Mode, "logMode", "", "text", "Log mode ('text' or 'json')")
	Cmd.PersistentFlags().StringVarP(&flags.logConfig.Level, "logLevel", "l", "INFO", "Log level(DEBUG, INFO, WARN, ERROR)")
	Cmd.PersistentFlags().BoolVar(&flags.displayFlags, "displayFlags", true, "Dump flags values")

	Cmd.PersistentFlags().StringVar(&flags.probeAddr, "healthProbeBindAddress", ":8210", "The address the probe endpoint binds to.")
	Cmd.PersistentFlags().BoolVar(&flags.enableLeaderElection, "leaderElect", false, "Enable leader election. Should be false, as we are stateless")
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

	Cmd.PersistentFlags().StringVar(&flags.usersNamespace, "usersNamespace", "", "The namespace hosting users and groups resources.")

	// userdb server config
	Cmd.PersistentFlags().BoolVarP(&flags.HttpConfig.Tls, "tls", "t", false, "enable TLS")
	Cmd.PersistentFlags().IntVar(&flags.HttpConfig.DumpExchanges, "dumpExchanges", 0, "Dump http server req/resp (0, 1, 2 or 3)")
	Cmd.PersistentFlags().StringVarP(&flags.HttpConfig.BindAddr, "bindAddr", "a", "127.0.0.1", "Bind Address")
	Cmd.PersistentFlags().IntVarP(&flags.HttpConfig.BindPort, "bindPort", "p", 8201, "Bind port")
	Cmd.PersistentFlags().StringVarP(&flags.HttpConfig.CertDir, "certDir", "", "", "Certificate Directory")
	Cmd.PersistentFlags().StringVar(&flags.HttpConfig.CertName, "certName", "tls.crt", "Certificate Directory")
	Cmd.PersistentFlags().StringVar(&flags.HttpConfig.KeyName, "keyName", "tls.key", "Certificate Directory")
	//Cmd.PersistentFlags().StringArrayVarP(&config.Conf.HttpConfig.AllowedOrigins, "allowedOrigins", "", []string{}, "Allowed Origins")

	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(kubauthv1alpha1.AddToScheme(scheme))
}

var Cmd = &cobra.Command{
	Use:   "userdb",
	Short: "User DB server",
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

		logger.Info("Starting User DB Server", slog.String("logLevel", flags.logConfig.Level), slog.String("version", global.Version), slog.String("build", global.BuildTs))
		if flags.displayFlags {
			sb := new(strings.Builder)
			cmd.PersistentFlags().VisitAll(func(f *pflag.Flag) {
				_, _ = fmt.Fprintf(sb, "--%s=%q\n", f.Name, f.Value)
			})
			fmt.Printf("Flags:\n%s", sb.String())
		}
		if flags.usersNamespace == "" {
			setupLog.Error(nil, "usersNamespace must be specified and non null")
			os.Exit(1)
		}

		if flags.HttpConfig.BindAddr != "127.0.0.1" && flags.HttpConfig.BindAddr != "localhost" {
			fmt.Printf("**** WARNING ****: This enpoint is not protected and externaly accessible. It should be accessible only from side containers")
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
					flags.usersNamespace: {},
				},
			},
		})
		if err != nil {
			setupLog.Error(err, "unable to start manager")
			os.Exit(1)
		}

		if flags.enableWebhook {
			if err := v1alpha1.SetupUserWebhookWithManager(mgr); err != nil {
				setupLog.Error(err, "unable to create webhook", "webhook", "User")
				os.Exit(1)
			}
			if err := v1alpha1.SetupGroupWebhookWithManager(mgr); err != nil {
				setupLog.Error(err, "unable to create webhook", "webhook", "Group")
				os.Exit(1)
			}
			if err := v1alpha1.SetupGroupBindingWebhookWithManager(mgr); err != nil {
				setupLog.Error(err, "unable to create webhook", "webhook", "GroupBinding")
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

		// ---------------------- Setup our user identity server
		router := http.NewServeMux()
		router.Handle("/v1/identity", handlers.IdentityHandler(mgr.GetClient(), flags.usersNamespace))
		server := httpsrv.New("userIdSrv", &flags.HttpConfig, router)
		err = mgr.Add(server)
		if err != nil {
			setupLog.Error(err, "unable to add oidc server to the manager")
			os.Exit(1)
		}

		//------------------------------------- Index groupBindings by user
		err = mgr.GetFieldIndexer().IndexField(context.TODO(), &kubauthv1alpha1.GroupBinding{}, "userkey", func(rawObj client.Object) []string {
			ugb := rawObj.(*kubauthv1alpha1.GroupBinding)
			return []string{ugb.Spec.User}
		})
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
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
