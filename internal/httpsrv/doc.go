// Package httpsrv host an http server implementation, able to be used inside a kubernetes controller
// - Support Runnable interface with context handling
// - Support TLS with automatique certificate update
// - Log using 	"github.com/go-logr/logr" package
// Note the main router is a parameters, thus letting mux (http.ServerMux, Gorilla, httprouter, chi, flow,...) choice to the caller.
package httpsrv
