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

// Package httpsrv host an http server implementation, able to be used inside a kubernetes controller
// - Support Runnable interface with context handling
// - Support TLS with automatique certificate update
// - Log using 	"github.com/go-logr/logr" package
// Note the main router is a parameters, thus letting mux (http.ServerMux, Gorilla, httprouter, chi, flow,...) choice to the caller.
package httpsrv
