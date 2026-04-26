/*
Copyright (c) 2025 Kubotal.

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

package httpclient

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"kubauth/internal/misc"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

type HttpAuth struct {
	Login    string `yaml:"login"`
	Password string `yaml:"password"`
	Token    string `yaml:"token"`
}

type Config struct {
	BaseURL            string    `yaml:"baseURL"`
	RootCaPaths        []string  `yaml:"rootCaPaths"`
	RootCaDatas        []string  `yaml:"rootCaDatas"`
	RootCaBytes        [][]byte  `yaml:"-"` // Raw PEM bundles (preferred; avoids base64 round-trips)
	InsecureSkipVerify bool      `yaml:"insecureSkipVerify"`
	DumpExchanges      bool      `yaml:"dumpExchanges"`
	HttpAuth           *HttpAuth `yaml:"httpAuth"`
	// Label is used only for diagnostic logs (identifying which CA bundle was loaded).
	Label string `yaml:"-"`
}

/*
	After calling HttpClient.Do() add the following:
	if resp != nil {
		defer func() { _ = resp.Body.Close() }()
	}
	https://medium.easyread.co/avoiding-memory-leak-in-golang-api-1843ef45fca8
*/

type HttpClient interface {
	Do(method string, path string, contentType string, body io.Reader) (*http.Response, error)
	GetBaseHttpDotClient() *http.Client
}

type httpClient struct {
	Config
	httpClient *http.Client
}

var _ HttpClient = &httpClient{}

func New(conf *Config) (HttpClient, error) {
	// Just a test for validity. Not used in this function
	u, err := url.Parse(conf.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("unable to parse url '%s': %w", conf.BaseURL, err)
	}
	if strings.ToLower(u.Scheme) != "https" && strings.ToLower(u.Scheme) != "http" {
		return nil, fmt.Errorf("invalid url scheme '%s'", conf.BaseURL)
	}
	var tlsConfig *tls.Config = nil
	if strings.ToLower(u.Scheme) == "https" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
		tlsConfig = &tls.Config{RootCAs: pool, InsecureSkipVerify: conf.InsecureSkipVerify}
		if !conf.InsecureSkipVerify {
			var loadedSubjects []string
			for _, rootCaPath := range conf.RootCaPaths {
				if rootCaPath != "" {
					subjects, err := appendCaFromFile(tlsConfig.RootCAs, rootCaPath)
					if err != nil {
						return nil, err
					}
					loadedSubjects = append(loadedSubjects, subjects...)
				}
			}
			for _, rootCaData := range conf.RootCaDatas {
				if rootCaData != "" {
					subjects, err := appendCaFromBase64(tlsConfig.RootCAs, rootCaData)
					if err != nil {
						return nil, err
					}
					loadedSubjects = append(loadedSubjects, subjects...)
				}
			}
			for _, rootCaPEM := range conf.RootCaBytes {
				if len(rootCaPEM) > 0 {
					subjects, err := appendCaFromPEM(tlsConfig.RootCAs, rootCaPEM)
					if err != nil {
						return nil, err
					}
					loadedSubjects = append(loadedSubjects, subjects...)
				}
			}
			if len(loadedSubjects) > 0 {
				slog.Default().Info("httpclient: loaded custom CA certificate(s)",
					"label", conf.Label,
					"baseURL", conf.BaseURL,
					"count", len(loadedSubjects),
					"subjects", loadedSubjects)
			} else if conf.Label != "" {
				slog.Default().Info("httpclient: no custom CA configured; relying on system trust store",
					"label", conf.Label,
					"baseURL", conf.BaseURL)
			}
		}
	}
	httpclient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
			Proxy:           http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
	if conf.DumpExchanges {
		httpclient.Transport = debugTransport{httpclient.Transport}
	}
	return &httpClient{
		Config:     *conf,
		httpClient: httpclient,
	}, nil
}

func (c *httpClient) GetBaseHttpDotClient() *http.Client {
	return c.httpClient
}

func appendCaFromFile(pool *x509.CertPool, caPath string) ([]string, error) {
	rootCaBytes, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA file '%s': %w", caPath, err)
	}
	subjects, err := appendCaFromPEM(pool, rootCaBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid root CA certificate in file %s: %w", caPath, err)
	}
	return subjects, nil
}

func appendCaFromBase64(pool *x509.CertPool, b64 string) ([]string, error) {
	// StdEncoding.Decode writes n bytes; the destination may be larger than n when
	// the input is padded, so we must use data[:n] rather than the full buffer.
	dst := make([]byte, base64.StdEncoding.DecodedLen(len(b64)))
	n, err := base64.StdEncoding.Decode(dst, []byte(b64))
	if err != nil {
		return nil, fmt.Errorf("error while parsing base64 root ca data %s : %w", misc.ShortenString(b64), err)
	}
	subjects, err := appendCaFromPEM(pool, dst[:n])
	if err != nil {
		return nil, fmt.Errorf("invalid root CA certificate in %s: %w", misc.ShortenString(b64), err)
	}
	return subjects, nil
}

// appendCaFromPEM parses a PEM bundle and adds all CERTIFICATE blocks to the pool.
// Returns the list of parsed certificate subjects (for diagnostic logging) so that
// operators can confirm at runtime which CAs have been trusted.
func appendCaFromPEM(pool *x509.CertPool, pemBytes []byte) ([]string, error) {
	if len(pemBytes) == 0 {
		return nil, fmt.Errorf("empty PEM bundle")
	}
	var subjects []string
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return subjects, fmt.Errorf("parse certificate: %w", err)
		}
		pool.AddCert(cert)
		subjects = append(subjects, cert.Subject.String())
	}
	if len(subjects) == 0 {
		return nil, fmt.Errorf("no CERTIFICATE block found in PEM data")
	}
	return subjects, nil
}

type debugTransport struct {
	t http.RoundTripper
}

var exchangeCount = 0

func (d debugTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	reqDump, err := httputil.DumpRequest(req, true)
	if err != nil {
		return nil, err
	}
	fmt.Printf("-----------------> REQUEST (%d)\n%s\n----------------->\n", exchangeCount, string(reqDump))
	exchangeCount++
	//log.Printf("%s", reqDump)

	resp, err := d.t.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	respDump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		resp.Body.Close()
		return nil, err
	}
	fmt.Printf("<----------------- RESPONSE (%d)\n%s\n<-----------------\n", exchangeCount, string(respDump))
	exchangeCount++
	//log.Printf("%s", respDump)
	return resp, nil
}

// ------------------------------------------------------------------------

type UnauthorizedError struct{}

func (e *UnauthorizedError) Error() string {
	return "Unauthorized"
}

type NotFoundError struct {
	url string
}

func (e *NotFoundError) Error() string {
	return fmt.Sprintf("Resource '%s' not found", e.url)
}

func (c *httpClient) Do(method string, path string, contentType string, body io.Reader) (*http.Response, error) {
	u, err := url.JoinPath(c.BaseURL, path)
	if err != nil {
		return nil, fmt.Errorf("unable to join %s to %s: %w", path, c.BaseURL, err)
	}
	req, err := http.NewRequest(method, u, body)
	if err != nil {
		return nil, fmt.Errorf("unable to build request '%s:%s': %w", method, u, err)
	}

	req.Header.Set("Content-Type", contentType)
	if c.Config.HttpAuth != nil {
		auth := c.Config.HttpAuth
		if auth.Login != "" {
			req.SetBasicAuth(auth.Login, auth.Password)
		}
		if auth.Token != "" {
			req.Header.Set("Authorization", "Bearer "+auth.Token)
		}
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error on http connection on request '%s:%s': %w", method, u, err)
	}
	if resp.StatusCode == 401 {
		// This is not a system error, but a user's one. So this special handling
		return nil, &UnauthorizedError{}
	}
	if resp.StatusCode == 404 {
		// Some caller may need to handle this specifically
		return nil, &NotFoundError{
			url: u,
		}
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("invalid status code: %d (%s) on request '%s:%s'", resp.StatusCode, resp.Status, method, u)
	}
	return resp, nil
}
