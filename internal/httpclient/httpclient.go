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
	"fmt"
	"io"
	"kubauth/internal/misc"
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
	InsecureSkipVerify bool      `yaml:"insecureSkipVerify"`
	DumpExchanges      bool      `yaml:"dumpExchanges"`
	HttpAuth           *HttpAuth `yaml:"httpAuth"`
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
			caCount := 0
			for _, rootCaPath := range conf.RootCaPaths {
				if rootCaPath != "" {
					if err := appendCaFromFile(tlsConfig.RootCAs, rootCaPath); err != nil {
						return nil, err
					}
					caCount++
				}
			}
			for _, rootCaData := range conf.RootCaDatas {
				if rootCaData != "" {
					if err := appendCaFromBase64(tlsConfig.RootCAs, rootCaData); err != nil {
						return nil, err
					}
					caCount++
				}
			}
			//if caCount == 0 {
			//	return nil, fmt.Errorf("no root CA certificate was configured")
			//}
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

func appendCaFromFile(pool *x509.CertPool, caPath string) error {
	rootCaBytes, err := os.ReadFile(caPath)
	if err != nil {
		return fmt.Errorf("failed to read CA file '%s': %w", caPath, err)
	}
	if !pool.AppendCertsFromPEM(rootCaBytes) {
		return fmt.Errorf("invalid root CA certificate in file %s", caPath)
	}
	return nil
}

func appendCaFromBase64(pool *x509.CertPool, b64 string) error {
	data := make([]byte, base64.StdEncoding.DecodedLen(len(b64)))
	_, err := base64.StdEncoding.Decode(data, []byte(b64))
	if err != nil {
		return fmt.Errorf("error while parsing base64 root ca data %s : %w", misc.ShortenString(b64), err)
	}
	if !pool.AppendCertsFromPEM(data) {
		return fmt.Errorf("invalid root CA certificate in %s", misc.ShortenString(b64))
	}
	return nil
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
