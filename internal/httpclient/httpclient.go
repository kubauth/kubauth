package httpclient

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"kubauth/cmd/kubauth/proto"
	"kubauth/internal/misc"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type HttpAuth struct {
	Login    string
	Password string
	Token    string
}

type Config struct {
	BaseURL            string
	RootCaPaths        []string
	RootCaDatas        []string
	InsecureSkipVerify bool
	HttpAuth           *HttpAuth
}

type HttpClient interface {
	Do(method string, path string, request proto.RequestPayload, response proto.ResponsePayload) error
}

var _ HttpClient = &httpClient{}

type httpClient struct {
	Config
	httpClient *http.Client
}

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
	return &httpClient{
		Config:     *conf,
		httpClient: httpclient,
	}, nil
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

func (c *httpClient) Do(method string, path string, request proto.RequestPayload, response proto.ResponsePayload) error {
	body, err := request.ToJson()
	if err != nil {
		return fmt.Errorf("unable to marshal request '%s': %w", request, err)
	}
	u, err := url.JoinPath(c.BaseURL, path)
	if err != nil {
		return fmt.Errorf("unable to join %s to %s: %w", path, c.BaseURL, err)
	}
	req, err := http.NewRequest(method, u, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("unable to build request '%s': %w", request, err)
	}
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
	if resp != nil {
		// https://medium.easyread.co/avoiding-memory-leak-in-golang-api-1843ef45fca8
		defer func() { _ = resp.Body.Close() }()
	}
	if err != nil {
		return fmt.Errorf("error on http connection on request '%s': %w", request, err)
	}
	if resp.StatusCode == 401 {
		// This is not a system error, but a user's one. So this special handling
		return &UnauthorizedError{}
	}
	if resp.StatusCode == 404 {
		// Some caller may need to handle this specifically
		return &NotFoundError{
			url: u,
		}
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("invalid status code: %d (%s) on request '%s'", resp.StatusCode, resp.Status, request)
	}
	err = response.FromJson(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to unmarshal response: %w", err)
	}
	return nil
}
