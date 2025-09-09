package proto

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"kubauth/internal/httpclient"
)

type RequestPayload interface {
	fmt.Stringer // For debug & error message
	ToJson() ([]byte, error)
	FromJson(r io.Reader) error
}

type ResponsePayload interface {
	FromJson(r io.Reader) error
}

// -----------------------------------------------------

func toJson(payload interface{}) ([]byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return []byte{}, err
	}
	return body, nil
}

func fromJson(r io.Reader, payload interface{}) error {
	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields()
	return decoder.Decode(payload)
}

func Exchange(c httpclient.HttpClient, method string, path string, request RequestPayload, response ResponsePayload) error {
	body, err := request.ToJson()
	if err != nil {
		return fmt.Errorf("unable to marshal request '%s': %w", request, err)
	}
	resp, err := c.Do(method, path, "application/json", bytes.NewReader(body))
	if resp != nil {
		// https://medium.easyread.co/avoiding-memory-leak-in-golang-api-1843ef45fca8
		defer func() { _ = resp.Body.Close() }()
	}
	if err != nil {
		return err
	}
	err = response.FromJson(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to unmarshal response: %w", err)
	}
	return nil
}
