package proto

import (
	"encoding/json"
	"fmt"
	"io"
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
