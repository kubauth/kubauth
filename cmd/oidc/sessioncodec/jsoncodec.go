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

package sessioncodec

import (
	"encoding/json"
	"time"
)

// JSONCodec implements scs.Codec and stores session data as a JSON string.
// It encodes both the session deadline and values map in a single JSON object.
type JSONCodec struct{}

type jsonPayload struct {
	Deadline time.Time              `json:"deadline"`
	Values   map[string]interface{} `json:"values"`
}

// Encode serializes the deadline and values to JSON.
func (JSONCodec) Encode(deadline time.Time, values map[string]interface{}) ([]byte, error) {
	payload := jsonPayload{
		Deadline: deadline,
		Values:   values,
	}
	return json.Marshal(payload)
}

// Decode deserializes the JSON into a deadline and values map.
func (JSONCodec) Decode(b []byte) (time.Time, map[string]interface{}, error) {
	if len(b) == 0 {
		return time.Time{}, map[string]interface{}{}, nil
	}
	var payload jsonPayload
	if err := json.Unmarshal(b, &payload); err != nil {
		return time.Time{}, nil, err
	}
	if payload.Values == nil {
		payload.Values = map[string]interface{}{}
	}
	return payload.Deadline, payload.Values, nil
}
