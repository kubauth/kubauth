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

package misc

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v2"
)

func LoadConfig(configFile string, conf interface{}) (absConfigFile string, err error) {
	absConfigFile, err = filepath.Abs(configFile)
	if err != nil {
		return "", err
	}
	content, err := os.ReadFile(absConfigFile)
	if err != nil {
		return absConfigFile, err
	}
	content2, err := ExpandEnv(string(content))
	if err != nil {
		return absConfigFile, err
	}
	decoder := yaml.NewDecoder(strings.NewReader(content2))
	decoder.SetStrict(true)
	if err = decoder.Decode(conf); err != nil {
		if err == io.EOF {
			// Empty file is not an error
			return absConfigFile, nil
		}
		return absConfigFile, fmt.Errorf("file '%s': %w", configFile, err)
	}
	return absConfigFile, nil
}
