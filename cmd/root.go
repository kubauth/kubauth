/*
Copyright (c) 2025 Kubotal

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

package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"kubauth/cmd/ldap"
	"kubauth/cmd/oidc"
	userdb "kubauth/cmd/userdb"
	"os"
)

func init() {
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(oidc.Cmd)
	rootCmd.AddCommand(userdb.Cmd)
	rootCmd.AddCommand(ldap.Cmd)

}

var rootCmd = &cobra.Command{
	Use:   "kubauth",
	Short: "K8s authentication management",
}

var debug = true

func Execute() {
	defer func() {
		if !debug {
			if r := recover(); r != nil {
				fmt.Printf("ERROR:%v\n", r)
				os.Exit(1)
			}
		}
	}()
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(2)
	}
}
