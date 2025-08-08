/*
Copyright 2025 Kubotal

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

package hash

import (
	"fmt"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
)

const DefaultBCryptWorkFactor = 12

var Cmd = &cobra.Command{
	Use:   "hash [secret]",
	Short: "Generate a BCrypt hash for OIDC client secret",
	Long: `Generate a BCrypt hash for OIDC client secret that can be used in fosite.Client.Secret.

The hash is generated using the same method as fosite's default BCrypt hasher with work factor 12.

Example:
  kubauth hash my-secret
`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		secret := args[0]

		// Generate BCrypt hash with work factor 12 (same as fosite default)
		hash, err := bcrypt.GenerateFromPassword([]byte(secret), DefaultBCryptWorkFactor)
		if err != nil {
			fmt.Printf("Error generating hash: %v\n", err)
			return
		}

		fmt.Printf("Secret: %s\n", secret)
		fmt.Printf("Hash: %s\n", string(hash))
		fmt.Printf("\nUse this hash in your OidcClient secret field.\n")
		fmt.Printf("Example:\n")
		fmt.Printf("  Secret: []byte(\"%s\"),\n", string(hash))
	},
}
