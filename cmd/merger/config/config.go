package config

import "kubauth/internal/httpclient"

type ProviderConfig struct {
	Name                string            `yaml:"name"`
	HttpConfig          httpclient.Config `yaml:"httpConfig"`
	CredentialAuthority *bool             `yaml:"credentialAuthority"` // Is this provider is authority for password checking
	GroupAuthority      *bool             `yaml:"groupAuthority"`      // Groups will be fetched and added. Default true
	GroupPattern        string            `yaml:"groupPattern"`        // Group pattern. Default "%s"
	ClaimAuthority      *bool             `yaml:"claimAuthority"`      // Claims will be merged. Default true
	ClaimPattern        string            `yaml:"claimPattern"`        // Claim pattern. Default "%s". Applied only on first level claims.
	NameAuthority       *bool             `yaml:"nameAuthority"`       // CommonNames will be added. Default true
	EmailAuthority      *bool             `yaml:"emailAuthority"`      // Emails will be added. Default true
	Critical            *bool             `yaml:"critical"`            // If true (default), a failure on this provider will leads 'invalid login'. Even if another provider grants access
	UidOffset           int               `yaml:"uidOffset"`           // Will be added to the returned Uid. Default to 0
}

type Config struct {
	Providers []*ProviderConfig `yaml:"providers"`
}
