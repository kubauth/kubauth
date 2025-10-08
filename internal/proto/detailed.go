package proto

type Translated struct {
	Groups []string               `yaml:"groups"`
	Claims map[string]interface{} `yaml:"claims"`
	Uid    int                    `yaml:"uid"`
}

type ProviderSpec struct {
	Name                string `json:"name"`
	CredentialAuthority bool   `json:"credentialAuthority"` // Is this provider Authority for authentication (password) for this user
	GroupAuthority      bool   `json:"groupAuthority"`      // Should we take groups in account
	ClaimAuthority      bool   `json:"claimAuthority"`      // Should we take claims in account
	NameAuthority       bool   `json:"nameAuthority"`
	EmailAuthority      bool   `json:"emailAuthority"`
}

type UserDetail struct {
	User       User         `json:"user"`
	Status     Status       `json:"status"`
	Provider   ProviderSpec `json:"provider"`
	Translated Translated   `json:"translated"`
}
