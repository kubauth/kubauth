package global

var DefaultPorts = struct {
	Oidc struct {
		Entry       int
		HealthProbe int
		Webhook     int
	}
	Crd struct {
		Entry       int
		HealthProbe int
		Webhook     int
	}
	Ldap struct {
		Entry int
	}
	Merger struct {
		Entry int
	}
}{}

func init() {
	DefaultPorts.Oidc.Entry = 6801
	DefaultPorts.Crd.Entry = 6802
	DefaultPorts.Ldap.Entry = 6803
	DefaultPorts.Merger.Entry = 6804

	DefaultPorts.Oidc.HealthProbe = 8110
	DefaultPorts.Oidc.Webhook = 9443
	DefaultPorts.Crd.HealthProbe = 8111
	DefaultPorts.Crd.Webhook = 9444

}
