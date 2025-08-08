package misc

func SafeBoolPtr(p *bool) bool {
	if p == nil {
		return false
	}
	return *p
}
