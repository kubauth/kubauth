package misc

import "fmt"

func SafeBoolPtr(p *bool) bool {
	if p == nil {
		return false
	}
	return *p
}

func ShortenString(str string) string {
	if len(str) <= 30 {
		return str
	} else {
		return fmt.Sprintf("%s.......%s", str[:10], str[len(str)-10:])
	}
}
