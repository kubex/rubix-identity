package identity

import "net/http"

type Request struct {
	RequestUri string
	RemoteIP   string
	Header     http.Header
	Cookies    []*http.Cookie
}

func (r Request) CookieValue(name string) string {
	cookie := r.Cookie(name)
	if cookie == nil {
		return ""
	}
	return cookie.Value
}

func (r Request) Cookie(name string) *http.Cookie {
	for _, cookie := range r.Cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}
