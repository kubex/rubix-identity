package identity

import "net/http"

type Request struct {
	RequestUri string
	RemoteIP   string
	Header     http.Header
	Cookies    []*http.Cookie
}

func RequestFromHttp(r *http.Request) *Request {
	return &Request{
		Header:     r.Header,
		RequestUri: r.RequestURI,
		Cookies:    r.Cookies(),
		RemoteIP:   r.RemoteAddr,
	}
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
