package identity

import (
	"github.com/valyala/fasthttp"
)

type Provider interface {
	IsLoggedIn(*Session) bool      // Quick is logged in check
	HydrateSession(*Session) error // Hydrate session with user data
	CreateSession(ctx *fasthttp.RequestCtx) (*Session, error)

	LoginUrl(ctx *fasthttp.RequestCtx) string
	LogoutUrl(ctx *fasthttp.RequestCtx) string
	RegisterURL(ctx *fasthttp.RequestCtx) string
}
