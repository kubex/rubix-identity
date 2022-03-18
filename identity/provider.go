package identity

import (
	"github.com/valyala/fasthttp"
)

type Provider interface {
	IsLoggedIn(ctx *fasthttp.RequestCtx) bool
	GetSession(ctx *fasthttp.RequestCtx) (*Session, error)
	LoginUrl(ctx *fasthttp.RequestCtx) string
	LogoutUrl(ctx *fasthttp.RequestCtx) string
	RegisterURL(ctx *fasthttp.RequestCtx) string
}
