package identity

import (
	"context"
	"github.com/ferluci/fast-realip"
	"github.com/valyala/fasthttp"
	"time"
)

type User struct {
	IdentityID string
	Username   string
	Name       string
}

type Session struct {
	SessionID       string
	RemoteIP        string
	User            *User
	MFA             bool
	VerifiedAccount bool
	Issued          time.Time
	Expiry          time.Time
	LastConfirmed   time.Time // Last password/mfa check
	Scopes          []string
	Audience        []string
	Issuer          string
	IsLoggedIn      bool
	RequestContext  *fasthttp.RequestCtx
	ProviderContext context.Context // Context for the session provider to use
}

func NewSession(ctx *fasthttp.RequestCtx) *Session {
	return &Session{
		RemoteIP:       realip.FromRequest(ctx),
		RequestContext: ctx,
	}
}
