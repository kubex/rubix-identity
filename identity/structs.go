package identity

import (
	"context"
	"github.com/valyala/fasthttp"
	"net"
	"time"
)

type User struct {
	IdentityID string
	Username   string
	Name       string
}

type Session struct {
	SessionID       string
	RemoteIP        net.IP
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
