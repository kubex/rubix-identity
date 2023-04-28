package anonymous

import (
	"strings"
	"time"

	"github.com/kubex/rubix-identity/identity"
	"github.com/valyala/fasthttp"
)

type Provider struct {
	RequireIP string
}

func (p Provider) LoginUrl(ctx *fasthttp.RequestCtx) string    { return "" }
func (p Provider) LogoutUrl(ctx *fasthttp.RequestCtx) string   { return "" }
func (p Provider) RegisterURL(ctx *fasthttp.RequestCtx) string { return "" }

func (p Provider) IsLoggedIn(session *identity.Session) bool {
	if p.RequireIP == "" {
		return true
	}
	return strings.Contains(p.RequireIP, session.RemoteIP.String())
}

func (p Provider) HydrateSession(session *identity.Session) error { return nil }
func (p Provider) CreateSession(ctx *fasthttp.RequestCtx) (*identity.Session, error) {
	return &identity.Session{
		RemoteIP:        ctx.RemoteIP(),
		SessionID:       "anonymous",
		MFA:             false,
		VerifiedAccount: false,
		Issued:          time.Now(),
		Expiry:          time.Now().Add(time.Minute),
		LastConfirmed:   time.Now(),
		Scopes:          []string{},
		Audience:        []string{},
		Issuer:          "anonymous",
		User: &identity.User{
			IdentityID: "anonymous",
			Username:   "anonymous",
			Name:       "anonymous",
		},
	}, nil
}
