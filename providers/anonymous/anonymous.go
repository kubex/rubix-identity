package anonymous

import (
	"time"

	"github.com/kubex/rubix-identity/identity"
	"github.com/valyala/fasthttp"
)

type Provider struct {
}

func (p Provider) IsLoggedIn(ctx *fasthttp.RequestCtx) bool    { return true }
func (p Provider) LoginUrl(ctx *fasthttp.RequestCtx) string    { return "" }
func (p Provider) LogoutUrl(ctx *fasthttp.RequestCtx) string   { return "" }
func (p Provider) RegisterURL(ctx *fasthttp.RequestCtx) string { return "" }

func (p Provider) GetSession(ctx *fasthttp.RequestCtx) (*identity.Session, error) {
	return &identity.Session{
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
