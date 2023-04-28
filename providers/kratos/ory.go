package kratos

import (
	"context"
	"encoding/json"
	"github.com/kubex/rubix-identity/identity"
	ory "github.com/ory/client-go"
	"github.com/valyala/fasthttp"
	"log"
)

type Provider struct {
	config    Config
	oryConfig *ory.Configuration
	api       *ory.APIClient
}

func New(cfg Config) (*Provider, error) {
	p := &Provider{
		config: cfg,
	}

	p.oryConfig = ory.NewConfiguration()
	p.oryConfig.Servers = ory.ServerConfigurations{{URL: cfg.PublicApi}}
	p.api = ory.NewAPIClient(p.oryConfig)

	return p, nil
}

func (p Provider) IsLoggedIn(session *identity.Session) bool      { return session.IsLoggedIn }
func (p Provider) HydrateSession(session *identity.Session) error { return nil }
func (p Provider) CreateSession(ctx *fasthttp.RequestCtx) (*identity.Session, error) {
	rCtx := context.Background()

	iSession := &identity.Session{
		ProviderContext: rCtx,
	}

	kratosCookie := ctx.Request.Header.Cookie(p.config.CookieName)
	session, resp, err := p.api.FrontendApi.ToSession(rCtx).Cookie(p.config.CookieName + "=" + string(kratosCookie)).Execute()
	log.Println(resp, err)
	if session != nil {
		iSession.IsLoggedIn = true

		iSession.SessionID = session.Id
		iSession.MFA = *session.AuthenticatorAssuranceLevel != ory.AUTHENTICATORASSURANCELEVEL_AAL0 &&
			*session.AuthenticatorAssuranceLevel != ory.AUTHENTICATORASSURANCELEVEL_AAL1 &&
			*session.AuthenticatorAssuranceLevel != ""
		if session.IssuedAt != nil {
			iSession.Issued = *session.IssuedAt
		}
		if session.ExpiresAt != nil {
			iSession.Expiry = *session.ExpiresAt
		}
		for _, addr := range session.Identity.VerifiableAddresses {
			if addr.Verified {
				iSession.VerifiedAccount = addr.Verified
			}
		}

		iSession.User = &identity.User{
			IdentityID: session.Identity.Id,
		}

		if traitBytes, err := json.Marshal(session.Identity.Traits); err == nil {
			iTrait := identityTrait{}
			if err := json.Unmarshal(traitBytes, &iTrait); err == nil {
				log.Println(iTrait)
				iSession.User.Username = iTrait.Email
				iSession.User.Name = iTrait.Name.First + " " + iTrait.Name.Last
			}
		}
	}

	return iSession, nil
}

func (p Provider) returnDest(ctx *fasthttp.RequestCtx) string {
	return ctx.URI().String()
}

func (p Provider) LoginUrl(ctx *fasthttp.RequestCtx) string {
	return p.config.LoginUrl + "?destination=" + p.returnDest(ctx)
}

func (p Provider) LogoutUrl(ctx *fasthttp.RequestCtx) string { return p.config.LogoutUrl }

func (p Provider) RegisterURL(ctx *fasthttp.RequestCtx) string {
	return p.config.SignupUrl + "?destination=" + p.returnDest(ctx)
}
