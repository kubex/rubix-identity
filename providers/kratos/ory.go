package kratos

import (
	"context"
	"encoding/json"
	"github.com/kubex/rubix-identity/identity"
	ory "github.com/ory/client-go"
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
func (p Provider) CacheID(ctx *identity.Request) string {
	return ctx.CookieValue(p.config.CookieName)
}
func (p Provider) CreateSession(ctx *identity.Request) (*identity.Session, error) {

	kratosCookie := p.CacheID(ctx)
	rCtx := context.Background()
	iSession := identity.NewSession(ctx)
	iSession.ProviderContext = rCtx

	session, _, _ := p.api.FrontendAPI.ToSession(rCtx).Cookie(p.config.CookieName + "=" + kratosCookie).Execute()
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
				iSession.User.Username = iTrait.Email
				iSession.User.Name = iTrait.Name.First + " " + iTrait.Name.Last
			}
		}
	}

	return iSession, nil
}

func (p Provider) LoginUrl(ctx *identity.Request) string {
	return p.config.LoginUrl + "?return_to=" + ctx.RequestUri
}

func (p Provider) LogoutUrl(ctx *identity.Request) string { return p.config.LogoutUrl }

func (p Provider) RegisterURL(ctx *identity.Request) string {
	return p.config.SignupUrl + "?return_to=" + ctx.RequestUri
}
