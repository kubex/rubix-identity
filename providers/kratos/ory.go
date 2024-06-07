package kratos

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/kubex/rubix-identity/identity"
	ory "github.com/ory/kratos-client-go"
)

type Provider struct {
	config         Config
	oryConfig      *ory.Configuration
	api            *ory.APIClient
	adminOryConfig *ory.Configuration
	adminApi       *ory.APIClient
}

func New(cfg Config) (*Provider, error) {
	p := &Provider{
		config: cfg,
	}

	p.oryConfig = ory.NewConfiguration()
	p.oryConfig.Servers = ory.ServerConfigurations{{URL: cfg.PublicApi}}
	p.api = ory.NewAPIClient(p.oryConfig)

	p.adminOryConfig = ory.NewConfiguration()
	p.adminOryConfig.Servers = ory.ServerConfigurations{{URL: cfg.AdminApi}}
	p.adminApi = ory.NewAPIClient(p.adminOryConfig)

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

		iSession.User = identityToUser(*session.Identity)
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

func (p Provider) ListUsers(ctx context.Context, ids ...string) ([]*identity.User, error) {
	var users []*identity.User
	switch len(ids) {
	case 0:
		return nil, nil
	case 1:
		ident, resp, err := p.adminApi.IdentityAPI.GetIdentity(ctx, ids[0]).Execute()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 200 {
			return nil, errors.New("failed to list identities")
		}
		users = append(users, identityToUser(*ident))
	default:
		identities, resp, err := p.adminApi.IdentityAPI.ListIdentities(ctx).Ids(ids).Execute()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 200 {
			return nil, errors.New("failed to list identities")
		}

		for _, i := range identities {
			users = append(users, identityToUser(i))
		}
	}

	return users, nil
}

func identityToUser(src ory.Identity) *identity.User {
	user := &identity.User{
		IdentityID: src.Id,
		State:      *src.State,
	}

	if traitBytes, err := json.Marshal(src.Traits); err == nil {
		iTrait := identityTrait{}
		if err := json.Unmarshal(traitBytes, &iTrait); err == nil {
			user.Username = iTrait.Email
			user.Email = iTrait.Email
			user.Name = iTrait.Name.First + " " + iTrait.Name.Last
		}
	}
	return user
}
