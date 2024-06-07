package oathkeeper

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/kubex/rubix-identity/identity"
	ory "github.com/ory/kratos-client-go"
	"strings"
	"time"
)

type Provider struct {
	config Config
}

func New(cfg Config) (*Provider, error) {
	p := &Provider{
		config: cfg,
	}

	return p, nil
}

func (p Provider) getToken(ctx *identity.Request) *jwt.Token {
	jwtString := ""

	if p.config.CookieName != "" {
		jwtString = ctx.CookieValue(p.config.CookieName)
	} else if p.config.HeaderName != "" {
		jwtString = ctx.Header.Get(p.config.HeaderName)
	}

	if len(jwtString) > 10 && jwtString[:7] == "Bearer " {
		jwtString = strings.TrimSpace(jwtString[7:])
	}

	if jwtString != "" {
		token, _ := jwt.Parse(jwtString, p.verifyToken)
		return token
	}
	return nil
}

func (p Provider) verifyToken(token *jwt.Token) (interface{}, error) {

	if p.config.VerifySecret != "" {
		return []byte(p.config.VerifySecret), nil
	}

	if p.config.JwksUrl != "" {
		if jwks, err := keyfunc.Get(p.config.JwksUrl, keyfunc.Options{}); err == nil {
			return jwks.Keyfunc, nil
		} else {
			return nil, err
		}
	}

	if p.config.Jwks != nil {
		if jwks, err := keyfunc.NewJSON(p.config.Jwks); err == nil {
			return jwks.Keyfunc, nil
		} else {
			return nil, err
		}
	}

	return nil, nil
}

func (p Provider) IsLoggedIn(session *identity.Session) bool      { return session.IsLoggedIn }
func (p Provider) HydrateSession(session *identity.Session) error { return nil }
func (p Provider) ListUsers(ctx context.Context, ids ...string) ([]*identity.User, error) {
	return nil, nil
}

func (p Provider) CreateSession(ctx *identity.Request) (*identity.Session, error) {

	rCtx := context.Background()
	iSession := identity.NewSession(ctx)
	iSession.ProviderContext = rCtx

	token := p.getToken(ctx)
	if token == nil {
		iSession.IsLoggedIn = false
		return iSession, nil
	}

	iSession.IsLoggedIn = token.Valid
	if !token.Valid {
		if p.config.VerifySecret == "" && p.config.JwksUrl == "" && p.config.Jwks == nil {
			iSession.IsLoggedIn = true
		}
	}

	claims := token.Claims

	if notBefore, err := claims.GetNotBefore(); err == nil && notBefore != nil {
		if notBefore.After(time.Now()) {
			iSession.IsLoggedIn = false
			return iSession, nil
		}
	}

	iSession.Issuer, _ = claims.GetIssuer()

	if isuAt, err := claims.GetIssuedAt(); err == nil && isuAt != nil {
		iSession.Issued = isuAt.Time
	}

	if expAt, err := claims.GetExpirationTime(); err == nil && expAt != nil {
		iSession.Expiry = expAt.Time
	}

	rawSplit := strings.Split(token.Raw+"...", ".")
	rawJwt, _ := base64.RawURLEncoding.DecodeString(rawSplit[1])

	session := oryJwt{}
	_ = json.Unmarshal(rawJwt, &session)
	if session.Iss != iSession.Issuer || session.Session == nil {
		iSession.IsLoggedIn = false
		return iSession, nil
	}

	iSession.User = &identity.User{}
	iSession.SessionID = session.Session.Id
	if session.Session.AuthenticatedAt != nil {
		iSession.LastConfirmed = *session.Session.AuthenticatedAt
	}

	iSession.User.IdentityID = session.Sub

	iSession.MFA = *session.Session.AuthenticatorAssuranceLevel != ory.AUTHENTICATORASSURANCELEVEL_AAL0 &&
		*session.Session.AuthenticatorAssuranceLevel != ory.AUTHENTICATORASSURANCELEVEL_AAL1 &&
		*session.Session.AuthenticatorAssuranceLevel != ""

	for _, addr := range session.Session.Identity.VerifiableAddresses {
		if addr.Verified {
			iSession.VerifiedAccount = addr.Verified
		}
	}

	if traitBytes, err := json.Marshal(session.Session.Identity.Traits); err == nil {
		iTrait := identityTrait{}
		if err := json.Unmarshal(traitBytes, &iTrait); err == nil {
			iSession.User.Username = iTrait.Email
			iSession.User.Name = iTrait.Name.First + " " + iTrait.Name.Last
		}
	}

	return iSession, nil
}

func (p Provider) CacheID(ctx *identity.Request) string { return "" } // No need to cache the JWT

func (p Provider) LoginUrl(ctx *identity.Request) string {
	return p.config.LoginUrl + "?return_to=" + ctx.RequestUri
}

func (p Provider) LogoutUrl(ctx *identity.Request) string { return p.config.LogoutUrl }

func (p Provider) RegisterURL(ctx *identity.Request) string {
	return p.config.SignupUrl + "?return_to=" + ctx.RequestUri
}
