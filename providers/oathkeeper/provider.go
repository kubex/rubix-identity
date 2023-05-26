package oathkeeper

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/golang-jwt/jwt/v5"
	"github.com/kubex/rubix-identity/identity"
	ory "github.com/ory/client-go"
	"github.com/valyala/fasthttp"
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

func (p Provider) getToken(ctx *fasthttp.RequestCtx) *jwt.Token {
	jwtString := ""

	if p.config.CookieName != "" {
		jwtString = string(ctx.Request.Header.Cookie(p.config.CookieName))
	} else if p.config.HeaderName != "" {
		jwtString = string(ctx.Request.Header.Peek(p.config.HeaderName))
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
	return []byte(p.config.VerifySecret), nil
}

func (p Provider) IsLoggedIn(session *identity.Session) bool      { return session.IsLoggedIn }
func (p Provider) HydrateSession(session *identity.Session) error { return nil }

func (p Provider) CreateSession(ctx *fasthttp.RequestCtx) (*identity.Session, error) {

	rCtx := context.Background()
	iSession := identity.NewSession(ctx)
	iSession.ProviderContext = rCtx

	token := p.getToken(ctx)
	if token == nil {
		iSession.IsLoggedIn = false
		return iSession, nil
	}

	iSession.IsLoggedIn = token.Valid

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
	rawJwt, _ := base64.StdEncoding.DecodeString(rawSplit[1])

	session := oryJwt{}
	json.Unmarshal(rawJwt, &session)
	if session.Iss != iSession.Issuer || session.Session == nil {
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

	return iSession, nil
}

func (p Provider) CacheID(ctx *fasthttp.RequestCtx) string { return "" } // No need to cache the JWT

func (p Provider) returnDest(ctx *fasthttp.RequestCtx) string {
	return ctx.URI().String()
}

func (p Provider) LoginUrl(ctx *fasthttp.RequestCtx) string {
	return p.config.LoginUrl + "?return_to=" + p.returnDest(ctx)
}

func (p Provider) LogoutUrl(ctx *fasthttp.RequestCtx) string { return p.config.LogoutUrl }

func (p Provider) RegisterURL(ctx *fasthttp.RequestCtx) string {
	return p.config.SignupUrl + "?return_to=" + p.returnDest(ctx)
}
