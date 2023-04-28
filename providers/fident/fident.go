package fident

import (
	"crypto/rsa"
	"errors"
	"strings"

	gofidentweb "github.com/fident/go-web"
	"github.com/kubex/rubix-identity/identity"
	"github.com/valyala/fasthttp"
)

type Provider struct {
	allowInsecure bool
	aesKey        string
	rsaPublicKey  *rsa.PublicKey
	loginUrl      string
	logoutUrl     string
	registerURL   string
	serviceUrl    string
	forceHttps    bool
	tokenHelper   gofidentweb.TokenHelper
}

func (p Provider) getCookie(ctx *fasthttp.RequestCtx) string {
	cookieValue := ctx.Request.Header.Cookie(gofidentweb.TokenName)
	if len(cookieValue) == 0 && p.allowInsecure {
		cookieValue = ctx.Request.Header.Cookie(gofidentweb.TokenNameNonSecure)
	}
	return string(cookieValue)
}

func (p Provider) returnDest(ctx *fasthttp.RequestCtx) string {
	if p.forceHttps {
		return strings.Replace(ctx.URI().String(), "http:", "https:", 1)
	}
	return ctx.URI().String()
}

func (p Provider) LoginUrl(ctx *fasthttp.RequestCtx) string {
	return p.loginUrl + "?destination=" + p.returnDest(ctx)
}

func (p Provider) LogoutUrl(ctx *fasthttp.RequestCtx) string { return p.logoutUrl }

func (p Provider) RegisterURL(ctx *fasthttp.RequestCtx) string {
	return p.registerURL + "?destination=" + p.returnDest(ctx)
}

func (p Provider) IsLoggedIn(session *identity.Session) bool { return session.IsLoggedIn }

func (p Provider) CreateSession(ctx *fasthttp.RequestCtx) (*identity.Session, error) {
	_, err := p.tokenHelper.VerifyToken(p.getCookie(ctx))

	session := &identity.Session{
		IsLoggedIn:     err == nil,
		Scopes:         nil,
		Audience:       nil,
		RequestContext: ctx,
	}

	return session, nil
}

func (p Provider) HydrateSession(session *identity.Session) error {

	if session.RequestContext == nil {
		return errors.New("request context is not available")
	}

	u, err := p.tokenHelper.VerifyToken(p.getCookie(session.RequestContext))
	if err != nil {
		return err
	}

	usr := identity.User{
		IdentityID: u.IdentityID,
		Username:   u.Username,
		Name:       u.GetFirstName() + " " + u.GetLastName(),
	}

	session.SessionID = u.GetSubject()
	session.User = &usr
	session.MFA = u.MFA
	session.VerifiedAccount = u.Verified
	session.Issued = u.GetIssuedAt()
	session.Expiry = u.GetExpiry()
	session.LastConfirmed = u.GetIssuedAt()
	session.Scopes = nil
	session.Audience = nil
	session.Issuer = u.GetIssuer()

	return nil
}

func (p Provider) GetSession(ctx *fasthttp.RequestCtx) (*identity.Session, error) {
	u, err := p.tokenHelper.VerifyToken(p.getCookie(ctx))
	if err != nil {
		return nil, err
	}
	usr := identity.User{
		IdentityID: u.IdentityID,
		Username:   u.Username,
		Name:       u.GetFirstName() + " " + u.GetLastName(),
	}

	return &identity.Session{
		SessionID:       u.GetSubject(),
		User:            &usr,
		MFA:             u.MFA,
		VerifiedAccount: u.Verified,
		Issued:          u.GetIssuedAt(),
		Expiry:          u.GetExpiry(),
		LastConfirmed:   u.GetIssuedAt(),
		Scopes:          nil,
		Audience:        nil,
		Issuer:          u.GetIssuer(),
	}, nil
}
