package fident

import (
	"crypto/rsa"
	"errors"
	"strings"

	gofidentweb "github.com/fident/go-web"
	"github.com/kubex/rubix-identity/identity"
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

func (p Provider) getCookie(ctx *identity.Request) string {
	cookieValue := ctx.CookieValue(gofidentweb.TokenName)
	if len(cookieValue) == 0 && p.allowInsecure {
		cookieValue = ctx.CookieValue(gofidentweb.TokenNameNonSecure)
	}
	return cookieValue
}

func (p Provider) returnDest(ctx *identity.Request) string {
	if p.forceHttps {
		return strings.Replace(ctx.RequestUri, "http:", "https:", 1)
	}
	return ctx.RequestUri
}

func (p Provider) LoginUrl(ctx *identity.Request) string {
	return p.loginUrl + "?destination=" + p.returnDest(ctx)
}

func (p Provider) LogoutUrl(ctx *identity.Request) string { return p.logoutUrl }

func (p Provider) CacheID(ctx *identity.Request) string { return "" }

func (p Provider) RegisterURL(ctx *identity.Request) string {
	return p.registerURL + "?destination=" + p.returnDest(ctx)
}

func (p Provider) IsLoggedIn(session *identity.Session) bool { return session.IsLoggedIn }

func (p Provider) CreateSession(ctx *identity.Request) (*identity.Session, error) {
	_, err := p.tokenHelper.VerifyToken(p.getCookie(ctx))

	session := identity.NewSession(ctx)
	session.IsLoggedIn = err == nil
	session.Scopes = nil
	session.Audience = nil

	return session, nil
}

func (p Provider) HydrateSession(session *identity.Session) error {

	if session.ForRequest == nil {
		return errors.New("request context is not available")
	}

	u, err := p.tokenHelper.VerifyToken(p.getCookie(session.ForRequest))
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

func (p Provider) GetSession(ctx *identity.Request) (*identity.Session, error) {
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
