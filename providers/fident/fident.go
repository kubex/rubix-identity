package fident

import (
	"crypto/rsa"
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
	cookieKey     string
	forceHttps    bool
	tokenHelper   gofidentweb.TokenHelper
}

func (p Provider) getCookie(ctx *fasthttp.RequestCtx) string {
	cookieValue := ctx.Request.Header.Cookie(gofidentweb.TokenName)
	if len(cookieValue) == 0 {
		cookieValue = ctx.Request.Header.Cookie(gofidentweb.TokenNameNonSecure)
	}
	return string(cookieValue)
}

func (p Provider) IsLoggedIn(ctx *fasthttp.RequestCtx) bool {
	_, err := p.tokenHelper.VerifyToken(p.getCookie(ctx))
	return err == nil
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
