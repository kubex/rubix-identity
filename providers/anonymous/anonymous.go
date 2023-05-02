package anonymous

import (
	"log"
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
	return strings.Contains(p.RequireIP, session.RemoteIP)
}

func (p Provider) HydrateSession(session *identity.Session) error { return nil }
func (p Provider) CreateSession(ctx *fasthttp.RequestCtx) (*identity.Session, error) {
	log.Println("Creating anonymous session")
	s := identity.NewSession(ctx)
	s.SessionID = "anonymous"
	s.MFA = false
	s.VerifiedAccount = false
	s.Issued = time.Now()
	s.Expiry = time.Now().Add(time.Minute)
	s.LastConfirmed = time.Now()
	s.Scopes = []string{}
	s.Audience = []string{}
	s.Issuer = "anonymous"
	s.User = &identity.User{
		IdentityID: "anonymous",
		Username:   "anonymous",
		Name:       "anonymous",
	}
	return s, nil
}
