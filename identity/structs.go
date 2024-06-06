package identity

import (
	"context"
	"time"
)

type User struct {
	IdentityID string
	Username   string
	Name       string
	Email      string
	State      string
	MFA        bool
	Verified   bool
}

type Session struct {
	SessionID       string
	RemoteIP        string
	User            *User
	MFA             bool
	VerifiedAccount bool
	Issued          time.Time
	Expiry          time.Time
	LastConfirmed   time.Time // Last password/mfa check
	Scopes          []string
	Audience        []string
	Issuer          string
	IsLoggedIn      bool
	ForRequest      *Request        `json:"-"`
	ProviderContext context.Context `json:"-"` // Context for the session provider to use
}

func (s *Session) ID() string {
	if s == nil {
		return ""
	}
	return s.SessionID
}

func (s *Session) UserID() string {
	if s == nil || s.User == nil {
		return ""
	}
	return s.User.IdentityID
}

func NewSession(ctx *Request) *Session {
	return &Session{
		RemoteIP:   ctx.RemoteIP,
		ForRequest: ctx,
	}
}
