package identity

import "time"

type User struct {
	IdentityID string
	Username   string
	Name       string
}

type Session struct {
	SessionID       string
	User            *User
	MFA             bool
	VerifiedAccount bool
	Issued          time.Time
	Expiry          time.Time
	LastConfirmed   time.Time // Last password/mfa check
	Scopes          []string
	Audience        []string
	Issuer          string
}
