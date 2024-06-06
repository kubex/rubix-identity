package identity

import "context"

type Provider interface {
	IsLoggedIn(*Session) bool      // Quick is logged in check
	HydrateSession(*Session) error // Hydrate session with user data
	CreateSession(ctx *Request) (*Session, error)
	CacheID(ctx *Request) string // Quick cacheable ID to avoid session hydration

	LoginUrl(ctx *Request) string
	LogoutUrl(ctx *Request) string
	RegisterURL(ctx *Request) string

	ListUsers(ctx context.Context, ids ...string) ([]*User, error)
}
