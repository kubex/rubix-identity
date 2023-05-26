package oathkeeper

import (
	ory "github.com/ory/client-go"
)

type oryJwt struct {
	Exp     int          `json:"exp"`
	Iat     int          `json:"iat"`
	Iss     string       `json:"iss"`
	Jti     string       `json:"jti"`
	Nbf     int          `json:"nbf"`
	Session *ory.Session `json:"session"`
	Sub     string       `json:"sub"`
}
