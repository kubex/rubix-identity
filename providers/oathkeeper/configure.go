package oathkeeper

import (
	"encoding/json"
	"strings"
)

const ProviderKey = "oathkeeper"

type Config struct {
	PublicApi    string          `json:"publicApi"`
	LoginUrl     string          `json:"loginUrl"`
	LogoutUrl    string          `json:"logoutUrl"`
	SignupUrl    string          `json:"signupUrl"`
	ForceHttps   bool            `json:"forceHttps"`
	CookieName   string          `json:"cookieName"`
	HeaderName   string          `json:"headerName"`
	VerifySecret string          `json:"verifySecret"`
	JwksUrl      string          `json:"JwksUrl"`
	Jwks         json.RawMessage `json:"Jwks"`
}

func FromJson(data []byte) (*Provider, error) {
	cfg := Config{
		ForceHttps: true,
		HeaderName: "Authorization",
	}
	if err := json.Unmarshal(data, &cfg); err == nil {
		return Create(cfg)
	} else {
		return nil, err
	}
}

func Create(cfg Config) (*Provider, error) {
	cfg.PublicApi = strings.TrimRight(cfg.PublicApi, "/") + "/"
	return New(cfg)
}
