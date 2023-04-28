package kratos

import (
	"encoding/json"
	"strings"
)

const ProviderKey = "kratos"

type Config struct {
	PublicApi  string `json:"publicApi"`
	LoginUrl   string `json:"loginUrl"`
	LogoutUrl  string `json:"logoutUrl"`
	SignupUrl  string `json:"signupUrl"`
	ForceHttps bool   `json:"forceHttps"`
	CookieName string `json:"cookieName"`
}

func FromJson(data []byte) (*Provider, error) {
	cfg := Config{
		CookieName: "ory_kratos_session",
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
