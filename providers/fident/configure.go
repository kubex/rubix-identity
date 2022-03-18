package fident

import (
	"encoding/json"
	"strings"

	gofidentweb "github.com/fident/go-web"
	"github.com/golang-jwt/jwt"
)

const ProviderKey = "fident"

type Config struct {
	RsaPublicKey string `json:"rsaPublicKey"`
	AesKey       string `json:"aesKey"`
	ServiceUrl   string `json:"serviceUrl"`
	ForceHttps   bool   `json:"forceHttps"`
}

func FromJson(data []byte) (*Provider, error) {
	cfg := Config{}
	if err := json.Unmarshal(data, &cfg); err == nil {
		return Create(cfg)
	} else {
		return nil, err
	}
}

func Create(cfg Config) (*Provider, error) {

	rsaPublicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(cfg.RsaPublicKey))
	if err != nil {
		return nil, err
	}

	helper, err := gofidentweb.NewTokenHelper(cfg.AesKey, *rsaPublicKey)
	if err != nil {
		return nil, err
	}

	cfg.ServiceUrl = strings.TrimRight(cfg.ServiceUrl, "/") + "/"

	return &Provider{
		forceHttps:    cfg.ForceHttps,
		allowInsecure: cfg.ForceHttps == false,
		aesKey:        cfg.AesKey,
		rsaPublicKey:  rsaPublicKey,
		loginUrl:      cfg.ServiceUrl + "login",
		logoutUrl:     cfg.ServiceUrl + "logout",
		registerURL:   cfg.ServiceUrl + "register",
		serviceUrl:    cfg.ServiceUrl,
		tokenHelper:   helper,
	}, nil
}
