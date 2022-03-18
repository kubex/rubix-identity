package identityproviders

import (
	"encoding/json"
	"errors"

	"github.com/kubex/rubix-identity/identity"
	"github.com/kubex/rubix-identity/providers/anonymous"
	"github.com/kubex/rubix-identity/providers/fident"
)

func Load(jsonBytes []byte) (identity.Provider, error) {

	loader := struct {
		Provider      string
		Configuration *json.RawMessage
	}{}

	err := json.Unmarshal(jsonBytes, &loader)
	if err != nil {
		return nil, err
	}

	switch loader.Provider {
	case fident.ProviderKey:
		return fident.FromJson(*loader.Configuration)
	case anonymous.ProviderKey:
		return anonymous.FromJson(*loader.Configuration)
	}

	return nil, errors.New("unable to load provider '" + loader.Provider + "'")
}
