package identityproviders

import (
	"encoding/json"
	"errors"
	"github.com/kubex/rubix-identity/providers/kratos"
	"github.com/kubex/rubix-identity/providers/oathkeeper"

	"github.com/kubex/rubix-identity/identity"
	"github.com/kubex/rubix-identity/providers/anonymous"
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
	case anonymous.ProviderKey:
		return anonymous.FromJson(*loader.Configuration)
	case kratos.ProviderKey:
		return kratos.FromJson(*loader.Configuration)
	case oathkeeper.ProviderKey:
		return oathkeeper.FromJson(*loader.Configuration)
	}

	return nil, errors.New("unable to load provider '" + loader.Provider + "'")
}
