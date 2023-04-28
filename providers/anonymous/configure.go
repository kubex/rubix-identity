package anonymous

import "encoding/json"

const ProviderKey = "anonymous"

func FromJson(data []byte) (*Provider, error) {
	prov := &Provider{}
	if err := json.Unmarshal(data, prov); err == nil {
		return prov, nil
	} else {
		return nil, err
	}
}
