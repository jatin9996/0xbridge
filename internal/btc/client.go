package btc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

)

type BitcoinClient struct {
	RPCUser string
	RPCPass string
	Host    string
}

func (c *BitcoinClient) Call(method string, params []any) (json.RawMessage, error) {
	body := map[string]any{
		"jsonrpc": "1.0",
		"id":      "0xbridge",
		"method":  method,
		"params":  params,
	}
	data, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", c.Host, bytes.NewReader(data))
	req.SetBasicAuth(c.RPCUser, c.RPCPass)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Result json.RawMessage `json:\"result\"`
		Error  any             `json:\"error\"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	if result.Error != nil {
		return nil, fmt.Errorf(\"RPC error: %v\", result.Error)
	}
	return result.Result, nil
}
