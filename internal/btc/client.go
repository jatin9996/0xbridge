package btc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	psbtlib "github.com/btcsuite/btcutil/psbt"
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
		Result json.RawMessage `json:"result"`
		Error  any             `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	if result.Error != nil {
		return nil, fmt.Errorf("RPC error: %v", result.Error)
	}
	return result.Result, nil
}

// BroadcastPSBT broadcasts a signed PSBT to the Bitcoin network
func BroadcastPSBT(packet interface{}) (string, error) {
	// Type assert the packet to PSBT packet
	psbtPacket, ok := packet.(*psbtlib.Packet)
	if !ok {
		return "", fmt.Errorf("invalid packet type, expected *psbtlib.Packet")
	}

	// Check if the PSBT is finalized
	if !psbtPacket.IsComplete() {
		return "", fmt.Errorf("PSBT is not complete and ready for broadcast")
	}

	// Extract the final transaction from the PSBT
	finalTx, err := psbtlib.Extract(psbtPacket)
	if err != nil {
		return "", fmt.Errorf("failed to extract final transaction from PSBT: %v", err)
	}

	// Serialize the transaction to hex
	var txBuf bytes.Buffer
	if err := finalTx.Serialize(&txBuf); err != nil {
		return "", fmt.Errorf("failed to serialize transaction: %v", err)
	}
	txHex := hex.EncodeToString(txBuf.Bytes())

	// Create a Bitcoin client for broadcasting using configuration
	config := NewConfig()
	client := NewBitcoinClient(config)

	// Broadcast the transaction using Bitcoin RPC
	result, err := client.Call("sendrawtransaction", []any{txHex})
	if err != nil {
		return "", fmt.Errorf("failed to broadcast transaction: %v", err)
	}

	// Parse the transaction ID from the result
	var txid string
	if err := json.Unmarshal(result, &txid); err != nil {
		return "", fmt.Errorf("failed to parse transaction ID from response: %v", err)
	}

	return txid, nil
}

// BroadcastPSBTWithClient allows broadcasting with a specific Bitcoin client
func BroadcastPSBTWithClient(client *BitcoinClient, packet interface{}) (string, error) {
	// Type assert the packet to PSBT packet
	psbtPacket, ok := packet.(*psbtlib.Packet)
	if !ok {
		return "", fmt.Errorf("invalid packet type, expected *psbtlib.Packet")
	}

	// Check if the PSBT is finalized
	if !psbtPacket.IsComplete() {
		return "", fmt.Errorf("PSBT is not complete and ready for broadcast")
	}

	// Extract the final transaction from the PSBT
	finalTx, err := psbtlib.Extract(psbtPacket)
	if err != nil {
		return "", fmt.Errorf("failed to extract final transaction from PSBT: %v", err)
	}

	// Serialize the transaction to hex
	var txBuf bytes.Buffer
	if err := finalTx.Serialize(&txBuf); err != nil {
		return "", fmt.Errorf("failed to serialize transaction: %v", err)
	}
	txHex := hex.EncodeToString(txBuf.Bytes())

	// Broadcast the transaction using Bitcoin RPC
	result, err := client.Call("sendrawtransaction", []any{txHex})
	if err != nil {
		return "", fmt.Errorf("failed to broadcast transaction: %v", err)
	}

	// Parse the transaction ID from the result
	var txid string
	if err := json.Unmarshal(result, &txid); err != nil {
		return "", fmt.Errorf("failed to parse transaction ID from response: %v", err)
	}

	return txid, nil
}
