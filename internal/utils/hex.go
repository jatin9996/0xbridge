package utils

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
)

// EncodeHex encodes bytes to hex string
func EncodeHex(data []byte) string {
	return hex.EncodeToString(data)
}

// DecodeHex decodes hex string to bytes
func DecodeHex(hexStr string) ([]byte, error) {
	return hex.DecodeString(hexStr)
}

// DecodeJSONBody decodes JSON request body
func DecodeJSONBody(w http.ResponseWriter, r *http.Request, dst interface{}) error {
	if r.Header.Get("Content-Type") != "application/json" {
		return fmt.Errorf("content-type is not application/json")
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1048576)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(&dst)
	if err != nil {
		return err
	}

	return nil
}
