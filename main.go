// main.go
package main

import (
	"0xbridge/api"
	"0xbridge/internal/avs"
	"0xbridge/internal/btc"
	"0xbridge/internal/coordination"
	"0xbridge/internal/psbt"
	"0xbridge/internal/taproot"
	"0xbridge/internal/utils"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/gorilla/mux"
)

func main() {
	// Initialize coordination contract
	coordinationContract := coordination.NewCoordinationContract(1, "0x1234567890123456789012345678901234567890")

	// Setup router
	r := mux.NewRouter()

	// Setup routes
	r.HandleFunc("/mint", MintHandler).Methods("POST")
	r.HandleFunc("/validate", ValidatePSBTHandler).Methods("POST")
	r.HandleFunc("/avs/status", AVSStatusHandler).Methods("GET")

	// Setup coordination routes
	api.SetupCoordinationRoutes(r, coordinationContract)

	log.Println("0xBridge backend running on :8080")
	http.ListenAndServe(":8080", r)
}

func MintHandler(w http.ResponseWriter, r *http.Request) {
	type MintRequest struct {
		PSBT       string `json:"psbt"`
		UserPubKey string `json:"user_pub_key"`
		AVSPubKey  string `json:"avs_pub_key"`
	}
	var req MintRequest
	if err := utils.DecodeJSONBody(w, r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	psbtBytes, err := base64.StdEncoding.DecodeString(req.PSBT)
	if err != nil {
		http.Error(w, "invalid base64 PSBT", http.StatusBadRequest)
		return
	}

	packet, err := psbt.ParsePSBT(psbtBytes)
	if err != nil {
		http.Error(w, "invalid PSBT structure", http.StatusBadRequest)
		return
	}

	feeValid := psbt.ValidateFeeOutput(packet)
	if !feeValid {
		http.Error(w, "fee output missing or incorrect", http.StatusBadRequest)
		return
	}

	userKeyBytes, err := base64.StdEncoding.DecodeString(req.UserPubKey)
	if err != nil {
		http.Error(w, "invalid user pubkey", http.StatusBadRequest)
		return
	}
	avsKeyBytes, err := base64.StdEncoding.DecodeString(req.AVSPubKey)
	if err != nil {
		http.Error(w, "invalid AVS pubkey", http.StatusBadRequest)
		return
	}

	leaf1, err := taproot.BuildUserAVSPath(userKeyBytes, avsKeyBytes)
	if err != nil {
		http.Error(w, "failed to build leaf1", http.StatusInternalServerError)
		return
	}
	leaf2, err := taproot.BuildBurnVerifyPath(avsKeyBytes)
	if err != nil {
		http.Error(w, "failed to build leaf2", http.StatusInternalServerError)
		return
	}

	internalKey, err := btcec.ParsePubKey(userKeyBytes)
	if err != nil {
		http.Error(w, "invalid internal pubkey", http.StatusBadRequest)
		return
	}

	tapAddr, err := taproot.ComputeTaprootAddress(internalKey, [][]byte{leaf1, leaf2})
	if err != nil {
		http.Error(w, "taproot address generation failed", http.StatusInternalServerError)
		return
	}

	signedPacket, err := avs.SignPSBTWithAVS(packet)
	if err != nil {
		http.Error(w, "AVS signing failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	txHex, err := btc.BroadcastPSBT(signedPacket)
	if err != nil {
		http.Error(w, "broadcast failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Minted! Taproot Address: %s\nBroadcasted TXID: %s", tapAddr.EncodeAddress(), txHex)
}

// ValidatePSBTHandler handles PSBT validation requests
func ValidatePSBTHandler(w http.ResponseWriter, r *http.Request) {
	type ValidateRequest struct {
		PSBT string `json:"psbt"`
	}

	var req ValidateRequest
	if err := utils.DecodeJSONBody(w, r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	psbtBytes, err := base64.StdEncoding.DecodeString(req.PSBT)
	if err != nil {
		http.Error(w, "invalid base64 PSBT", http.StatusBadRequest)
		return
	}

	packet, err := psbt.ParsePSBT(psbtBytes)
	if err != nil {
		http.Error(w, "invalid PSBT structure", http.StatusBadRequest)
		return
	}

	// Validate the PSBT
	validationResult, err := psbt.ValidatePSBT(packet)
	if err != nil {
		http.Error(w, "validation failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Return validation result
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"valid": %t, "errors": %v, "warnings": %v}`,
		validationResult.IsValid, validationResult.Errors, validationResult.Warnings)
}

// AVSStatusHandler handles AVS status requests
func AVSStatusHandler(w http.ResponseWriter, r *http.Request) {
	// Create a mock AVS network for status
	avsNetwork := avs.CreateMockAVSNetwork()

	status := map[string]interface{}{
		"network_status":      "operational",
		"node_count":          len(avsNetwork.Nodes),
		"consensus_threshold": 3,
		"nodes":               make([]map[string]interface{}, 0),
	}

	for nodeID, node := range avsNetwork.Nodes {
		status["nodes"] = append(status["nodes"].([]map[string]interface{}), node.GetNodeInfo())
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status": %v}`, status)
}
