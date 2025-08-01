package api

import (
	"0xbridge/internal/coordination"
	"0xbridge/internal/utils"
	"encoding/json"
	"fmt"
	"net/http"
)

// CoordinationHandler handles coordination contract API requests
type CoordinationHandler struct {
	Contract *coordination.CoordinationContract
}

// NewCoordinationHandler creates a new coordination handler
func NewCoordinationHandler(contract *coordination.CoordinationContract) *CoordinationHandler {
	return &CoordinationHandler{
		Contract: contract,
	}
}

// AddClaimHandler handles adding a new claim
func (h *CoordinationHandler) AddClaimHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var claim coordination.Claim
	if err := utils.DecodeJSONBody(w, r, &claim); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate the claim
	if err := h.Contract.ValidateClaim(&claim); err != nil {
		http.Error(w, fmt.Sprintf("Invalid claim: %v", err), http.StatusBadRequest)
		return
	}

	// Add the claim
	if err := h.Contract.AddClaim(&claim); err != nil {
		http.Error(w, fmt.Sprintf("Failed to add claim: %v", err), http.StatusInternalServerError)
		return
	}

	// Return the claim with generated ID
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"claim":   claim,
	})
}

// GetClaimHandler handles retrieving a claim by ID
func (h *CoordinationHandler) GetClaimHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract claim ID from URL or query parameter
	claimID := r.URL.Query().Get("id")
	if claimID == "" {
		http.Error(w, "Claim ID is required", http.StatusBadRequest)
		return
	}

	claim, err := h.Contract.GetClaim(claimID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get claim: %v", err), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"claim":   claim,
	})
}

// ProcessClaimHandler handles processing a claim
func (h *CoordinationHandler) ProcessClaimHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		ClaimID string `json:"claim_id"`
		TxHash  string `json:"tx_hash"`
	}

	if err := utils.DecodeJSONBody(w, r, &request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if request.ClaimID == "" {
		http.Error(w, "Claim ID is required", http.StatusBadRequest)
		return
	}

	if request.TxHash == "" {
		http.Error(w, "Transaction hash is required", http.StatusBadRequest)
		return
	}

	// Process the claim
	if err := h.Contract.ProcessClaim(request.ClaimID, request.TxHash); err != nil {
		http.Error(w, fmt.Sprintf("Failed to process claim: %v", err), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Claim processed successfully",
	})
}

// GetPendingClaimsHandler handles retrieving pending claims
func (h *CoordinationHandler) GetPendingClaimsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	claims := h.Contract.GetPendingClaims()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"claims":  claims,
		"count":   len(claims),
	})
}

// GetContractInfoHandler handles retrieving contract information
func (h *CoordinationHandler) GetContractInfoHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	info := h.Contract.GetContractInfo()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"info":    info,
	})
}

// SetupCoordinationRoutes sets up the coordination API routes
func SetupCoordinationRoutes(router *http.ServeMux, contract *coordination.CoordinationContract) {
	handler := NewCoordinationHandler(contract)

	router.HandleFunc("/api/coordination/claim/add", handler.AddClaimHandler)
	router.HandleFunc("/api/coordination/claim/get", handler.GetClaimHandler)
	router.HandleFunc("/api/coordination/claim/process", handler.ProcessClaimHandler)
	router.HandleFunc("/api/coordination/claims/pending", handler.GetPendingClaimsHandler)
	router.HandleFunc("/api/coordination/info", handler.GetContractInfoHandler)
}
