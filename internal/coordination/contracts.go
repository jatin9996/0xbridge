package coordination

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Claim represents a claim for 0xBTC minting
type Claim struct {
	ID                 string     `json:"id"`
	UserAddress        string     `json:"user_address"`
	ClaimAddress       string     `json:"claim_address"`
	DestinationChainID byte       `json:"destination_chain_id"`
	Amount             int64      `json:"amount"`
	Status             string     `json:"status"`
	CreatedAt          time.Time  `json:"created_at"`
	ProcessedAt        *time.Time `json:"processed_at,omitempty"`
	TransactionHash    string     `json:"transaction_hash,omitempty"`
}

// CoordinationContract manages cross-chain coordination
type CoordinationContract struct {
	Claims          map[string]*Claim
	mu              sync.RWMutex
	ChainID         byte
	ContractAddress string
}

// NewCoordinationContract creates a new coordination contract
func NewCoordinationContract(chainID byte, contractAddress string) *CoordinationContract {
	return &CoordinationContract{
		Claims:          make(map[string]*Claim),
		ChainID:         chainID,
		ContractAddress: contractAddress,
	}
}

// AddClaim adds a new claim to the coordination contract
func (cc *CoordinationContract) AddClaim(claim *Claim) error {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	if claim.ID == "" {
		claim.ID = generateClaimID(claim)
	}

	if claim.CreatedAt.IsZero() {
		claim.CreatedAt = time.Now()
	}

	claim.Status = "pending"
	cc.Claims[claim.ID] = claim

	return nil
}

// GetClaim retrieves a claim by ID
func (cc *CoordinationContract) GetClaim(claimID string) (*Claim, error) {
	cc.mu.RLock()
	defer cc.mu.RUnlock()

	claim, exists := cc.Claims[claimID]
	if !exists {
		return nil, fmt.Errorf("claim not found: %s", claimID)
	}

	return claim, nil
}

// ProcessClaim processes a claim and marks it as completed
func (cc *CoordinationContract) ProcessClaim(claimID string, txHash string) error {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	claim, exists := cc.Claims[claimID]
	if !exists {
		return fmt.Errorf("claim not found: %s", claimID)
	}

	if claim.Status != "pending" {
		return fmt.Errorf("claim is not in pending status: %s", claim.Status)
	}

	now := time.Now()
	claim.Status = "completed"
	claim.ProcessedAt = &now
	claim.TransactionHash = txHash

	return nil
}

// GetPendingClaims returns all pending claims
func (cc *CoordinationContract) GetPendingClaims() []*Claim {
	cc.mu.RLock()
	defer cc.mu.RUnlock()

	var pendingClaims []*Claim
	for _, claim := range cc.Claims {
		if claim.Status == "pending" {
			pendingClaims = append(pendingClaims, claim)
		}
	}

	return pendingClaims
}

// ValidateClaim validates a claim for processing
func (cc *CoordinationContract) ValidateClaim(claim *Claim) error {
	if claim.UserAddress == "" {
		return fmt.Errorf("user address is required")
	}

	if claim.ClaimAddress == "" {
		return fmt.Errorf("claim address is required")
	}

	if claim.Amount <= 0 {
		return fmt.Errorf("amount must be greater than 0")
	}

	if claim.DestinationChainID == 0 {
		return fmt.Errorf("destination chain ID is required")
	}

	return nil
}

// generateClaimID generates a unique claim ID
func generateClaimID(claim *Claim) string {
	data := fmt.Sprintf("%s:%s:%d:%d",
		claim.UserAddress,
		claim.ClaimAddress,
		claim.Amount,
		claim.DestinationChainID)

	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8])
}

// GetContractInfo returns information about the coordination contract
func (cc *CoordinationContract) GetContractInfo() map[string]interface{} {
	cc.mu.RLock()
	defer cc.mu.RUnlock()

	pendingCount := 0
	completedCount := 0
	totalAmount := int64(0)

	for _, claim := range cc.Claims {
		if claim.Status == "pending" {
			pendingCount++
		} else if claim.Status == "completed" {
			completedCount++
		}
		totalAmount += claim.Amount
	}

	return map[string]interface{}{
		"chain_id":         cc.ChainID,
		"contract_address": cc.ContractAddress,
		"total_claims":     len(cc.Claims),
		"pending_claims":   pendingCount,
		"completed_claims": completedCount,
		"total_amount":     totalAmount,
	}
}
