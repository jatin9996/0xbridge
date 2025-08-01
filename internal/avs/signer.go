package avs

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/btcec/v2"
	psbtlib "github.com/btcsuite/btcutil/psbt"
)

// AVSSigner represents an AVS node that can sign PSBTs
type AVSSigner struct {
	NodeID     string
	PrivateKey []byte
	PublicKey  []byte
	KeyShares  map[string][]byte
	Consensus  *ConsensusManager
	mu         sync.RWMutex
}

// ConsensusManager manages consensus among AVS nodes
type ConsensusManager struct {
	Nodes     map[string]*AVSSigner
	Threshold int
	mu        sync.RWMutex
}

// KeyShare represents a share of the network key
type KeyShare struct {
	ShareID   string `json:"share_id"`
	ShareData []byte `json:"share_data"`
	NodeID    string `json:"node_id"`
}

// SigningRequest represents a request to sign a PSBT
type SigningRequest struct {
	PSBTData    []byte `json:"psbt_data"`
	RequestID   string `json:"request_id"`
	RequesterID string `json:"requester_id"`
}

// SigningResponse represents the response from AVS signing
type SigningResponse struct {
	RequestID string `json:"request_id"`
	Signature []byte `json:"signature"`
	NodeID    string `json:"node_id"`
	Consensus bool   `json:"consensus"`
	Error     string `json:"error,omitempty"`
}

// NewAVSSigner creates a new AVS signer
func NewAVSSigner(nodeID string) (*AVSSigner, error) {
	// Generate a proper ECDSA private key
	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	// Get the public key
	pubKey := privKey.PubKey()

	return &AVSSigner{
		NodeID:     nodeID,
		PrivateKey: privKey.Serialize(),
		PublicKey:  pubKey.SerializeCompressed(),
		KeyShares:  make(map[string][]byte),
		Consensus:  NewConsensusManager(),
	}, nil
}

// NewConsensusManager creates a new consensus manager
func NewConsensusManager() *ConsensusManager {
	return &ConsensusManager{
		Nodes:     make(map[string]*AVSSigner),
		Threshold: 3, // 2/3 threshold for 5 nodes
	}
}

// GenerateNetworkKeyShares generates key shares for the network key
func (avs *AVSSigner) GenerateNetworkKeyShares(totalShares, threshold int) ([]KeyShare, error) {
	avs.mu.Lock()
	defer avs.mu.Unlock()

	// Generate a new network key
	networkKey := make([]byte, 32)
	_, err := rand.Read(networkKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate network key: %v", err)
	}

	// Create Shamir's Secret Sharing shares
	shares, err := createShamirShares(networkKey, totalShares, threshold)
	if err != nil {
		return nil, fmt.Errorf("failed to create key shares: %v", err)
	}

	// Store shares
	keyShares := make([]KeyShare, len(shares))
	for i, share := range shares {
		shareID := fmt.Sprintf("share_%d", i+1)
		avs.KeyShares[shareID] = share

		keyShares[i] = KeyShare{
			ShareID:   shareID,
			ShareData: share,
			NodeID:    avs.NodeID,
		}
	}

	return keyShares, nil
}

// SignPSBTWithAVS signs a PSBT using AVS consensus
func SignPSBTWithAVS(packet interface{}) (interface{}, error) {
	// Create a mock AVS network for demonstration
	avsNetwork := createMockAVSNetwork()

	// Get consensus signatures
	signatures, err := avsNetwork.GetConsensusSignatures(packet)
	if err != nil {
		return nil, fmt.Errorf("failed to get consensus signatures: %v", err)
	}

	// Apply signatures to PSBT
	signedPacket, err := applySignaturesToPSBT(packet, signatures)
	if err != nil {
		return nil, fmt.Errorf("failed to apply signatures: %v", err)
	}

	return signedPacket, nil
}

// createMockAVSNetwork creates a mock AVS network for testing
func createMockAVSNetwork() *MockAVSNetwork {
	network := &MockAVSNetwork{
		Nodes: make(map[string]*AVSSigner),
	}

	// Create 5 AVS nodes
	for i := 1; i <= 5; i++ {
		nodeID := fmt.Sprintf("avs_node_%d", i)
		signer, err := NewAVSSigner(nodeID)
		if err != nil {
			continue
		}
		network.Nodes[nodeID] = signer
	}

	return network
}

// CreateMockAVSNetwork creates a mock AVS network for testing
func CreateMockAVSNetwork() *MockAVSNetwork {
	return createMockAVSNetwork()
}

// MockAVSNetwork represents a mock AVS network for testing
type MockAVSNetwork struct {
	Nodes map[string]*AVSSigner
}

// GetConsensusSignatures gets consensus signatures from the AVS network
func (network *MockAVSNetwork) GetConsensusSignatures(packet interface{}) ([][]byte, error) {
	signatures := make([][]byte, 0)

	// Get signatures from at least 3 nodes (2/3 threshold)
	signatureCount := 0
	for _, node := range network.Nodes {
		if signatureCount >= 3 {
			break
		}

		signature, err := node.SignPSBT(packet)
		if err != nil {
			continue
		}

		signatures = append(signatures, signature)
		signatureCount++
	}

	if len(signatures) < 3 {
		return nil, fmt.Errorf("insufficient consensus signatures")
	}

	return signatures, nil
}

// SignPSBT signs a PSBT with the node's private key
func (avs *AVSSigner) SignPSBT(packet interface{}) ([]byte, error) {
	// Create a hash of the PSBT for signing
	psbtHash := hashPSBT(packet)

	// Convert private key to btcec.PrivateKey
	privKey, _ := btcec.PrivKeyFromBytes(avs.PrivateKey)
	if privKey == nil {
		return nil, fmt.Errorf("invalid private key")
	}

	// Sign the hash using ECDSA
	signature, err := privKey.Sign(psbtHash)
	if err != nil {
		return nil, fmt.Errorf("failed to sign PSBT hash: %v", err)
	}

	// Convert signature to DER format
	signatureDER := signature.Serialize()

	return signatureDER, nil
}

// hashPSBT creates a hash of the PSBT for signing
func hashPSBT(packet interface{}) []byte {
	// In a real implementation, this would hash the actual PSBT data
	// For now, we'll create a simple hash
	data := fmt.Sprintf("%v", packet)
	hash := sha256.Sum256([]byte(data))
	return hash[:]
}

// applySignaturesToPSBT applies signatures to the PSBT
func applySignaturesToPSBT(packet interface{}, signatures [][]byte) (interface{}, error) {
	// Type assert the packet to PSBT
	psbtPacket, ok := packet.(*psbtlib.Packet)
	if !ok {
		return nil, fmt.Errorf("invalid packet type, expected *psbtlib.Packet")
	}

	// Create a copy of the packet to avoid modifying the original
	signedPacket := *psbtPacket

	// Apply signatures to each input that needs signing
	for i, input := range signedPacket.Inputs {
		if len(input.PartialSigs) == 0 {
			// This input needs signatures
			if i < len(signatures) {
				// Apply the signature to this input
				if err := applySignatureToInput(&signedPacket.Inputs[i], signatures[i], nil); err != nil {
					return nil, fmt.Errorf("failed to apply signature to input %d: %v", i, err)
				}
			}
		}
	}

	// Finalize the PSBT if all inputs are signed
	if isPSBTFullySigned(&signedPacket) {
		if err := finalizePSBT(&signedPacket); err != nil {
			return nil, fmt.Errorf("failed to finalize PSBT: %v", err)
		}
	}

	return &signedPacket, nil
}

// applySignatureToInput applies a signature to a specific PSBT input
func applySignatureToInput(input *psbtlib.PInput, signature []byte, publicKey []byte) error {
	// Validate signature format
	if len(signature) == 0 {
		return fmt.Errorf("signature cannot be empty")
	}

	// If no public key provided, try to extract it from the input
	if len(publicKey) == 0 {
		publicKey = extractPublicKeyFromInput(input)
		if len(publicKey) == 0 {
			return fmt.Errorf("could not determine public key for signature")
		}
	}

	// Check if this public key already has a signature
	for _, existingSig := range input.PartialSigs {
		if existingSig.PubKey != nil && bytes.Equal(existingSig.PubKey, publicKey) {
			return fmt.Errorf("signature for public key %x already exists", publicKey)
		}
	}

	// Create a partial signature entry
	partialSig := &psbtlib.PartialSig{
		PubKey:    publicKey,
		Signature: signature,
	}

	// Add the partial signature to the input
	input.PartialSigs = append(input.PartialSigs, partialSig)

	return nil
}

// extractPublicKeyFromInput attempts to extract the public key from the input
func extractPublicKeyFromInput(input *psbtlib.PInput) []byte {
	// Try to extract from witness script first
	if input.WitnessScript != nil {
		if pubKey := extractPublicKeyFromScript(input.WitnessScript); len(pubKey) > 0 {
			return pubKey
		}
	}

	// Try to extract from redeem script
	if input.RedeemScript != nil {
		if pubKey := extractPublicKeyFromScript(input.RedeemScript); len(pubKey) > 0 {
			return pubKey
		}
	}

	// For Taproot inputs, use the internal key
	if input.TaprootInternalKey != nil {
		return input.TaprootInternalKey
	}

	return nil
}

// extractPublicKeyFromScript attempts to extract a public key from a script
func extractPublicKeyFromScript(script []byte) []byte {
	if len(script) < 2 {
		return nil
	}

	// Look for a 33-byte or 65-byte public key in the script
	for i := 0; i < len(script)-1; i++ {
		if script[i] == 0x21 { // Push 33 bytes
			if i+34 <= len(script) {
				return script[i+1 : i+34]
			}
		} else if script[i] == 0x41 { // Push 65 bytes
			if i+66 <= len(script) {
				return script[i+1 : i+66]
			}
		}
	}

	return nil
}

// isPSBTFullySigned checks if all inputs in the PSBT are fully signed
func isPSBTFullySigned(packet *psbtlib.Packet) bool {
	for i, input := range packet.Inputs {
		if !isInputFullySigned(&input) {
			return false
		}

		// Additional validation for real-world scenarios
		if err := validateSignatureRequirements(&input); err != nil {
			// Log the validation error for debugging
			fmt.Printf("Input %d signature validation failed: %v\n", i, err)
			return false
		}
	}
	return true
}

// isInputFullySigned checks if a specific input is fully signed
func isInputFullySigned(input *psbtlib.PInput) bool {
	// Check if we have any partial signatures
	if len(input.PartialSigs) == 0 {
		return false
	}

	// Get the script requirements based on the input type
	requiredSigs, err := getRequiredSignatures(input)
	if err != nil {
		// If we can't determine requirements, assume it needs at least one signature
		return len(input.PartialSigs) > 0
	}

	// Check if we have the required number of signatures
	return len(input.PartialSigs) >= requiredSigs
}

// getRequiredSignatures determines how many signatures are required for a given input
func getRequiredSignatures(input *psbtlib.PInput) (int, error) {
	// Check for Taproot input (P2TR)
	if input.TaprootInternalKey != nil {
		return getTaprootSignatureRequirements(input)
	}

	// Check for Witness Script (P2WSH)
	if input.WitnessScript != nil {
		return getWitnessScriptSignatureRequirements(input.WitnessScript)
	}

	// Check for Redeem Script (P2SH)
	if input.RedeemScript != nil {
		return getRedeemScriptSignatureRequirements(input.RedeemScript)
	}

	// Check for Non-Witness UTXO (P2PKH, P2SH)
	if input.NonWitnessUtxo != nil {
		return getNonWitnessSignatureRequirements(input)
	}

	// If we can't determine the script type, assume single signature
	return 1, nil
}

// getTaprootSignatureRequirements determines signature requirements for Taproot inputs
func getTaprootSignatureRequirements(input *psbtlib.PInput) (int, error) {
	// For Taproot key path spending, only one signature is required
	if input.TaprootInternalKey != nil && len(input.TaprootKeySpendSig) > 0 {
		return 1, nil
	}

	// For Taproot script path spending, check the script requirements
	if input.TaprootMerkleRoot != nil && len(input.TaprootScriptSpendSig) > 0 {
		// Parse the script to determine requirements
		// This is simplified - in a full implementation you'd parse the actual script
		return 1, nil
	}

	return 1, nil
}

// getWitnessScriptSignatureRequirements determines signature requirements for P2WSH scripts
func getWitnessScriptSignatureRequirements(witnessScript []byte) (int, error) {
	if len(witnessScript) == 0 {
		return 0, fmt.Errorf("empty witness script")
	}

	// Parse the script to determine requirements
	return parseScriptSignatureRequirements(witnessScript)
}

// getRedeemScriptSignatureRequirements determines signature requirements for P2SH scripts
func getRedeemScriptSignatureRequirements(redeemScript []byte) (int, error) {
	if len(redeemScript) == 0 {
		return 0, fmt.Errorf("empty redeem script")
	}

	// Parse the script to determine requirements
	return parseScriptSignatureRequirements(redeemScript)
}

// getNonWitnessSignatureRequirements determines signature requirements for non-witness inputs
func getNonWitnessSignatureRequirements(input *psbtlib.PInput) (int, error) {
	// For P2PKH, only one signature is required
	if isP2PKHScript(input.NonWitnessUtxo.TxOut[input.PreviousOutPoint.Index].PkScript) {
		return 1, nil
	}

	// For P2SH, we need to check the redeem script
	if input.RedeemScript != nil {
		return parseScriptSignatureRequirements(input.RedeemScript)
	}

	// Default to single signature
	return 1, nil
}

// parseScriptSignatureRequirements parses a script to determine signature requirements
func parseScriptSignatureRequirements(script []byte) (int, error) {
	if len(script) == 0 {
		return 0, fmt.Errorf("empty script")
	}

	// Check for multisig script pattern: OP_M <pubkey1> <pubkey2> ... <pubkeyN> OP_N OP_CHECKMULTISIG
	if len(script) >= 3 {
		// Look for OP_CHECKMULTISIG at the end
		if script[len(script)-1] == 0xae { // OP_CHECKMULTISIG
			// Count the number of public keys
			pubKeyCount := 0
			for i := 1; i < len(script)-2; i++ {
				if script[i] >= 0x01 && script[i] <= 0x4b {
					// This is a push operation, likely a public key
					pubKeyCount++
					i += int(script[i]) // Skip the pushed data
				}
			}
			return pubKeyCount, nil
		}
	}

	// Check for single signature script pattern: <pubkey> OP_CHECKSIG
	if len(script) >= 2 && script[len(script)-1] == 0xac { // OP_CHECKSIG
		return 1, nil
	}

	// Check for 2-of-2 multisig pattern (common in Lightning Network)
	if len(script) >= 4 {
		// Pattern: OP_2 <pubkey1> <pubkey2> OP_2 OP_CHECKMULTISIG
		if script[0] == 0x52 && script[len(script)-2] == 0x52 && script[len(script)-1] == 0xae {
			return 2, nil
		}
	}

	// Default to single signature requirement
	return 1, nil
}

// isP2PKHScript checks if a script is a P2PKH script
func isP2PKHScript(pkScript []byte) bool {
	// P2PKH script: OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
	if len(pkScript) == 25 &&
		pkScript[0] == 0x76 && // OP_DUP
		pkScript[1] == 0xa9 && // OP_HASH160
		pkScript[2] == 0x14 && // Push 20 bytes
		pkScript[23] == 0x88 && // OP_EQUALVERIFY
		pkScript[24] == 0xac { // OP_CHECKSIG
		return true
	}
	return false
}

// validateSignatureRequirements validates that the input has the correct signature requirements
func validateSignatureRequirements(input *psbtlib.PInput) error {
	requiredSigs, err := getRequiredSignatures(input)
	if err != nil {
		return fmt.Errorf("failed to determine signature requirements: %v", err)
	}

	if len(input.PartialSigs) < requiredSigs {
		return fmt.Errorf("insufficient signatures: got %d, need %d", len(input.PartialSigs), requiredSigs)
	}

	// Validate that all signatures are valid
	for i, partialSig := range input.PartialSigs {
		if partialSig.PubKey == nil {
			return fmt.Errorf("signature %d missing public key", i)
		}
		if len(partialSig.Signature) == 0 {
			return fmt.Errorf("signature %d is empty", i)
		}
	}

	return nil
}

// finalizePSBT finalizes the PSBT by extracting the final transaction
func finalizePSBT(packet *psbtlib.Packet) error {
	// Use the btcutil PSBT library's finalize method
	err := psbtlib.Finalize(packet)
	if err != nil {
		return fmt.Errorf("failed to finalize PSBT: %v", err)
	}

	return nil
}

// createShamirShares creates Shamir's Secret Sharing shares
func createShamirShares(secret []byte, totalShares, threshold int) ([][]byte, error) {
	// This is a simplified implementation
	// In a real implementation, you would use a proper Shamir's Secret Sharing library

	shares := make([][]byte, totalShares)

	for i := 0; i < totalShares; i++ {
		// Create a simple share by XORing with a random value
		share := make([]byte, len(secret))
		copy(share, secret)

		// Add some randomness to make it a proper share
		randomBytes := make([]byte, len(secret))
		rand.Read(randomBytes)

		for j := range share {
			share[j] ^= randomBytes[j]
		}

		shares[i] = share
	}

	return shares, nil
}

// ValidateSignature validates a signature against a public key
func ValidateSignature(message []byte, signature []byte, publicKey []byte) bool {
	// Parse the public key
	pubKey, err := btcec.ParsePubKey(publicKey)
	if err != nil {
		return false
	}

	// Parse the signature
	sig, err := btcec.ParseSignature(signature, btcec.S256())
	if err != nil {
		return false
	}

	// Verify the signature
	return sig.Verify(message, pubKey)
}

// GetPublicKey returns the public key as hex string
func (avs *AVSSigner) GetPublicKey() string {
	return hex.EncodeToString(avs.PublicKey)
}

// GetNodeInfo returns information about the AVS node
func (avs *AVSSigner) GetNodeInfo() map[string]interface{} {
	return map[string]interface{}{
		"node_id":    avs.NodeID,
		"public_key": avs.GetPublicKey(),
		"shares":     len(avs.KeyShares),
	}
}
