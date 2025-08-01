package main

import (
	"0xbridge/internal/avs"
	"0xbridge/internal/coordination"
	"0xbridge/internal/taproot"
	"encoding/json"
	"fmt"
	"log"
)

// Example usage of 0xBridge components
func main() {
	fmt.Println("0xBridge Protocol Test Example")
	fmt.Println("==============================")

	// 1. Create AVS Network
	fmt.Println("\n1. Creating AVS Network...")
	avsNetwork := avs.CreateMockAVSNetwork()
	fmt.Printf("Created AVS network with %d nodes\n", len(avsNetwork.Nodes))

	// 2. Generate Key Shares
	fmt.Println("\n2. Generating Network Key Shares...")
	for nodeID, node := range avsNetwork.Nodes {
		shares, err := node.GenerateNetworkKeyShares(5, 3)
		if err != nil {
			log.Printf("Error generating shares for node %s: %v\n", nodeID, err)
			continue
		}
		fmt.Printf("Node %s generated %d key shares\n", nodeID, len(shares))
	}

	// 3. Create Taproot MST Script
	fmt.Println("\n3. Creating Taproot MST Script...")
	userPubKey := []byte("user_public_key_32_bytes_long_example")
	avsPubKey := []byte("avs_public_key_32_bytes_long_example")

	mstScript, err := taproot.CreateMSTScript(userPubKey, avsPubKey)
	if err != nil {
		log.Printf("Error creating MST script: %v\n", err)
		return
	}
	fmt.Printf("Created MST script with address: %s\n", mstScript.EncodeAddress())

	// 4. Create Coordination Contract
	fmt.Println("\n4. Creating Coordination Contract...")
	contract := coordination.NewCoordinationContract(1, "0x1234567890123456789012345678901234567890")
	fmt.Printf("Created coordination contract for chain ID: %d\n", contract.ChainID)

	// 5. Add a Claim
	fmt.Println("\n5. Adding a Claim...")
	claim := &coordination.Claim{
		UserAddress:        "user_address_example",
		ClaimAddress:       "claim_address_example",
		DestinationChainID: 1,
		Amount:             1000000, // 0.01 BTC in satoshis
	}

	err = contract.AddClaim(claim)
	if err != nil {
		log.Printf("Error adding claim: %v\n", err)
		return
	}
	fmt.Printf("Added claim with ID: %s\n", claim.ID)

	// 6. Get Contract Info
	fmt.Println("\n6. Getting Contract Information...")
	info := contract.GetContractInfo()
	infoJSON, _ := json.MarshalIndent(info, "", "  ")
	fmt.Printf("Contract Info:\n%s\n", string(infoJSON))

	// 7. Get Pending Claims
	fmt.Println("\n7. Getting Pending Claims...")
	pendingClaims := contract.GetPendingClaims()
	fmt.Printf("Found %d pending claims\n", len(pendingClaims))

	// 8. Process a Claim
	if len(pendingClaims) > 0 {
		fmt.Println("\n8. Processing a Claim...")
		claimToProcess := pendingClaims[0]
		err = contract.ProcessClaim(claimToProcess.ID, "mock_transaction_hash_123")
		if err != nil {
			log.Printf("Error processing claim: %v\n", err)
		} else {
			fmt.Printf("Successfully processed claim: %s\n", claimToProcess.ID)
		}
	}

	// 9. Get AVS Node Information
	fmt.Println("\n9. Getting AVS Node Information...")
	for nodeID, node := range avsNetwork.Nodes {
		nodeInfo := node.GetNodeInfo()
		fmt.Printf("Node %s: %s\n", nodeID, nodeInfo["public_key"])
	}

	fmt.Println("\n0xBridge Protocol Test Example Completed!")
}

// Example API usage functions
func exampleAPIUsage() {
	fmt.Println("\nAPI Usage Examples:")
	fmt.Println("===================")

	// Example 1: Mint 0xBTC
	fmt.Println("\n1. Mint 0xBTC:")
	fmt.Println(`curl -X POST http://localhost:8080/mint \
  -H "Content-Type: application/json" \
  -d '{
    "psbt": "base64_encoded_psbt_data",
    "user_pub_key": "base64_encoded_user_public_key",
    "avs_pub_key": "base64_encoded_avs_public_key"
  }'`)

	// Example 2: Validate PSBT
	fmt.Println("\n2. Validate PSBT:")
	fmt.Println(`curl -X POST http://localhost:8080/validate \
  -H "Content-Type: application/json" \
  -d '{
    "psbt": "base64_encoded_psbt_data"
  }'`)

	// Example 3: Get AVS Status
	fmt.Println("\n3. Get AVS Status:")
	fmt.Println(`curl -X GET http://localhost:8080/avs/status`)

	// Example 4: Add Claim
	fmt.Println("\n4. Add Claim:")
	fmt.Println(`curl -X POST http://localhost:8080/api/coordination/claim/add \
  -H "Content-Type: application/json" \
  -d '{
    "user_address": "user_address",
    "claim_address": "claim_address",
    "destination_chain_id": 1,
    "amount": 1000000
  }'`)

	// Example 5: Get Pending Claims
	fmt.Println("\n5. Get Pending Claims:")
	fmt.Println(`curl -X GET http://localhost:8080/api/coordination/claims/pending`)

	// Example 6: Get Contract Info
	fmt.Println("\n6. Get Contract Info:")
	fmt.Println(`curl -X GET http://localhost:8080/api/coordination/info`)
}
