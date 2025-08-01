# 0xBridge Protocol Implementation

0xBridge is a decentralized Bitcoin bridging protocol that enables users to mint 0xBTC by self-locking native BTC using Partially Signed Bitcoin Transaction (PSBTs). The protocol uses Taproot Merkleized Script Trees (MST) and a decentralized Attestation Verification System (AVS) to facilitate secure, trust-minimized cross-chain minting with built-in fee routing and signature-based spend control.

## Architecture Overview

### Core Components

1. **PSBT Parser & Validator** (`internal/psbt/`)
   - Parses and validates PSBT structures
   - Validates OP_RETURN metadata
   - Ensures proper fee distribution (0.1%)
   - Validates Taproot MST outputs

2. **Taproot Script Builder** (`internal/taproot/`)
   - Creates 2-of-2 multisig scripts
   - Implements Merkleized Script Trees (MST)
   - Supports dual-signature spend paths
   - Handles OP_CHECKSIGVERIFY enforcement

3. **AVS (Attestation Verification System)** (`internal/avs/`)
   - Threshold signing with 2/3 consensus
   - Key share distribution among nodes
   - Consensus management for PSBT signing
   - Network key management

4. **Bitcoin Client** (`internal/btc/`)
   - JSON-RPC integration with Bitcoin Core
   - PSBT broadcasting functionality
   - Transaction validation

5. **Coordination Contracts** (`internal/coordination/`)
   - Cross-chain claim management
   - Claim validation and processing
   - Status tracking and reporting

## Protocol Flow

### 1. PSBT Creation
- User creates PSBT with three outputs:
  - **OP_RETURN**: Metadata (claim address + chain ID)
  - **Taproot MST**: 2-of-2 lock script
  - **Fee Output**: 0.1% fee to collector

### 2. Validation
- PSBT structure validation
- Metadata parsing and validation
- Fee amount verification
- Taproot script validation

### 3. AVS Signing
- Network key share distribution
- Threshold consensus (2/3 of 5 nodes)
- PSBT signing with AVS signatures

### 4. Broadcasting
- Signed PSBT broadcast to Bitcoin network
- Transaction confirmation tracking

### 5. Claim Processing
- Header submission to coordination contracts
- Claim addition and validation
- 0xBTC minting on destination chain

## API Endpoints

### Minting
```
POST /mint
Content-Type: application/json

{
  "psbt": "base64_encoded_psbt",
  "user_pub_key": "base64_encoded_user_public_key",
  "avs_pub_key": "base64_encoded_avs_public_key"
}
```

### Validation
```
POST /validate
Content-Type: application/json

{
  "psbt": "base64_encoded_psbt"
}
```

### AVS Status
```
GET /avs/status
```

### Coordination Contract APIs

#### Add Claim
```
POST /api/coordination/claim/add
Content-Type: application/json

{
  "user_address": "user_address",
  "claim_address": "claim_address",
  "destination_chain_id": 1,
  "amount": 1000000
}
```

#### Get Claim
```
GET /api/coordination/claim/get?id=claim_id
```

#### Process Claim
```
POST /api/coordination/claim/process
Content-Type: application/json

{
  "claim_id": "claim_id",
  "tx_hash": "transaction_hash"
}
```

#### Get Pending Claims
```
GET /api/coordination/claims/pending
```

#### Get Contract Info
```
GET /api/coordination/info
```

## Installation & Setup

### Prerequisites
- Go 1.24.5 or later
- Bitcoin Core (for production)
- Docker (optional)

### Installation
```bash
git clone <repository>
cd 0xbridge
go mod tidy
go build -o 0xbridge main.go
```

### Configuration
Create a configuration file or set environment variables:
```bash
export BITCOIN_RPC_HOST="localhost:8332"
export BITCOIN_RPC_USER="your_rpc_user"
export BITCOIN_RPC_PASS="your_rpc_password"
export FEE_COLLECTOR_ADDRESS="bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
```

### Running
```bash
./0xbridge
```

The server will start on port 8080.

## Technical Specifications

### PSBT Structure
- **Inputs**: Bitcoin UTXOs to be locked
- **Outputs**: 
  - OP_RETURN (metadata)
  - Taproot MST (lock script)
  - Fee output (0.1%)

### Taproot MST Scripts
1. **User-AVS Path**: Requires both user and AVS signatures
2. **Burn Verification Path**: Requires user signature + burn proof

### AVS Network
- **5 nodes** total
- **3 nodes** required for consensus (2/3 threshold)
- **Key shares** distributed among nodes
- **Consensus** for PSBT signing

### Fee Structure
- **0.1%** of locked amount
- **Automatic** routing to fee collector
- **Enforced** at both minting and redemption

## Security Features

1. **Threshold Signing**: 2/3 consensus required
2. **Key Share Distribution**: Shamir's Secret Sharing
3. **Taproot Security**: Advanced Bitcoin scripting
4. **Fee Enforcement**: Protocol-level fee routing
5. **Claim Validation**: Cross-chain verification

## Development

### Project Structure
```
0xbridge/
├── main.go                 # Main application entry
├── api/                    # API handlers
│   ├── handler.go         # Core API handlers
│   └── coordination.go    # Coordination contract APIs
├── internal/              # Core modules
│   ├── psbt/             # PSBT parsing & validation
│   ├── taproot/          # Taproot script building
│   ├── avs/              # AVS consensus system
│   ├── btc/              # Bitcoin client
│   ├── coordination/     # Cross-chain coordination
│   └── utils/            # Utility functions
├── go.mod                # Go module file
└── README.md             # This file
```

### Testing
```bash
go test ./...
```

### Building
```bash
go build -o 0xbridge main.go
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the MIT License.

## Support

For questions and support, please open an issue on the repository. 