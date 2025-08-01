package psbt

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	psbtlib "github.com/btcsuite/btcutil/psbt"
)

// ValidationResult contains the results of PSBT validation
type ValidationResult struct {
	IsValid    bool
	Errors     []string
	Warnings   []string
	Metadata   *OPReturnMetadata
	FeeAmount  int64
	LockAmount int64
}

// OPReturnMetadata contains the parsed metadata from OP_RETURN output
type OPReturnMetadata struct {
	ClaimAddress       string `json:"claim_address"`
	DestinationChainID byte   `json:"destination_chain_id"`
	RawData            []byte `json:"raw_data"`
}

// ValidatePSBT performs comprehensive validation of a PSBT for 0xBridge protocol
func ValidatePSBT(packet *psbtlib.Packet) (*ValidationResult, error) {
	result := &ValidationResult{
		IsValid:  true,
		Errors:   make([]string, 0),
		Warnings: make([]string, 0),
	}

	// Validate basic PSBT structure
	if err := validateBasicStructure(packet); err != nil {
		result.IsValid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Basic structure validation failed: %v", err))
		return result, nil
	}

	// Validate outputs according to 0xBridge specification
	if err := validateOutputs(packet, result); err != nil {
		result.IsValid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Output validation failed: %v", err))
		return result, nil
	}

	// Validate fee distribution
	if err := validateFeeDistribution(packet, result); err != nil {
		result.IsValid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Fee validation failed: %v", err))
		return result, nil
	}

	// Validate Taproot MST script
	if err := validateTaprootMST(packet, result); err != nil {
		result.IsValid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Taproot MST validation failed: %v", err))
		return result, nil
	}

	return result, nil
}

func validateBasicStructure(packet *psbtlib.Packet) error {
	if packet == nil {
		return fmt.Errorf("PSBT packet is nil")
	}

	if packet.UnsignedTx == nil {
		return fmt.Errorf("PSBT unsigned transaction is nil")
	}

	if len(packet.UnsignedTx.TxOut) < 3 {
		return fmt.Errorf("PSBT must have at least 3 outputs (OP_RETURN, Taproot MST, Fee)")
	}

	return nil
}

func validateOutputs(packet *psbtlib.Packet, result *ValidationResult) error {
	outputs := packet.UnsignedTx.TxOut
	var opReturnFound, taprootFound, feeFound bool
	var totalAmount int64

	for i, output := range outputs {
		totalAmount += output.Value

		// Check for OP_RETURN output (metadata)
		if isOPReturnOutput(output) {
			if opReturnFound {
				result.Errors = append(result.Errors, "Multiple OP_RETURN outputs found")
				return fmt.Errorf("multiple OP_RETURN outputs")
			}
			opReturnFound = true

			// Parse OP_RETURN metadata
			metadata, err := parseOPReturnMetadata(output.PkScript)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("OP_RETURN metadata parsing failed: %v", err))
				return err
			}
			result.Metadata = metadata
		}

		// Check for Taproot MST output
		if isTaprootMSTOutput(output) {
			if taprootFound {
				result.Errors = append(result.Errors, "Multiple Taproot MST outputs found")
				return fmt.Errorf("multiple Taproot MST outputs")
			}
			taprootFound = true
			result.LockAmount = output.Value
		}

		// Check for fee output
		if isFeeOutput(output) {
			if feeFound {
				result.Errors = append(result.Errors, "Multiple fee outputs found")
				return fmt.Errorf("multiple fee outputs")
			}
			feeFound = true
			result.FeeAmount = output.Value
		}
	}

	if !opReturnFound {
		result.Errors = append(result.Errors, "OP_RETURN output not found")
		return fmt.Errorf("OP_RETURN output missing")
	}

	if !taprootFound {
		result.Errors = append(result.Errors, "Taproot MST output not found")
		return fmt.Errorf("Taproot MST output missing")
	}

	if !feeFound {
		result.Errors = append(result.Errors, "Fee output not found")
		return fmt.Errorf("fee output missing")
	}

	return nil
}

func validateFeeDistribution(packet *psbtlib.Packet, result *ValidationResult) error {
	// Calculate expected fee (0.1% of lock amount)
	expectedFee := int64(float64(result.LockAmount) * 0.001)

	// Allow for small rounding differences (within 1 satoshi)
	if abs(result.FeeAmount-expectedFee) > 1 {
		result.Errors = append(result.Errors,
			fmt.Sprintf("Fee amount %d does not match expected 0.1%% fee %d",
				result.FeeAmount, expectedFee))
		return fmt.Errorf("incorrect fee amount")
	}

	return nil
}

func validateTaprootMST(packet *psbtlib.Packet, result *ValidationResult) error {
	// Find Taproot MST output
	var taprootOutput *wire.TxOut
	for _, output := range packet.UnsignedTx.TxOut {
		if isTaprootMSTOutput(output) {
			taprootOutput = output
			break
		}
	}

	if taprootOutput == nil {
		return fmt.Errorf("Taproot MST output not found")
	}

	// Validate Taproot script structure
	if err := validateTaprootScript(taprootOutput.PkScript); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Taproot script validation failed: %v", err))
		return err
	}

	return nil
}

func isOPReturnOutput(output *wire.TxOut) bool {
	if len(output.PkScript) < 2 {
		return false
	}
	return output.PkScript[0] == txscript.OP_RETURN
}

func isTaprootMSTOutput(output *wire.TxOut) bool {
	if len(output.PkScript) != 34 {
		return false
	}
	// Taproot outputs start with 0x51 (OP_1) followed by 32 bytes
	return output.PkScript[0] == txscript.OP_1 && output.PkScript[1] == 0x20
}

func isFeeOutput(output *wire.TxOut) bool {
	// Check if this is the fee collector address
	// For now, we'll use a placeholder - in production this would be the actual fee collector address
	feeCollectorAddress := "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"

	addr, err := btcutil.DecodeAddress(feeCollectorAddress, &chaincfg.MainNetParams)
	if err != nil {
		return false
	}

	feeScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return false
	}

	return bytes.Equal(output.PkScript, feeScript)
}

func parseOPReturnMetadata(pkScript []byte) (*OPReturnMetadata, error) {
	if len(pkScript) < 3 {
		return nil, fmt.Errorf("OP_RETURN script too short")
	}

	if pkScript[0] != txscript.OP_RETURN {
		return nil, fmt.Errorf("not an OP_RETURN script")
	}

	// Extract data from OP_RETURN
	dataLength := int(pkScript[1])
	if len(pkScript) < 2+dataLength {
		return nil, fmt.Errorf("OP_RETURN data length mismatch")
	}

	data := pkScript[2 : 2+dataLength]

	// Parse metadata according to 0xBridge specification
	// Format: [20 bytes claim address][1 byte chain ID][remaining data]
	if len(data) < 21 {
		return nil, fmt.Errorf("OP_RETURN metadata too short")
	}

	claimAddress := hex.EncodeToString(data[:20])
	destinationChainID := data[20]

	return &OPReturnMetadata{
		ClaimAddress:       claimAddress,
		DestinationChainID: destinationChainID,
		RawData:            data,
	}, nil
}

func validateTaprootScript(pkScript []byte) error {
	if len(pkScript) != 34 {
		return fmt.Errorf("invalid Taproot script length")
	}

	if pkScript[0] != txscript.OP_1 || pkScript[1] != 0x20 {
		return fmt.Errorf("invalid Taproot script format")
	}

	return nil
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}
