package psbt

import (
	"bytes"

	"github.com/btcsuite/btcd/wire"
	psbtlib "github.com/btcsuite/btcutil/psbt"
)

func ParsePSBT(raw []byte) (*psbtlib.Packet, error) {
	packet, err := psbtlib.NewFromRawBytes(bytes.NewReader(raw), true)
	if err != nil {
		return nil, err
	}
	return packet, nil
}

func ValidateFeeOutput(packet *psbtlib.Packet) bool {
	const feePercent = 0.001 // 0.1%
	for _, out := range packet.UnsignedTx.TxOut {
		if isFeeOutput(out) {
			return true
		}
	}
	return false
}

func isFeeOutput(out *wire.TxOut) bool {
	// TODO: Replace with actual fee collector address PkScript match
	return out.Value > 0 && out.PkScript != nil
}
