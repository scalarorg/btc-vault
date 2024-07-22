package btcminting

// Based on github.com/babylonchain/btcstaking/witness_utils.go

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
)

func (si *SpendInfo) CreateBurnPathWitness(
	covenantSigs []*schnorr.Signature,
	dAppSig, delegatorSig *schnorr.Signature,
) (wire.TxWitness, error) {
	if si == nil {
		panic("cannot build witness without spend info")
	}

	var witnessStack [][]byte

	// add covenant signatures to witness stack
	// NOTE: only a quorum number of covenant signatures needs to be non-nil
	if len(covenantSigs) == 0 {
		return nil, fmt.Errorf("covenant signatures should not be empty")
	}
	for _, covSig := range covenantSigs {
		if covSig == nil {
			witnessStack = append(witnessStack, []byte{})
		} else {
			witnessStack = append(witnessStack, covSig.Serialize())
		}
	}

	// add dApp signature to witness stack
	if dAppSig == nil {
		return nil, fmt.Errorf("dApp signature should not be nil")
	}

	witnessStack = append(witnessStack, dAppSig.Serialize())

	// add delegator signature to witness stack
	if delegatorSig == nil {
		return nil, fmt.Errorf("delegator signature should not be nil")
	}

	witnessStack = append(witnessStack, delegatorSig.Serialize())

	return CreateWitness(si, witnessStack)
}

func (si *SpendInfo) CreateSlashingOrLostKeyPathWitness(
	covenantSigs []*schnorr.Signature,
	dAppSig *schnorr.Signature,
) (wire.TxWitness, error) {
	if si == nil {
		panic("cannot build witness without spend info")
	}

	var witnessStack [][]byte

	// add covenant signatures to witness stack
	// NOTE: only a quorum number of covenant signatures needs to be non-nil
	if len(covenantSigs) == 0 {
		return nil, fmt.Errorf("covenant signatures should not be empty")
	}
	for _, covSig := range covenantSigs {
		if covSig == nil {
			witnessStack = append(witnessStack, []byte{})
		} else {
			witnessStack = append(witnessStack, covSig.Serialize())
		}
	}

	// add dApp signature to witness stack
	if dAppSig == nil {
		return nil, fmt.Errorf("dApp signature should not be nil")
	}

	witnessStack = append(witnessStack, dAppSig.Serialize())

	return CreateWitness(si, witnessStack)
}

func (si *SpendInfo) CreateBurnWithoutDAppPathWitness(
	covenantSigs []*schnorr.Signature,
	delegatorSig *schnorr.Signature,
) (wire.TxWitness, error) {
	if si == nil {
		panic("cannot build witness without spend info")
	}

	var witnessStack [][]byte

	// add covenant signatures to witness stack
	// NOTE: only a quorum number of covenant signatures needs to be non-nil
	if len(covenantSigs) == 0 {
		return nil, fmt.Errorf("covenant signatures should not be empty")
	}
	for _, covSig := range covenantSigs {
		if covSig == nil {
			witnessStack = append(witnessStack, []byte{})
		} else {
			witnessStack = append(witnessStack, covSig.Serialize())
		}
	}

	// add dApp signature to witness stack
	if delegatorSig == nil {
		return nil, fmt.Errorf("dApp signature should not be nil")
	}

	witnessStack = append(witnessStack, delegatorSig.Serialize())

	return CreateWitness(si, witnessStack)
}

// - first come signatures
// - then whole revealed script
// - then control block
func CreateWitness(si *SpendInfo, signatures [][]byte) (wire.TxWitness, error) {
	numSignatures := len(signatures)

	controlBlockBytes, err := si.ControlBlock.ToBytes()
	if err != nil {
		return nil, err
	}

	// witness stack has:
	// all signatures
	// whole revealed script
	// control block
	witnessStack := wire.TxWitness(make([][]byte, numSignatures+2))

	for i, sig := range signatures {
		sc := sig
		witnessStack[i] = sc
	}

	witnessStack[numSignatures] = si.GetPkScriptPath()
	witnessStack[numSignatures+1] = controlBlockBytes

	return witnessStack, nil
}
