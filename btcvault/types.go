package btcvault

// Using the private method
// from github.com/babylonchain/babylon/btcstaking/types.go

import (
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const (
	// Point with unknown discrete logarithm defined in: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
	// using it as internal public key effectively disables taproot key spends
	unspendableKeyPath = "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
)

var (
	unspendableKeyPathKey    = unspendableKeyPathInternalPubKeyInternal(unspendableKeyPath)
	ErrDuplicatedKeyInScript = fmt.Errorf("duplicated key in script")
)

func unspendableKeyPathInternalPubKeyInternal(keyHex string) btcec.PublicKey {
	keyBytes, err := hex.DecodeString(keyHex)

	if err != nil {
		panic(fmt.Sprintf("unexpected error: %v", err))
	}

	// We are using btcec here, as key is 33 byte compressed format.
	pubKey, err := btcec.ParsePubKey(keyBytes)

	if err != nil {
		panic(fmt.Sprintf("unexpected error: %v", err))
	}
	return *pubKey
}

func unspendableKeyPathInternalPubKey() btcec.PublicKey {
	return unspendableKeyPathKey
}

func NewTaprootTreeFromScripts(
	scripts [][]byte,
) *txscript.IndexedTapScriptTree {
	var tapLeafs []txscript.TapLeaf
	for _, script := range scripts {
		scr := script
		tapLeafs = append(tapLeafs, txscript.NewBaseTapLeaf(scr))
	}
	return txscript.AssembleTaprootScriptTree(tapLeafs...)
}

func DeriveTaprootAddress(
	tapScriptTree *txscript.IndexedTapScriptTree,
	internalPubKey *btcec.PublicKey,
	net *chaincfg.Params) (*btcutil.AddressTaproot, error) {

	tapScriptRootHash := tapScriptTree.RootNode.TapHash()

	outputKey := txscript.ComputeTaprootOutputKey(
		internalPubKey, tapScriptRootHash[:],
	)

	address, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(outputKey), net)

	if err != nil {
		return nil, fmt.Errorf("error encoding Taproot address: %v", err)
	}

	return address, nil
}

func DeriveTaprootPkScript(
	tapScriptTree *txscript.IndexedTapScriptTree,
	internalPubKey *btcec.PublicKey,
	net *chaincfg.Params,
) ([]byte, error) {
	taprootAddress, err := DeriveTaprootAddress(
		tapScriptTree,
		&unspendableKeyPathKey,
		net,
	)

	if err != nil {
		return nil, err
	}

	taprootPkScript, err := txscript.PayToAddrScript(taprootAddress)

	if err != nil {
		return nil, err
	}

	return taprootPkScript, nil
}

type taprootScriptHolder struct {
	internalPubKey *btcec.PublicKey
	scriptTree     *txscript.IndexedTapScriptTree
}

func newTaprootScriptHolder(
	internalPubKey *btcec.PublicKey,
	scripts [][]byte,
) (*taprootScriptHolder, error) {
	if internalPubKey == nil {
		return nil, fmt.Errorf("internal public key is nil")
	}

	if len(scripts) == 0 {
		return &taprootScriptHolder{
			scriptTree: txscript.NewIndexedTapScriptTree(0),
		}, nil
	}

	createdLeafs := make(map[chainhash.Hash]bool)
	tapLeafs := make([]txscript.TapLeaf, len(scripts))

	for i, s := range scripts {
		script := s
		if len(script) == 0 {
			return nil, fmt.Errorf("cannot build tree with empty script")
		}

		tapLeaf := txscript.NewBaseTapLeaf(script)
		leafHash := tapLeaf.TapHash()

		if _, ok := createdLeafs[leafHash]; ok {
			return nil, fmt.Errorf("duplicate script in provided scripts")
		}

		createdLeafs[leafHash] = true
		tapLeafs[i] = tapLeaf
	}

	scriptTree := txscript.AssembleTaprootScriptTree(tapLeafs...)

	return &taprootScriptHolder{
		internalPubKey: internalPubKey,
		scriptTree:     scriptTree,
	}, nil
}

func (t *taprootScriptHolder) scriptSpendInfoByName(
	leafHash chainhash.Hash,
) (*SpendInfo, error) {
	scriptIdx, ok := t.scriptTree.LeafProofIndex[leafHash]

	if !ok {
		return nil, fmt.Errorf("script not found in script tree")
	}

	merkleProof := t.scriptTree.LeafMerkleProofs[scriptIdx]

	return &SpendInfo{
		ControlBlock: merkleProof.ToControlBlock(t.internalPubKey),
		RevealedLeaf: merkleProof.TapLeaf,
	}, nil
}

func (t *taprootScriptHolder) taprootPkScript(net *chaincfg.Params) ([]byte, error) {
	return DeriveTaprootPkScript(
		t.scriptTree,
		t.internalPubKey,
		net,
	)
}

// Package responsible for different kinds of btc scripts used by babylon
// Staking script has 3 spending paths:
// 1. Staker can spend after relative time lock - staking
// 2. Staker can spend with covenat cooperation any time
// 3. Staker can spend with finality provider and covenant cooperation any time.
type StakingInfo struct {
	StakingOutput         *wire.TxOut
	scriptHolder          *taprootScriptHolder
	timeLockPathLeafHash  chainhash.Hash
	unbondingPathLeafHash chainhash.Hash
	slashingPathLeafHash  chainhash.Hash
}

// GetPkScript returns the full staking taproot pkscript in the corresponding staking tx
func (sti *StakingInfo) GetPkScript() []byte {
	return sti.StakingOutput.PkScript
}

// GetOutputFetcher returns the fetcher of the staking tx's output
func (sti *StakingInfo) GetOutputFetcher() *txscript.CannedPrevOutputFetcher {
	return txscript.NewCannedPrevOutputFetcher(
		sti.GetPkScript(), sti.StakingOutput.Value,
	)
}

// SpendInfo contains information necessary to create witness for given script
type SpendInfo struct {
	// Control block contains merkle proof of inclusion of revealed script path
	ControlBlock txscript.ControlBlock
	// RevealedLeaf is the leaf of the script tree which is revealed i.e scriptpath
	// which is being executed
	RevealedLeaf txscript.TapLeaf
}

// GetPkScriptPath returns the path of the taproot pkscript corresponding
// to the triggered spending condition of the tx associated with the SpendInfo
func (si *SpendInfo) GetPkScriptPath() []byte {
	return si.RevealedLeaf.Script
}

func SpendInfoFromRevealedScript(
	revealedScript []byte,
	internalKey *btcec.PublicKey,
	tree *txscript.IndexedTapScriptTree) (*SpendInfo, error) {

	revealedLeaf := txscript.NewBaseTapLeaf(revealedScript)
	leafHash := revealedLeaf.TapHash()

	scriptIdx, ok := tree.LeafProofIndex[leafHash]

	if !ok {
		return nil, fmt.Errorf("script not found in script tree")
	}

	merkleProof := tree.LeafMerkleProofs[scriptIdx]

	return &SpendInfo{
		ControlBlock: merkleProof.ToControlBlock(internalKey),
		RevealedLeaf: revealedLeaf,
	}, nil
}

func aggregateScripts(scripts ...[]byte) []byte {
	if len(scripts) == 0 {
		return []byte{}
	}

	var finalScript []byte

	for _, script := range scripts {
		finalScript = append(finalScript, script...)
	}
	return finalScript
}

func keyToString(key *btcec.PublicKey) string {
	return hex.EncodeToString(schnorr.SerializePubKey(key))
}

func checkForDuplicateKeys(
	stakerKey *btcec.PublicKey,
	fpKeys []*btcec.PublicKey,
	covenantKeys []*btcec.PublicKey,
) error {
	keyMap := make(map[string]struct{})

	keyMap[keyToString(stakerKey)] = struct{}{}

	for _, key := range fpKeys {
		keyStr := keyToString(key)

		if _, ok := keyMap[keyStr]; ok {
			return fmt.Errorf("key: %s: %w", keyStr, ErrDuplicatedKeyInScript)
		}

		keyMap[keyStr] = struct{}{}
	}

	for _, key := range covenantKeys {
		keyStr := keyToString(key)

		if _, ok := keyMap[keyStr]; ok {
			return fmt.Errorf("key: %s: %w", keyStr, ErrDuplicatedKeyInScript)
		}

		keyMap[keyStr] = struct{}{}
	}

	return nil
}
