package btcvault

// Based on github.com/babylonchain/btcstaking/types.go

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

var (
	errBuildingVaultInfo   = fmt.Errorf("error building vault info")
	errBuildingBurningInfo = fmt.Errorf("error building burning info")
)

type scalarScriptPaths struct {
	// burnPathScript is the script path for normal burning
	// <Minter_PK> OP_CHECKSIGVERIFY
	// <dApp_PK> OP_CHECKSIGVERIFY
	// <Covenant_PK1> OP_CHECKSIG ... <Covenant_PKN> OP_CHECKSIGADD M OP_NUMEQUAL
	burnPathScript []byte
	// slashingOrLostKeyPathScript is the script path for slashing or minter lost key
	// <Minter_PK> OP_CHECKSIGVERIFY
	// <Covenant_PK1> OP_CHECKSIG ... <Covenant_PKN> OP_CHECKSIGADD M OP_GREATERTHANOREQUAL
	slashingOrLostKeyPathScript []byte
	// burnWithoutDAppPathScript is the script path for burning without dApp
	// <Minter_PK> OP_CHECKSIGVERIFY
	// <Covenant_PK1> OP_CHECKSIG ... <Covenant_PKN> OP_CHECKSIGADD M OP_GREATERTHANOREQUAL
	burnWithoutDAppPathScript []byte
}

func newScalarScriptPaths(
	stakerKey *btcec.PublicKey,
	fpKeys []*btcec.PublicKey,
	covenantKeys []*btcec.PublicKey,
	covenantQuorum uint32,
) (*scalarScriptPaths, error) {
	if stakerKey == nil {
		return nil, fmt.Errorf("staker key is nil")
	}

	if err := checkForDuplicateKeys(stakerKey, fpKeys, covenantKeys); err != nil {
		return nil, fmt.Errorf("error building scripts: %w", err)
	}

	covenantMultisigScript, err := buildMultiSigScript(
		covenantKeys,
		covenantQuorum,
		// covenant multisig is always last in script so we do not run verify and leave
		// last value on the stack. If we do not leave at least one element on the stack
		// script will always error
		false,
	)

	if err != nil {
		return nil, err
	}

	stakerSigScript, err := buildSingleKeySigScript(stakerKey, true)

	if err != nil {
		return nil, err
	}

	fpSingleKeySigScripts, err := buildSingleKeySigScript(fpKeys[0], false)

	if err != nil {
		return nil, err
	}

	fpMultisigScript, err := buildMultiSigScript(
		fpKeys,
		// we always require only one dApp provider to sign
		1,
		// we need to run verify to clear the stack, as finality provider multisig is in the middle of the script
		true,
	)

	if err != nil {
		return nil, err
	}

	burningPathScript := aggregateScripts(
		stakerSigScript,
		fpSingleKeySigScripts,
	)

	slashingOrLostKeyPathScript := aggregateScripts(
		stakerSigScript,
		fpMultisigScript,
		covenantMultisigScript,
	)

	burningWithoutDAppPathScript := aggregateScripts(
		stakerSigScript,
		covenantMultisigScript,
	)

	return &scalarScriptPaths{
		burnPathScript:              burningPathScript,
		slashingOrLostKeyPathScript: slashingOrLostKeyPathScript,
		burnWithoutDAppPathScript:   burningWithoutDAppPathScript,
	}, nil
}

type VaultInfo struct {
	VaultOutput                   *wire.TxOut
	scriptHolder                  *taprootScriptHolder
	burnPathLeafHash              chainhash.Hash
	slashingOrLostKeyPathLeafHash chainhash.Hash
	burnWithoutDAppPathLeafHash   chainhash.Hash
}

// GetPkScript returns the full staking taproot pkscript in the corresponding staking tx
func (sti *VaultInfo) GetPkScript() []byte {
	return sti.VaultOutput.PkScript
}

// GetOutputFetcher returns the fetcher of the staking tx's output
func (sti *VaultInfo) GetOutputFetcher() *txscript.CannedPrevOutputFetcher {
	return txscript.NewCannedPrevOutputFetcher(
		sti.GetPkScript(), sti.VaultOutput.Value,
	)
}

func BuildVaultInfo(
	stakerKey *btcec.PublicKey,
	fpKeys []*btcec.PublicKey,
	covenantKeys []*btcec.PublicKey,
	covenantQuorum uint32,
	stakingAmount btcutil.Amount,
	net *chaincfg.Params,
) (*VaultInfo, error) {
	unspendableKeyPathKey := unspendableKeyPathInternalPubKey()

	scalarScripts, err := newScalarScriptPaths(
		stakerKey,
		fpKeys,
		covenantKeys,
		covenantQuorum,
	)

	if err != nil {
		return nil, fmt.Errorf("%s: %w", errBuildingVaultInfo, err)
	}

	var unbondingPaths [][]byte
	unbondingPaths = append(unbondingPaths, scalarScripts.burnPathScript)
	unbondingPaths = append(unbondingPaths, scalarScripts.slashingOrLostKeyPathScript)
	unbondingPaths = append(unbondingPaths, scalarScripts.burnWithoutDAppPathScript)

	burnPathLeafHash := txscript.NewBaseTapLeaf(scalarScripts.burnPathScript).TapHash()
	slashingOrLostKeyPathLeafHash := txscript.NewBaseTapLeaf(scalarScripts.slashingOrLostKeyPathScript).TapHash()
	burnWithoutDAppPathLeafHash := txscript.NewBaseTapLeaf(scalarScripts.burnWithoutDAppPathScript).TapHash()

	sh, err := newTaprootScriptHolder(
		&unspendableKeyPathKey,
		unbondingPaths,
	)

	if err != nil {
		return nil, fmt.Errorf("%s: %w", errBuildingVaultInfo, err)
	}

	taprootPkScript, err := sh.taprootPkScript(net)

	if err != nil {
		return nil, fmt.Errorf("%s: %w", errBuildingVaultInfo, err)
	}

	vaultOutput := wire.NewTxOut(int64(stakingAmount), taprootPkScript)

	return &VaultInfo{
		VaultOutput:                   vaultOutput,
		scriptHolder:                  sh,
		burnPathLeafHash:              burnPathLeafHash,
		slashingOrLostKeyPathLeafHash: slashingOrLostKeyPathLeafHash,
		burnWithoutDAppPathLeafHash:   burnWithoutDAppPathLeafHash,
	}, nil
}

func (i *VaultInfo) BurnPathSpendInfo() (*SpendInfo, error) {
	return i.scriptHolder.scriptSpendInfoByName(i.burnPathLeafHash)
}

func (i *VaultInfo) SlashingOrLostKeyPathSpendInfo() (*SpendInfo, error) {
	return i.scriptHolder.scriptSpendInfoByName(i.slashingOrLostKeyPathLeafHash)
}

func (i *VaultInfo) BurnWithoutDAppPathSpendInfo() (*SpendInfo, error) {
	return i.scriptHolder.scriptSpendInfoByName(i.burnWithoutDAppPathLeafHash)
}

type BurningInfo struct {
	BurningOutput               *wire.TxOut
	scriptHolder                *taprootScriptHolder
	burningPathLeafHash         chainhash.Hash
	burnWithoutDAppPathLeafHash chainhash.Hash
}

func BuildBurningInfo(
	stakerKey *btcec.PublicKey,
	dAppKeys []*btcec.PublicKey,
	covenantKeys []*btcec.PublicKey,
	covenantQuorum uint32,
	burningAmount btcutil.Amount,
	net *chaincfg.Params,
) (*BurningInfo, error) {
	unspendableKeyPathKey := unspendableKeyPathInternalPubKey()

	scalarScripts, err := newScalarScriptPaths(
		stakerKey,
		dAppKeys,
		covenantKeys,
		covenantQuorum,
	)

	if err != nil {
		return nil, fmt.Errorf("%s: %w", errBuildingBurningInfo, err)
	}

	var burningPaths [][]byte
	burningPaths = append(burningPaths, scalarScripts.burnPathScript)
	burningPaths = append(burningPaths, scalarScripts.burnWithoutDAppPathScript)

	burningPathLeafHash := txscript.NewBaseTapLeaf(scalarScripts.burnPathScript).TapHash()
	burnWithoutDAppLeafHash := txscript.NewBaseTapLeaf(scalarScripts.burnWithoutDAppPathScript).TapHash()

	sh, err := newTaprootScriptHolder(
		&unspendableKeyPathKey,
		burningPaths,
	)

	if err != nil {
		return nil, fmt.Errorf("%s: %w", errBuildingBurningInfo, err)
	}

	taprootPkScript, err := sh.taprootPkScript(net)

	if err != nil {
		return nil, fmt.Errorf("%s: %w", errBuildingBurningInfo, err)
	}

	unbondingOutput := wire.NewTxOut(int64(burningAmount), taprootPkScript)

	return &BurningInfo{
		BurningOutput:               unbondingOutput,
		scriptHolder:                sh,
		burningPathLeafHash:         burningPathLeafHash,
		burnWithoutDAppPathLeafHash: burnWithoutDAppLeafHash,
	}, nil
}

func (i *BurningInfo) BurningPathSpendInfo() (*SpendInfo, error) {
	return i.scriptHolder.scriptSpendInfoByName(i.burningPathLeafHash)
}

func (i *BurningInfo) BurnWithoutDAppPathSpendInfo() (*SpendInfo, error) {
	return i.scriptHolder.scriptSpendInfoByName(i.burnWithoutDAppPathLeafHash)
}
