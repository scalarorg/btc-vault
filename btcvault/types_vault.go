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
	errBuildingVaultInfo    = fmt.Errorf("error building vault info")
	errBuildingBurningInfo  = fmt.Errorf("error building burning info")
	errBuildingSpendingInfo = fmt.Errorf("error building spending info")
)

type scalarScriptPaths struct {
	// burnPathScript is the script path for normal burning
	// <Minter_PK> OP_CHECKSIGVERIFY
	// <dApp_PK> OP_CHECKSIGVERIFY
	// <Covenant_PK1> OP_CHECKSIG ... <Covenant_PKN> OP_CHECKSIGADD M OP_NUMEQUAL
	burningPathScript []byte
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
		burningPathScript:           burningPathScript,
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
	unbondingPaths = append(unbondingPaths, scalarScripts.burningPathScript)
	unbondingPaths = append(unbondingPaths, scalarScripts.slashingOrLostKeyPathScript)
	unbondingPaths = append(unbondingPaths, scalarScripts.burnWithoutDAppPathScript)

	burnPathLeafHash := txscript.NewBaseTapLeaf(scalarScripts.burningPathScript).TapHash()
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

type SpendPathInfo struct {
	Output       *wire.TxOut
	scriptHolder *taprootScriptHolder
	pathLeafHash chainhash.Hash
}

func BuildSpendingInfo(
	typeOfSpend int,
	stakerKey *btcec.PublicKey,
	dAppKeys []*btcec.PublicKey,
	covenantKeys []*btcec.PublicKey,
	covenantQuorum uint32,
	burningAmount btcutil.Amount,
	net *chaincfg.Params,
) (*SpendPathInfo, error) {
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

	var spendingPaths [][]byte
	var pathLeafHash chainhash.Hash

	if typeOfSpend == 0 {
		spendingPaths = append(spendingPaths, scalarScripts.burningPathScript)
		pathLeafHash = txscript.NewBaseTapLeaf(scalarScripts.burningPathScript).TapHash()

	} else if typeOfSpend == 1 {
		spendingPaths = append(spendingPaths, scalarScripts.slashingOrLostKeyPathScript)
		pathLeafHash = txscript.NewBaseTapLeaf(scalarScripts.slashingOrLostKeyPathScript).TapHash()
	} else if typeOfSpend == 2 {
		spendingPaths = append(spendingPaths, scalarScripts.burnWithoutDAppPathScript)
		pathLeafHash = txscript.NewBaseTapLeaf(scalarScripts.burnWithoutDAppPathScript).TapHash()
	} else {
		return nil, fmt.Errorf("invalid type of spend")
	}

	sh, err := newTaprootScriptHolder(
		&unspendableKeyPathKey,
		spendingPaths,
	)

	if err != nil {
		return nil, fmt.Errorf("%s: %w", errBuildingSpendingInfo, err)
	}

	taprootPkScript, err := sh.taprootPkScript(net)

	if err != nil {
		return nil, fmt.Errorf("%s: %w", errBuildingSpendingInfo, err)
	}

	spendingOutput := wire.NewTxOut(int64(burningAmount), taprootPkScript)

	return &SpendPathInfo{
		Output:       spendingOutput,
		scriptHolder: sh,
		pathLeafHash: pathLeafHash,
	}, nil
}

func (i *SpendPathInfo) PathSpendInfo() (*SpendInfo, error) {
	return i.scriptHolder.scriptSpendInfoByName(i.pathLeafHash)
}
