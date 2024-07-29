package btcvault_test

// based on github.com/babylonchain/btcstaking/btcstaking_test.go

import (
	"bytes"
	"math/rand"
	"sort"
	"testing"
	"time"

	"github.com/babylonchain/babylon/btcstaking"
	btctest "github.com/babylonchain/babylon/testutil/bitcoin"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	btcvault "github.com/scalarorg/btc-vault/btcvault"
	"github.com/stretchr/testify/require"
)

type TestScenario struct {
	StakerKey            *btcec.PrivateKey
	FinalityProviderKeys []*btcec.PrivateKey
	CovenantKeys         []*btcec.PrivateKey
	RequiredCovenantSigs uint32
	StakingAmount        btcutil.Amount
}

func GenerateTestScenario(
	r *rand.Rand,
	t *testing.T,
	numFinalityProviderKeys uint32,
	numCovenantKeys uint32,
	requiredCovenantSigs uint32,
	stakingAmount btcutil.Amount,
) *TestScenario {
	stakerPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	finalityProviderKeys := make([]*btcec.PrivateKey, numFinalityProviderKeys)
	for i := uint32(0); i < numFinalityProviderKeys; i++ {
		covenantPrivKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		finalityProviderKeys[i] = covenantPrivKey
	}

	covenantKeys := make([]*btcec.PrivateKey, numCovenantKeys)

	for i := uint32(0); i < numCovenantKeys; i++ {
		covenantPrivKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		covenantKeys[i] = covenantPrivKey
	}

	return &TestScenario{
		StakerKey:            stakerPrivKey,
		FinalityProviderKeys: finalityProviderKeys,
		CovenantKeys:         covenantKeys,
		RequiredCovenantSigs: requiredCovenantSigs,
		StakingAmount:        stakingAmount,
	}
}

func (t *TestScenario) CovenantPublicKeys() []*btcec.PublicKey {
	covenantPubKeys := make([]*btcec.PublicKey, len(t.CovenantKeys))

	for i, covenantKey := range t.CovenantKeys {
		covenantPubKeys[i] = covenantKey.PubKey()
	}

	return covenantPubKeys
}

func (t *TestScenario) FinalityProviderPublicKeys() []*btcec.PublicKey {
	finalityProviderPubKeys := make([]*btcec.PublicKey, len(t.FinalityProviderKeys))

	for i, fpKey := range t.FinalityProviderKeys {
		finalityProviderPubKeys[i] = fpKey.PubKey()
	}

	return finalityProviderPubKeys
}

func createSpendStakeTx(amount btcutil.Amount) *wire.MsgTx {
	spendStakeTx := wire.NewMsgTx(2)
	spendStakeTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))
	spendStakeTx.AddTxOut(
		&wire.TxOut{
			PkScript: []byte("doesn't matter"),
			Value:    int64(amount),
		},
	)
	return spendStakeTx
}

type SignatureInfo struct {
	SignerPubKey *btcec.PublicKey
	Signature    *schnorr.Signature
}

func NewSignatureInfo(
	signerPubKey *btcec.PublicKey,
	signature *schnorr.Signature,
) *SignatureInfo {
	return &SignatureInfo{
		SignerPubKey: signerPubKey,
		Signature:    signature,
	}
}

// Helper function to sort all signatures in reverse lexicographical order of signing public keys
// this way signatures are ready to be used in multisig witness with corresponding public keys
func sortSignatureInfo(infos []*SignatureInfo) []*SignatureInfo {
	sortedInfos := make([]*SignatureInfo, len(infos))
	copy(sortedInfos, infos)
	sort.SliceStable(sortedInfos, func(i, j int) bool {
		keyIBytes := schnorr.SerializePubKey(sortedInfos[i].SignerPubKey)
		keyJBytes := schnorr.SerializePubKey(sortedInfos[j].SignerPubKey)
		return bytes.Compare(keyIBytes, keyJBytes) == 1
	})

	return sortedInfos
}

// generate list of signatures in valid order
func GenerateSignatures(
	t *testing.T,
	keys []*btcec.PrivateKey,
	tx *wire.MsgTx,
	stakingOutput *wire.TxOut,
	leaf txscript.TapLeaf,
) []*schnorr.Signature {

	var si []*SignatureInfo

	for _, key := range keys {
		pubKey := key.PubKey()
		sig, err := btcstaking.SignTxWithOneScriptSpendInputFromTapLeaf(
			tx,
			stakingOutput,
			key,
			leaf,
		)
		require.NoError(t, err)
		info := NewSignatureInfo(
			pubKey,
			sig,
		)
		si = append(si, info)
	}

	// sort signatures by public key
	sortedSigInfo := sortSignatureInfo(si)

	var sigs []*schnorr.Signature = make([]*schnorr.Signature, len(sortedSigInfo))

	for i, sigInfo := range sortedSigInfo {
		sig := sigInfo
		sigs[i] = sig.Signature
	}

	return sigs
}

func TestSpendingBurningPath(t *testing.T) {
	r := rand.New(rand.NewSource(time.Now().Unix()))

	scenario := GenerateTestScenario(
		r,
		t,
		1,
		5,
		3,
		btcutil.Amount(2*10e8),
	)

	vaultInfo, err := btcvault.BuildVaultInfo(
		scenario.StakerKey.PubKey(),
		scenario.FinalityProviderPublicKeys(),
		scenario.CovenantPublicKeys(),
		scenario.RequiredCovenantSigs,
		scenario.StakingAmount,
		&chaincfg.MainNetParams,
	)

	require.NoError(t, err)

	spendStakeTx := createSpendStakeTx(scenario.StakingAmount.MulF64(0.5))
	si, err := vaultInfo.BurnPathSpendInfo()
	require.NoError(t, err)

	// generate staker signature, and dApp signature
	stakerSig, err := btcstaking.SignTxWithOneScriptSpendInputFromTapLeaf(
		spendStakeTx,
		vaultInfo.VaultOutput,
		scenario.StakerKey,
		si.RevealedLeaf,
	)
	require.NoError(t, err)
	dAppSig, err := btcstaking.SignTxWithOneScriptSpendInputFromTapLeaf(
		spendStakeTx,
		vaultInfo.VaultOutput,
		scenario.FinalityProviderKeys[0],
		si.RevealedLeaf,
	)
	require.NoError(t, err)

	witness, err := si.CreateBurnPathWitness(
		dAppSig,
		stakerSig,
	)
	require.NoError(t, err)
	spendStakeTx.TxIn[0].Witness = witness

	// now as we have finality provider signature execution should succeed
	prevOutputFetcher := vaultInfo.GetOutputFetcher()
	newEngine := func() (*txscript.Engine, error) {
		return txscript.NewEngine(
			vaultInfo.GetPkScript(),
			spendStakeTx, 0, txscript.StandardVerifyFlags, nil,
			txscript.NewTxSigHashes(spendStakeTx, prevOutputFetcher), vaultInfo.VaultOutput.Value,
			prevOutputFetcher,
		)
	}
	btctest.AssertEngineExecution(t, 0, true, newEngine)
}

func TestSpendingSlashingOrLostKeyPathCovenant35MultiSig(t *testing.T) {
	r := rand.New(rand.NewSource(time.Now().Unix()))

	// we are having here 3/5 covenant threshold sig
	scenario := GenerateTestScenario(
		r,
		t,
		1,
		5,
		3,
		btcutil.Amount(2*10e8),
	)

	vaultInfo, err := btcvault.BuildVaultInfo(
		scenario.StakerKey.PubKey(),
		scenario.FinalityProviderPublicKeys(),
		scenario.CovenantPublicKeys(),
		scenario.RequiredCovenantSigs,
		scenario.StakingAmount,
		&chaincfg.MainNetParams,
	)

	require.NoError(t, err)

	spendStakeTx := createSpendStakeTx(scenario.StakingAmount.MulF64(0.5))

	si, err := vaultInfo.SlashingOrLostKeyPathSpendInfo()
	require.NoError(t, err)

	// generate staker, covenant signatures, and finality provider signature

	require.NoError(t, err)

	stakerSig, err := btcstaking.SignTxWithOneScriptSpendInputFromTapLeaf(
		spendStakeTx,
		vaultInfo.VaultOutput,
		scenario.StakerKey,
		si.RevealedLeaf,
	)
	require.NoError(t, err)

	covenantSigantures := GenerateSignatures(
		t,
		scenario.CovenantKeys,
		spendStakeTx,
		vaultInfo.VaultOutput,
		si.RevealedLeaf,
	)
	dAppSig, err := btcstaking.SignTxWithOneScriptSpendInputFromTapLeaf(
		spendStakeTx,
		vaultInfo.VaultOutput,
		scenario.FinalityProviderKeys[0],
		si.RevealedLeaf,
	)
	require.NoError(t, err)

	covenantSigantures[2] = nil
	covenantSigantures[4] = nil

	witness, err := si.CreateSlashingOrLostKeyPathWitness(
		covenantSigantures,
		dAppSig,
		stakerSig,
	)
	require.NoError(t, err)
	spendStakeTx.TxIn[0].Witness = witness

	// now as we have finality provider signature execution should succeed
	prevOutputFetcher := vaultInfo.GetOutputFetcher()
	newEngine := func() (*txscript.Engine, error) {
		return txscript.NewEngine(
			vaultInfo.GetPkScript(),
			spendStakeTx, 0, txscript.StandardVerifyFlags, nil,
			txscript.NewTxSigHashes(spendStakeTx, prevOutputFetcher), vaultInfo.VaultOutput.Value,
			prevOutputFetcher,
		)
	}
	btctest.AssertEngineExecution(t, 0, true, newEngine)
}

// func TestSpendingBurningWithOutDAppCovenant35MultiSig(t *testing.T) {
// 	r := rand.New(rand.NewSource(time.Now().Unix()))

// 	// we are having here 3/5 covenant threshold sig
// 	scenario := GenerateTestScenario(
// 		r,
// 		t,
// 		1,
// 		5,
// 		3,
// 		btcutil.Amount(2*10e8),
// 	)

// 	vaultInfo, err := btcvault.BuildvaultInfo(
// 		scenario.StakerKey.PubKey(),
// 		scenario.FinalityProviderPublicKeys(),
// 		scenario.CovenantPublicKeys(),
// 		scenario.RequiredCovenantSigs,
// 		scenario.StakingAmount,
// 		&chaincfg.MainNetParams,
// 	)

// 	require.NoError(t, err)

// 	spendStakeTx := createSpendStakeTx(scenario.StakingAmount.MulF64(0.5))

// 	si, err := vaultInfo.BurnWithoutDAppPathSpendInfo()
// 	require.NoError(t, err)

// 	// generate covenant signatures, and finality provider signature

// 	require.NoError(t, err)

// 	stakerSig, err := btcstaking.SignTxWithOneScriptSpendInputFromTapLeaf(
// 		spendStakeTx,
// 		vaultInfo.vaultOutput,
// 		scenario.StakerKey,
// 		si.RevealedLeaf,
// 	)

// 	covenantSigantures := GenerateSignatures(
// 		t,
// 		scenario.CovenantKeys,
// 		spendStakeTx,
// 		vaultInfo.vaultOutput,
// 		si.RevealedLeaf,
// 	)

// 	require.NoError(t, err)

// 	covenantSigantures[2] = nil
// 	covenantSigantures[4] = nil

// 	witness, err := si.CreateBurnWithoutDAppPathWitness(
// 		covenantSigantures,
// 		stakerSig,
// 	)
// 	require.NoError(t, err)
// 	spendStakeTx.TxIn[0].Witness = witness

// 	// now as we have finality provider signature execution should succeed
// 	prevOutputFetcher := vaultInfo.GetOutputFetcher()
// 	newEngine := func() (*txscript.Engine, error) {
// 		return txscript.NewEngine(
// 			vaultInfo.GetPkScript(),
// 			spendStakeTx, 0, txscript.StandardVerifyFlags, nil,
// 			txscript.NewTxSigHashes(spendStakeTx, prevOutputFetcher), vaultInfo.vaultOutput.Value,
// 			prevOutputFetcher,
// 		)
// 	}
// 	btctest.AssertEngineExecution(t, 0, true, newEngine)
// }
