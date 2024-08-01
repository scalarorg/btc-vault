package btcvault

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	asig "github.com/scalarorg/btc-vault/crypto/schnorr-adaptor-signature"
)

func signTxWithOneScriptSpendInputFromTapLeafInternal(
	txToSign *wire.MsgTx,
	fundingOutput *wire.TxOut,
	privKey *btcec.PrivateKey,
	tapLeaf txscript.TapLeaf) (*schnorr.Signature, error) {

	inputFetcher := txscript.NewCannedPrevOutputFetcher(
		fundingOutput.PkScript,
		fundingOutput.Value,
	)

	sigHashes := txscript.NewTxSigHashes(txToSign, inputFetcher)

	sig, err := txscript.RawTxInTapscriptSignature(
		txToSign, sigHashes, 0, fundingOutput.Value,
		fundingOutput.PkScript, tapLeaf, txscript.SigHashDefault,
		privKey,
	)

	if err != nil {
		return nil, err
	}

	parsedSig, err := schnorr.ParseSignature(sig)

	if err != nil {
		return nil, err
	}

	return parsedSig, nil
}

// SignTxWithOneScriptSpendInputFromTapLeaf signs transaction with one input coming
// from script spend output.
// It does not do any validations, expect that txToSign has exactly one input.
func SignTxWithOneScriptSpendInputFromTapLeaf(
	txToSign *wire.MsgTx,
	fundingOutput *wire.TxOut,
	privKey *btcec.PrivateKey,
	tapLeaf txscript.TapLeaf,
) (*schnorr.Signature, error) {
	if txToSign == nil {
		return nil, fmt.Errorf("tx to sign must not be nil")
	}

	if fundingOutput == nil {
		return nil, fmt.Errorf("funding output must not be nil")
	}

	if privKey == nil {
		return nil, fmt.Errorf("private key must not be nil")
	}

	if len(txToSign.TxIn) != 1 {
		return nil, fmt.Errorf("tx to sign must have exactly one input")
	}

	return signTxWithOneScriptSpendInputFromTapLeafInternal(
		txToSign,
		fundingOutput,
		privKey,
		tapLeaf,
	)
}

// SignTxWithOneScriptSpendInputFromScript signs transaction with one input coming
// from script spend output with provided script.
// It does not do any validations, expect that txToSign has exactly one input.
func SignTxWithOneScriptSpendInputFromScript(
	txToSign *wire.MsgTx,
	fundingOutput *wire.TxOut,
	privKey *btcec.PrivateKey,
	script []byte,
) (*schnorr.Signature, error) {
	tapLeaf := txscript.NewBaseTapLeaf(script)
	return SignTxWithOneScriptSpendInputFromTapLeaf(txToSign, fundingOutput, privKey, tapLeaf)
}

// SignTxWithOneScriptSpendInputStrict signs transaction with one input coming
// from script spend output with provided script.
// It checks:
// - txToSign is not nil
// - txToSign has exactly one input
// - fundingTx is not nil
// - fundingTx has one output committing to the provided script
// - txToSign input is pointing to the correct output in fundingTx
func SignTxWithOneScriptSpendInputStrict(
	txToSign *wire.MsgTx,
	fundingTx *wire.MsgTx,
	fundingOutputIdx uint32,
	signedScriptPath []byte,
	privKey *btcec.PrivateKey,
) (*schnorr.Signature, error) {

	if err := checkTxBeforeSigning(txToSign, fundingTx, fundingOutputIdx); err != nil {
		return nil, fmt.Errorf("invalid tx: %w", err)
	}

	fundingOutput := fundingTx.TxOut[fundingOutputIdx]

	return SignTxWithOneScriptSpendInputFromScript(txToSign, fundingOutput, privKey, signedScriptPath)
}

// EncSignTxWithOneScriptSpendInputStrict is encrypted version of
// SignTxWithOneScriptSpendInputStrict with the output to be encrypted
// by an encryption key (adaptor signature)
func EncSignTxWithOneScriptSpendInputStrict(
	txToSign *wire.MsgTx,
	fundingTx *wire.MsgTx,
	fundingOutputIdx uint32,
	signedScriptPath []byte,
	privKey *btcec.PrivateKey,
	encKey *asig.EncryptionKey,
) (*asig.AdaptorSignature, error) {

	if err := checkTxBeforeSigning(txToSign, fundingTx, fundingOutputIdx); err != nil {
		return nil, fmt.Errorf("invalid tx: %w", err)
	}

	fundingOutput := fundingTx.TxOut[fundingOutputIdx]

	tapLeaf := txscript.NewBaseTapLeaf(signedScriptPath)

	inputFetcher := txscript.NewCannedPrevOutputFetcher(
		fundingOutput.PkScript,
		fundingOutput.Value,
	)

	sigHashes := txscript.NewTxSigHashes(txToSign, inputFetcher)

	sigHash, err := txscript.CalcTapscriptSignaturehash(
		sigHashes,
		txscript.SigHashDefault,
		txToSign,
		0,
		inputFetcher,
		tapLeaf)
	if err != nil {
		return nil, err
	}

	adaptorSig, err := asig.EncSign(privKey, encKey, sigHash)
	if err != nil {
		return nil, err
	}

	return adaptorSig, nil
}

func checkTxBeforeSigning(txToSign *wire.MsgTx, fundingTx *wire.MsgTx, fundingOutputIdx uint32) error {
	if txToSign == nil {
		return fmt.Errorf("tx to sign must not be nil")
	}

	if len(txToSign.TxIn) != 1 {
		return fmt.Errorf("tx to sign must have exactly one input")
	}

	if fundingOutputIdx >= uint32(len(fundingTx.TxOut)) {
		return fmt.Errorf("invalid funding output index %d, tx has %d outputs", fundingOutputIdx, len(fundingTx.TxOut))
	}

	fundingTxHash := fundingTx.TxHash()

	if !txToSign.TxIn[0].PreviousOutPoint.Hash.IsEqual(&fundingTxHash) {
		return fmt.Errorf("txToSign must input point to fundingTx")
	}

	if txToSign.TxIn[0].PreviousOutPoint.Index != fundingOutputIdx {
		return fmt.Errorf("txToSign inpunt index must point to output with provided script")
	}

	return nil
}

// VerifyTransactionSigWithOutput verifies that:
// - provided transaction has exactly one input
// - provided signature is valid schnorr BIP340 signature
// - provided signature is signing whole provided transaction	(SigHashDefault)
func VerifyTransactionSigWithOutput(
	transaction *wire.MsgTx,
	fundingOutput *wire.TxOut,
	script []byte,
	pubKey *btcec.PublicKey,
	signature []byte) error {

	if fundingOutput == nil {
		return fmt.Errorf("funding output must not be nil")
	}

	if transaction == nil {
		return fmt.Errorf("tx to verify not be nil")
	}

	if len(transaction.TxIn) != 1 {
		return fmt.Errorf("tx to sign must have exactly one input")
	}

	if pubKey == nil {
		return fmt.Errorf("public key must not be nil")
	}

	tapLeaf := txscript.NewBaseTapLeaf(script)

	inputFetcher := txscript.NewCannedPrevOutputFetcher(
		fundingOutput.PkScript,
		fundingOutput.Value,
	)

	sigHashes := txscript.NewTxSigHashes(transaction, inputFetcher)

	sigHash, err := txscript.CalcTapscriptSignaturehash(
		sigHashes, txscript.SigHashDefault, transaction, 0, inputFetcher, tapLeaf,
	)

	if err != nil {
		return err
	}

	parsedSig, err := schnorr.ParseSignature(signature)

	if err != nil {
		return err
	}

	valid := parsedSig.Verify(sigHash, pubKey)

	if !valid {
		return fmt.Errorf("signature is not valid")
	}

	return nil
}

// EncVerifyTransactionSigWithOutput verifies that:
// - provided transaction has exactly one input
// - provided signature is valid adaptor signature
// - provided signature is signing whole provided transaction (SigHashDefault)
func EncVerifyTransactionSigWithOutput(
	transaction *wire.MsgTx,
	fundingOut *wire.TxOut,
	script []byte,
	pubKey *btcec.PublicKey,
	encKey *asig.EncryptionKey,
	signature *asig.AdaptorSignature,
) error {
	if transaction == nil {
		return fmt.Errorf("tx to verify not be nil")
	}

	if len(transaction.TxIn) != 1 {
		return fmt.Errorf("tx to sign must have exactly one input")
	}

	if pubKey == nil {
		return fmt.Errorf("public key must not be nil")
	}

	tapLeaf := txscript.NewBaseTapLeaf(script)

	inputFetcher := txscript.NewCannedPrevOutputFetcher(
		fundingOut.PkScript,
		fundingOut.Value,
	)

	sigHashes := txscript.NewTxSigHashes(transaction, inputFetcher)

	sigHash, err := txscript.CalcTapscriptSignaturehash(
		sigHashes, txscript.SigHashDefault, transaction, 0, inputFetcher, tapLeaf,
	)

	if err != nil {
		return err
	}

	return signature.EncVerify(pubKey, encKey, sigHash)
}
