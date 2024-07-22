package btcminting

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/babylonchain/babylon/btcstaking"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const (
	V0OpReturnDataSize               = 69
	PayloadOpReturnDataSize          = 80
	chainIdBytes                     = 8
	ChainIdUserAddressBytes          = 20
	ChainIdSmartContractAddressBytes = 20
	AmountBytes                      = 32
)

type IdentifiableMintingInfo struct {
	MintingOutput                 *wire.TxOut
	scriptHolder                  *taprootScriptHolder
	burnPathLeafHash              chainhash.Hash
	slashingOrLostKeyPathLeafHash chainhash.Hash
	burnWithoutDAppPathLeafHash   chainhash.Hash
	OpReturnOutput                *wire.TxOut
	PayloadOutput                 *wire.TxOut
}

type PayloadOpReturnData struct {
	ChainID                     []byte
	ChainIdUserAddress          []byte
	ChainIdSmartContractAddress []byte
	Amount                      []byte
}

func NewPayloadOpReturnData(
	chainID []byte,
	chainIdUserAddress []byte,
	chainIdSmartContractAddress []byte,
	amount []byte,
) (*PayloadOpReturnData, error) {
	if len(chainID) != chainIdBytes {
		return nil, fmt.Errorf("invalid chain id length: %d, expected: %d", len(chainID), chainIdBytes)
	}
	if len(chainIdUserAddress) != ChainIdUserAddressBytes {
		return nil, fmt.Errorf("invalid chain id user address length: %d, expected: %d", len(chainIdUserAddress), ChainIdUserAddressBytes)
	}
	if len(chainIdSmartContractAddress) != ChainIdSmartContractAddressBytes {
		return nil, fmt.Errorf("invalid chain id smart contract address length: %d, expected: %d", len(chainIdSmartContractAddress), ChainIdSmartContractAddressBytes)
	}
	if len(amount) != AmountBytes {
		return nil, fmt.Errorf("invalid amount length: %d, expected: %d", len(amount), AmountBytes)
	}
	return NewPayloadOpReturnDataFromParsed(chainID, chainIdUserAddress, chainIdSmartContractAddress, amount)
}

func NewPayloadOpReturnDataFromParsed(
	chainID []byte,
	chainIdUserAddress []byte,
	chainIdSmartContractAddress []byte,
	Amount []byte,
) (*PayloadOpReturnData, error) {
	return &PayloadOpReturnData{
		ChainID:                     chainID,
		ChainIdUserAddress:          chainIdUserAddress,
		ChainIdSmartContractAddress: chainIdSmartContractAddress,
		Amount:                      Amount,
	}, nil
}

func NewPayloadOpReturnDataFromBytes(b []byte) (*PayloadOpReturnData, error) {
	if len(b) != PayloadOpReturnDataSize {
		return nil, fmt.Errorf("invalid payload op return data length: %d, expected: %d", len(b), PayloadOpReturnDataSize)
	}
	chainID := b[:chainIdBytes]
	chainIdUserAddress := b[chainIdBytes : chainIdBytes+ChainIdUserAddressBytes]
	chainIdSmartContractAddress := b[chainIdBytes+ChainIdUserAddressBytes : chainIdBytes+ChainIdUserAddressBytes+ChainIdSmartContractAddressBytes]
	amount := b[chainIdBytes+ChainIdUserAddressBytes+ChainIdSmartContractAddressBytes:]
	return NewPayloadOpReturnData(chainID, chainIdUserAddress, chainIdSmartContractAddress, amount)
}

func getPayloadOPReturnBytes(out *wire.TxOut) ([]byte, error) {
	if out == nil {
		return nil, fmt.Errorf("nil tx output")
	}

	// We are adding `+3` as each op return has additional 3 for:
	// 1. OP_RETURN opcode - which signalizes that data is provably unspendable
	// 2. OP_PUSHDATA1 opcode - which pushes the next byte contains the number of bytes to be pushed onto the stack.
	// 3. 0x50 - we define that in code is OP_80 which is the bytes number to be pushed onto the stack
	if len(out.PkScript) != PayloadOpReturnDataSize+3 {
		return nil, fmt.Errorf("invalid op return data length: %d, expected: %d", len(out.PkScript), PayloadOpReturnDataSize+3)
	}
	if !txscript.IsNullData(out.PkScript) {
		return nil, fmt.Errorf("invalid op return script")
	}
	return out.PkScript[3:], nil
}

func NewPayloadOpReturnDataFromTxOutput(out *wire.TxOut) (*PayloadOpReturnData, error) {
	data, err := getPayloadOPReturnBytes(out)

	if err != nil {
		return nil, fmt.Errorf("cannot parse payload op return data: %w", err)
	}

	return NewPayloadOpReturnDataFromBytes(data)
}
func (d *PayloadOpReturnData) PayloadMarshall() []byte {
	var data []byte
	data = append(data, d.ChainID...)
	data = append(data, d.ChainIdUserAddress...)
	data = append(data, d.ChainIdSmartContractAddress...)
	data = append(data, d.Amount...)
	return data
}

func Marshall(d *btcstaking.V0OpReturnData) []byte {
	var data []byte
	data = append(data, d.Tag...)
	data = append(data, d.Version)
	data = append(data, d.StakerPublicKey.Marshall()...)
	data = append(data, d.FinalityProviderPublicKey.Marshall()...)
	return data
}

func DataToTxOutput(d *btcstaking.V0OpReturnData) (*wire.TxOut, error) {
	dataScript, err := txscript.NullDataScript(Marshall(d))
	if err != nil {
		return nil, err
	}
	return wire.NewTxOut(0, dataScript), nil
}

func (d *PayloadOpReturnData) PayloadDataToTxOutput() (*wire.TxOut, error) {
	dataScript, err := txscript.NullDataScript(d.PayloadMarshall())
	if err != nil {
		return nil, err
	}
	return wire.NewTxOut(0, dataScript), nil
}

// BuildV0IdentifiableMintingOutputs creates outputs which every minting transaction must have
func BuildV0IdentifiableMintingOutputs(
	tag []byte,
	stakerKey *btcec.PublicKey,
	dAppKey *btcec.PublicKey,
	covenantKeys []*btcec.PublicKey,
	covenantQuorum uint32,
	amount btcutil.Amount,
	chainID []byte,
	chainIdUserAddress []byte,
	chainIdSmartContractAddress []byte,
	mintingAmount []byte,
	net *chaincfg.Params,
) (*IdentifiableMintingInfo, error) {

	info, err := BuildMintingInfo(
		stakerKey,
		[]*btcec.PublicKey{dAppKey},
		covenantKeys,
		covenantQuorum,
		0,
		net,
	)

	if err != nil {
		return nil, err
	}

	V0OpReturnData, err := btcstaking.NewV0OpReturnDataFromParsed(tag, stakerKey, dAppKey, 0)

	if err != nil {
		return nil, err
	}
	DataOutput, err := DataToTxOutput(V0OpReturnData)

	if err != nil {

		return nil, err
	}

	PayloadOpReturnData, err := NewPayloadOpReturnDataFromParsed(chainID, chainIdUserAddress, chainIdSmartContractAddress, mintingAmount)

	if err != nil {

		return nil, err
	}

	PayloadDataOutput, err := PayloadOpReturnData.PayloadDataToTxOutput()

	if err != nil {

		return nil, err
	}

	return &IdentifiableMintingInfo{
		MintingOutput:                 info.MintingOutput,
		scriptHolder:                  info.scriptHolder,
		burnPathLeafHash:              info.burnPathLeafHash,
		slashingOrLostKeyPathLeafHash: info.slashingOrLostKeyPathLeafHash,
		burnWithoutDAppPathLeafHash:   info.burnWithoutDAppPathLeafHash,
		OpReturnOutput:                DataOutput,
		PayloadOutput:                 PayloadDataOutput,
	}, nil
}

// BuildV0IdentifiableMintingOutputsAndTx creates outputs which every minting transaction must have and
// returns the not-funded transaction with these outputs
func BuildV0IdentifiableMintingOutputsAndTx(
	tag []byte,
	stakerKey *btcec.PublicKey,
	fpKey *btcec.PublicKey,
	covenantKeys []*btcec.PublicKey,
	covenantQuorum uint32,
	amount btcutil.Amount,
	chainID []byte,
	chainIdUserAddress []byte,
	chainIdSmartContractAddress []byte,
	mintingAmount []byte,
	net *chaincfg.Params,
) (*IdentifiableMintingInfo, *wire.MsgTx, error) {
	info, err := BuildV0IdentifiableMintingOutputs(
		tag,
		stakerKey,
		fpKey,
		covenantKeys,
		covenantQuorum,
		amount,
		chainID,
		chainIdUserAddress,
		chainIdSmartContractAddress,
		mintingAmount,
		net,
	)
	if err != nil {
		return nil, nil, err
	}
	tx := wire.NewMsgTx(2)
	tx.AddTxOut(info.MintingOutput)
	tx.AddTxOut(info.OpReturnOutput)
	tx.AddTxOut(info.PayloadOutput)
	return info, tx, nil

}

func (i *IdentifiableMintingInfo) BurnPathSpendInfo() (*SpendInfo, error) {
	return i.scriptHolder.scriptSpendInfoByName(i.burnPathLeafHash)
}

func (i *IdentifiableMintingInfo) SlashingOrLostKeyPathSpendInfo() (*SpendInfo, error) {
	return i.scriptHolder.scriptSpendInfoByName(i.slashingOrLostKeyPathLeafHash)
}

func (i *IdentifiableMintingInfo) BurnWithoutDAppPathSpendInfo() (*SpendInfo, error) {
	return i.scriptHolder.scriptSpendInfoByName(i.burnWithoutDAppPathLeafHash)
}

type ParsedV0MintingTx struct {
	MintingOutput       *wire.TxOut
	MintingOutputIdx    int
	OpReturnOutput      *wire.TxOut
	OpReturnOutputIdx   int
	OpReturnData        *btcstaking.V0OpReturnData
	PayloadOutput       *wire.TxOut
	PayloadOutputIdx    int
	PayloadOpReturnData *PayloadOpReturnData
}

// ParseV0MintingTx takes a btc transaction and checks whether it is a staking transaction and if so parses it
// for easy data retrieval.
// It does all necessary checks to ensure that the transaction is valid staking transaction.
func ParseV0MintingTx(
	tx *wire.MsgTx,
	expectedTag []byte,
	covenantKeys []*btcec.PublicKey,
	covenantQuorum uint32,
	net *chaincfg.Params,
) (*ParsedV0MintingTx, error) {
	// 1. Basic arguments checks
	if tx == nil {
		return nil, fmt.Errorf("nil tx")
	}

	if len(expectedTag) != btcstaking.TagLen {
		return nil, fmt.Errorf("invalid tag length: %d, expected: %d", len(expectedTag), btcstaking.TagLen)
	}
	if len(covenantKeys) == 0 {
		return nil, fmt.Errorf("no covenant keys specified")
	}
	if covenantQuorum > uint32(len(covenantKeys)) {
		return nil, fmt.Errorf("covenant quorum is greater than the number of covenant keys")
	}

	// 2. Identify whether the transaction has expected shape
	if len(tx.TxOut) != 4 {
		return nil, fmt.Errorf("staking tx must have 4 outputs")
	}

	// opReturnData, opReturnOutputIdx, err := tryToGetOpReturnDataFromOutputs(tx.TxOut)
	opReturnData, err := NewV0OpReturnDataFromTxOutput(tx.TxOut[1])
	if err != nil {
		return nil, fmt.Errorf("cannot parse v0 op return staking transaction: %w", err)
	}
	if opReturnData == nil {
		return nil, fmt.Errorf("transaction does not have expected v0 op return output")
	}
	PayloadOpReturnData, err := NewPayloadOpReturnDataFromTxOutput(tx.TxOut[2])

	if err != nil {
		return nil, fmt.Errorf("cannot parse payload op return data: %w", err)
	}

	if PayloadOpReturnData == nil {
		return nil, fmt.Errorf("transaction does not have expected payload op return output")
	}

	// at this point we know that transaction has op return output which seems to match
	// the expected shape. Check the tag and version.
	if !bytes.Equal(opReturnData.Tag, expectedTag) {
		return nil, fmt.Errorf("unexpected tag: %s, expected: %s",
			hex.EncodeToString(opReturnData.Tag),
			hex.EncodeToString(expectedTag),
		)
	}

	if opReturnData.Version != 0 {
		return nil, fmt.Errorf("unexpcted version: %d, expected: %d", opReturnData.Version, 0)
	}

	// 3. Op return seems to be valid V0 op return output. Now, we need to check whether
	// the staking output exists and is valid.
	mintingInfo, err := BuildMintingInfo(
		opReturnData.StakerPublicKey.PubKey,
		[]*btcec.PublicKey{opReturnData.FinalityProviderPublicKey.PubKey},
		covenantKeys,
		covenantQuorum,
		// we can pass 0 here, as staking amount is not used when creating taproot address
		0,
		net,
	)
	if err != nil {
		return nil, fmt.Errorf("cannot build minting info: %w", err)
	}
	// mintingOutput, mintingOutputIdx, err := tryToGetMintingOutput(tx.TxOut, mintingInfo.MintingOutput.PkScript)
	if !bytes.Equal(tx.TxOut[0].PkScript, mintingInfo.MintingOutput.PkScript) {
		return nil, fmt.Errorf("transaction does not have expected minting output with format at index 0")
	}
	mintingOutput := tx.TxOut[0]
	mintingOutputIdx := 0

	if mintingOutput == nil {
		return nil, fmt.Errorf("staking output not found in potential staking transaction")
	}
	return &ParsedV0MintingTx{
		MintingOutput:       mintingOutput,
		MintingOutputIdx:    mintingOutputIdx,
		OpReturnOutput:      tx.TxOut[1],
		OpReturnOutputIdx:   1,
		OpReturnData:        opReturnData,
		PayloadOutput:       tx.TxOut[2],
		PayloadOutputIdx:    2,
		PayloadOpReturnData: PayloadOpReturnData,
	}, nil
}

// Modified getV0OpReturnDataBytes, NewV0OpReturnDataFromTxOutput, NewV0OpReturnDataFromBytes
// Using this private method
// from github.com/babylonchain/babylon/btcstaking/identifiable_staking.go
func getV0OpReturnBytes(out *wire.TxOut) ([]byte, error) {
	if out == nil {
		return nil, fmt.Errorf("nil tx output")
	}
	// We are adding `+2` as each op return has additional 2 for:
	// 1. OP_RETURN opcode - which signalizes that data is provably unspendable
	// 2. OP_PUSHBYTE_69 opcode - which pushes 69 bytes of data to the stack
	if len(out.PkScript) != V0OpReturnDataSize+2 {
		return nil, fmt.Errorf("invalid v0 op return data length: %d, expected: %d", len(out.PkScript), V0OpReturnDataSize+2)
	}

	if !txscript.IsNullData(out.PkScript) {
		return nil, fmt.Errorf("invalid v0 op return script")
	}
	return out.PkScript[2:], nil
}

// we need to change V0OpReturnDataSize to 69
func NewV0OpReturnDataFromBytes(b []byte) (*btcstaking.V0OpReturnData, error) {
	const TagLen = btcstaking.TagLen
	if len(b) != V0OpReturnDataSize {
		return nil, fmt.Errorf("invalid op return data length: %d, expected: %d", len(b), V0OpReturnDataSize)
	}
	tag := b[:TagLen]
	version := b[TagLen]

	if version != 0 {
		return nil, fmt.Errorf("invalid op return version: %d, expected: %d", version, 0)
	}

	stakerPublicKey := b[TagLen+1 : TagLen+1+schnorr.PubKeyBytesLen]
	finalityProviderPublicKey := b[TagLen+1+schnorr.PubKeyBytesLen : TagLen+1+schnorr.PubKeyBytesLen*2]

	return btcstaking.NewV0OpReturnData(tag, stakerPublicKey, finalityProviderPublicKey, []byte{0, 0})
}

func NewV0OpReturnDataFromTxOutput(out *wire.TxOut) (*btcstaking.V0OpReturnData, error) {
	data, err := getV0OpReturnBytes(out)
	if err != nil {
		return nil, fmt.Errorf("cannot parse op return data: %w", err)
	}

	return NewV0OpReturnDataFromBytes(data)
}

// IsPossibleV0MintingTx checks whether transaction may be a valid staking transaction
// checks:
// 1. Whether the transaction must have 4 outputs
// 2. have an 2 op return output
// 3. first op return output must the same as IsPossibleV0StakingTx but remove staking time
// 4. second op return output must be a valid payload
// This function is much faster than ParseV0StakingTx, as it does not perform
// all necessary checks.
func IsPossibleV0MintingTx(tx *wire.MsgTx, expectedTag []byte) bool {
	if len(expectedTag) != btcstaking.TagLen {
		return false
	}

	if len(tx.TxOut) != 4 {
		return false
	}
	_, err := getV0OpReturnBytes(tx.TxOut[1])

	if err != nil {
		return false
	}

	_, err = getPayloadOPReturnBytes(tx.TxOut[2])

	return err == nil
}
