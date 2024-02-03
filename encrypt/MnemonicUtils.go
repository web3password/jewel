/*
*
open source for free, this file is GPL LICENSE
*/
package encrypt

import (
	"crypto/ecdsa"
	"errors"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip39"
	"strings"
)

/*
*
go get -u github.com/tyler-smith/go-bip39
go get -u github.com/btcsuite/btcd/btcutil
go get -u github.com/btcsuite/btcd/chaincfg
go get -u github.com/ethereum/go-ethereum/crypto
go get github.com/ethereum/go-ethereum/log@v1.12.2
*/
const issue179FixEnvar = "GO_ETHEREUM_HDWALLET_FIX_ISSUE_179"

type Web3PasswordWallet struct {
	mnemonic    string
	seed        []byte
	masterKey   *hdkeychain.ExtendedKey
	fixIssue172 bool
}

type Web3PasswordKey struct {
	PrivateKey string // has 0x prefix, hex string
	PublicKey  string // has 0x prefix, hex string
	Address    string // has 0x prefix, hex string
}

func (w *Web3PasswordWallet) DeriveNewKey(hdPathStr_ string) (*Web3PasswordKey, error) {

	hdPath, _ := accounts.ParseDerivationPath(hdPathStr_)
	var err2 error
	key := w.masterKey
	for _, n := range hdPath {
		if w.fixIssue172 && key.IsAffectedByIssue172() {
			key, err2 = key.Derive(n)
		} else {
			key, err2 = key.DeriveNonStandard(n)
		}
		if err2 != nil {
			return nil, err2
		}
	}

	privateKey, err2 := key.ECPrivKey()
	privateKeyECDSA := privateKey.ToECDSA()
	if err2 != nil {
		return nil, err2
	}
	privateKeys2Bytes := crypto.FromECDSA(privateKeyECDSA)

	// private key with 0x prefix
	privateKeyStr := hexutil.Encode(privateKeys2Bytes)

	publicKey := privateKeyECDSA.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("generate public key failed")
	}

	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	// public key with 0x prefix
	publicKeyStr := hexutil.Encode(publicKeyBytes)

	// address with 0x prefix
	addressStr := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()

	return &Web3PasswordKey{
		PrivateKey: strings.ToLower(privateKeyStr),
		PublicKey:  strings.ToLower(publicKeyStr),
		Address:    strings.ToLower(addressStr),
	}, nil
}

func NewWalletFromMnemonic(mnemonic string) (*Web3PasswordWallet, error) {
	seedBytes, _ := bip39.NewSeedWithErrorChecking(mnemonic, "")

	masterKey, _ := hdkeychain.NewMaster(seedBytes, &chaincfg.MainNetParams)
	return &Web3PasswordWallet{
		mnemonic:  mnemonic,
		seed:      seedBytes,
		masterKey: masterKey,
		//fixIssue172: false || len(os.Getenv(issue179FixEnvar)) > 0,
		fixIssue172: true,
	}, nil
}
