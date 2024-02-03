/*
Copyright (C) 2024 Web3Password PTE. LTD.(Singapore UEN: 202333030C) - All Rights Reserved

Web3Password PTE. LTD.(Singapore UEN: 202333030C) holds the copyright of this file.

Unauthorized copying or redistribution of this file in binary forms via any medium is strictly prohibited.

For more information, please refer to https://www.web3password.com/web3password_license.txt
*/
package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"gopkg.in/mgo.v2/bson"
	"io"
)

/*
https://pkg.go.dev/github.com/decred/dcrd/dcrec/secp256k1/v4#example-package-EncryptDecryptMessage
*/
type Web3PasswordAsymmetricCipherStruct struct {
	AlgoSimpleName          string `bson:"cn"`
	CipherBytes             []byte `bson:"ct"`
	IvBytes                 []byte `bson:"iv"`
	AuthTagBytes            []byte `bson:"tg"`
	EphemeralPublicKeyBytes []byte `bson:"ep"`
	MacBytes                []byte `bson:"mc"`
	Id                      int32  `bson:"id"`
	CompressMode            int32  `bson:"cm"`
}

func AesAsymmetricEncrypt(publicKeyBytes []byte, rawBytes []byte, id int32) ([]byte, error) {
	//fmt.Println("key hex: ", hex.EncodeToString(keyBytes))
	//fmt.Println("rawBytes hex: ", hex.EncodeToString(rawBytes))
	compressMode := 1 // 1 => gzip
	sealTargetBytes, err := W3PGzip(rawBytes)
	if err != nil {
		return nil, err
	}

	publicKey, err := secp256k1.ParsePubKey(publicKeyBytes)
	if err != nil {
		return nil, err
	}
	ephemeralPrivateKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}

	ephemeralPublicKeyBytes := ephemeralPrivateKey.PubKey().SerializeUncompressed()

	// Using ECDHE, derive a shared symmetric key for encryption of the plaintext.
	//cipherKeyArray := sha256.Sum256(secp256k1.GenerateSharedSecret(ephemeralPrivateKey, publicKey))
	cipherKeyArray := sha512.Sum512(secp256k1.GenerateSharedSecret(ephemeralPrivateKey, publicKey))
	cipherKey := cipherKeyArray[:32]

	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		return nil, err
	}

	noneSize := 16
	aesgcm, err := cipher.NewGCMWithNonceSize(block, noneSize)
	if err != nil {
		return nil, err
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	//nonce := make([]byte, aesgcm.NonceSize())
	nonceBytes := make([]byte, noneSize)
	if _, err := io.ReadFull(rand.Reader, nonceBytes); err != nil {
		return nil, err
	}

	// encrypt an prepend the nonce to the ciphertext before returning it
	finalBytes := aesgcm.Seal(nil, nonceBytes, sealTargetBytes, nil)
	finalLength := len(finalBytes)
	cipherBodyBytes := finalBytes[:finalLength-16]
	authTagBytes := finalBytes[finalLength-16:]
	//fmt.Println("finalLength: ", finalLength)
	//fmt.Println("cipherBodyBytes length: ", len(cipherBodyBytes))
	//fmt.Println("authTagBytes length: ", len(authTagBytes))
	//
	//fmt.Println("asymmetric key hex: ", hex.EncodeToString(cipherKey))
	//fmt.Println("nonce hex: ", hex.EncodeToString(nonceBytes))
	//fmt.Println("cipher hex: ", hex.EncodeToString(cipherBodyBytes))
	//fmt.Println("auth hex: ", hex.EncodeToString(authTagBytes))

	//fmt.Println("cipher base64: ", base64.StdEncoding.EncodeToString(cipherBodyBytes))
	//fmt.Println("nonce base64: ", base64.StdEncoding.EncodeToString(nonceBytes))
	//fmt.Println("auth base64: ", base64.StdEncoding.EncodeToString(authTagBytes))
	//fmt.Println("ephemeral publickey base64: ", base64.StdEncoding.EncodeToString(ephemeralPublicKeyBytes))

	w3pCiperStruct := &Web3PasswordAsymmetricCipherStruct{
		AlgoSimpleName:          "ag",
		CipherBytes:             cipherBodyBytes,
		IvBytes:                 nonceBytes,
		AuthTagBytes:            authTagBytes,
		EphemeralPublicKeyBytes: ephemeralPublicKeyBytes,
		Id:                      id,
		CompressMode:            int32(compressMode), // 1 => gzip
	}

	outputBytes, _ := bson.Marshal(w3pCiperStruct)
	return outputBytes, nil
}

// func AesAsymmetricDecrypt(privateKeyBytes []byte, cipherBodyBytes []byte, nonceBytes []byte, authTagBytes []byte, ephemeralPublicKeyBytes []byte) ([]byte, error) {
func AesAsymmetricDecrypt(privateKeyBytes []byte, finalBytes []byte) ([]byte, error) {
	privateKey := secp256k1.PrivKeyFromBytes(privateKeyBytes)

	w3pCiperStruct := &Web3PasswordAsymmetricCipherStruct{}
	err := bson.Unmarshal(finalBytes, w3pCiperStruct)
	if err != nil {
		return nil, err
	}

	cipherBodyBytes := w3pCiperStruct.CipherBytes
	nonceBytes := w3pCiperStruct.IvBytes
	authTagBytes := w3pCiperStruct.AuthTagBytes
	ephemeralPublicKeyBytes := w3pCiperStruct.EphemeralPublicKeyBytes
	compressMode := w3pCiperStruct.CompressMode

	// why need this ???
	cipherBodyBytes, _ = hex.DecodeString(hex.EncodeToString(cipherBodyBytes))
	nonceBytes, _ = hex.DecodeString(hex.EncodeToString(nonceBytes))
	authTagBytes, _ = hex.DecodeString(hex.EncodeToString(authTagBytes))
	ephemeralPublicKeyBytes, _ = hex.DecodeString(hex.EncodeToString(ephemeralPublicKeyBytes))

	ephemeralPublicKey, _ := secp256k1.ParsePubKey(ephemeralPublicKeyBytes)

	//cipherPriateKeyBytesArray := sha256.Sum256(secp256k1.GenerateSharedSecret(privateKey, ephemeralPublicKey))
	cipherPriateKeyBytesArray := sha512.Sum512(secp256k1.GenerateSharedSecret(privateKey, ephemeralPublicKey))
	cipherPriateKeyBytes := cipherPriateKeyBytesArray[:32]

	block, err := aes.NewCipher(cipherPriateKeyBytes)
	if err != nil {
		return nil, err
	}

	noneSize := 16
	aesgcm, err := cipher.NewGCMWithNonceSize(block, noneSize)

	if err != nil {
		return nil, err
	}

	cipherBytes := append(cipherBodyBytes[:], authTagBytes[:]...)

	bytesCompressed, err := aesgcm.Open(nil, nonceBytes, cipherBytes, nil)
	if err != nil {
		return nil, err
	}

	if compressMode == 1 {
		bytesUmpressed, err := W3PUngzip(bytesCompressed)
		if err != nil {
			return nil, err
		}

		return bytesUmpressed, nil
	} else {
		return bytesCompressed, nil
	}
}
