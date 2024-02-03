/*
Copyright (C) 2024 Web3Password PTE. LTD.(Singapore UEN: 202333030C) - All Rights Reserved

Web3Password PTE. LTD.(Singapore UEN: 202333030C) holds the copyright of this file.

Unauthorized copying or redistribution of this file in binary forms via any medium is strictly prohibited.

For more information, please refer to https://www.web3password.com/web3password_license.txt
*/
package encrypt

import (
	"crypto/rand"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
)

func Chacha20Encrypt(keyBytes []byte, rawBytes []byte, id int32) (*Web3PasswordSymmetricCipherStruct, error) {
	//fmt.Println("key hex: ", hex.EncodeToString(keyBytes))
	//fmt.Println("rawBytes hex: ", hex.EncodeToString(rawBytes))
	ahead, err := chacha20poly1305.New(keyBytes)
	if err != nil {
		return nil, err
	}

	// chacha20-poly1305 iv == 12 bytes
	noneSize := 12
	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	//nonce := make([]byte, aesgcm.NonceSize())
	nonceBytes := make([]byte, noneSize)
	if _, err := io.ReadFull(rand.Reader, nonceBytes); err != nil {
		return nil, err
	}

	// encrypt an prepend the nonce to the ciphertext before returning it
	finalBytes := ahead.Seal(nil, nonceBytes, rawBytes, nil)
	finalLength := len(finalBytes)
	cipherBodyBytes := finalBytes[:finalLength-16]
	authTagBytes := finalBytes[finalLength-16:]
	//fmt.Println("finalLength: ", finalLength)
	//fmt.Println("cipherBodyBytes length: ", len(cipherBodyBytes))
	//fmt.Println("authTagBytes length: ", len(authTagBytes))
	//
	//fmt.Println("key hex: ", hex.EncodeToString(keyBytes))
	//fmt.Println("nonce hex: ", hex.EncodeToString(nonceBytes))
	//fmt.Println("cipher hex: ", hex.EncodeToString(cipherBodyBytes))
	//fmt.Println("auth hex: ", hex.EncodeToString(authTagBytes))

	//fmt.Println("cipher base64: ", base64.StdEncoding.EncodeToString(cipherBodyBytes))
	//fmt.Println("nonce length: ", len(nonceBytes))
	//fmt.Println("nonce hex: ", hex.EncodeToString(nonceBytes))
	//fmt.Println("nonce base64: ", base64.StdEncoding.EncodeToString(nonceBytes))
	//fmt.Println("auth base64: ", base64.StdEncoding.EncodeToString(authTagBytes))

	w3pCiperStruct := &Web3PasswordSymmetricCipherStruct{
		AlgoSimpleName: "cp",
		CipherBytes:    cipherBodyBytes,
		IvBytes:        nonceBytes,
		AuthTagBytes:   authTagBytes,
		Id:             id,
	}

	return w3pCiperStruct, nil
}

func Chacha20Decrypt(keyBytes []byte, cipherBodyBytes []byte, nonceBytes []byte, authTagBytes []byte) ([]byte, error) {
	ahead, err := chacha20poly1305.New(keyBytes)
	if err != nil {
		return nil, err
	}

	cipherBytes := append(cipherBodyBytes[:], authTagBytes[:]...)

	return ahead.Open(nil, nonceBytes, cipherBytes, nil)
}
