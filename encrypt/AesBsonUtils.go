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
	"encoding/hex"
	"fmt"
	"gopkg.in/mgo.v2/bson"
	"io"
)

type Web3PasswordSymmetricCipherBsonStruct struct {
	AlgoSimpleName string `bson:"cn"`
	CipherBytes    []byte `bson:"ct"`
	IvBytes        []byte `bson:"iv"`
	AuthTagBytes   []byte `bson:"tg"`
	Id             int32  `bson:"id"`
	CompressMode   int32  `bson:"cm"`
}

func AesEncryptBson(keyBytes []byte, rawBytes []byte, id int32) ([]byte, error) {
	//fmt.Println("---------------------------- encrypt -------------------------")
	//fmt.Println("encrypt key hex: ", hex.EncodeToString(keyBytes))
	AlgoSimpleName := "ag"

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		panic(err.Error())
	}

	compressMode := 0 // 0 => no compress
	if len(rawBytes) < 2*1024*1024 {
		compressMode = 1 // 1 => gzip
	} else {
		testLength := 1 * 1024 * 1024
		testBytes := rawBytes[:testLength]
		testCmBytes, err := W3PGzip(testBytes)
		if err != nil {
			return nil, err
		}

		//fmt.Println("testCmBytesLength: ", len(testCmBytes))
		//fmt.Println("testLength: ", testLength)
		cmRatio := float32(len(testCmBytes)) / float32(testLength)
		if cmRatio <= 0.7 {
			compressMode = 1
		}
	}

	sealTargetBytes := rawBytes
	if compressMode == 1 {
		sealTargetBytes, err = W3PGzip(rawBytes)
		if err != nil {
			return nil, err
		}
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
	cipherBytes := aesgcm.Seal(nil, nonceBytes, sealTargetBytes, nil)
	cipherLength := len(cipherBytes)
	cipherBodyBytes := cipherBytes[:cipherLength-16]
	authTagBytes := cipherBytes[cipherLength-16:]
	//fmt.Println("finalLength: ", finalLength)
	//fmt.Println("cipherBodyBytes length: ", len(cipherBodyBytes))
	//fmt.Println("authTagBytes length: ", len(authTagBytes))
	//fmt.Println("encrypt cipherBytes len: ", len(cipherBytes))
	//fmt.Println("encrypt cipherBytes hex: ", hex.EncodeToString(cipherBytes))
	//
	//fmt.Println("key hex: ", hex.EncodeToString(keyBytes))
	//fmt.Println("nonce hex: ", hex.EncodeToString(nonceBytes))
	//fmt.Println("cipher hex: ", hex.EncodeToString(cipherBodyBytes))
	//fmt.Println("auth hex: ", hex.EncodeToString(authTagBytes))

	//fmt.Println("cipher base64: ", base64.StdEncoding.EncodeToString(cipherBodyBytes))
	//fmt.Println("nonce base64: ", base64.StdEncoding.EncodeToString(nonceBytes))
	//fmt.Println("auth base64: ", base64.StdEncoding.EncodeToString(authTagBytes))

	w3pCiperStruct := &Web3PasswordSymmetricCipherBsonStruct{
		AlgoSimpleName: AlgoSimpleName,
		CipherBytes:    cipherBodyBytes,
		IvBytes:        nonceBytes,
		AuthTagBytes:   authTagBytes,
		Id:             id,
		CompressMode:   int32(compressMode),
	}

	//fmt.Println("encrypt cipher body len: ", len(cipherBodyBytes))
	//fmt.Println("encrypt cipher body hex: ", hex.EncodeToString(cipherBodyBytes))
	//fmt.Println("encrypt iv len: ", len(nonceBytes))
	//fmt.Println("encrypt iv hex: ", hex.EncodeToString(nonceBytes))
	//fmt.Println("encrypt auth tag len: ", len(authTagBytes))
	//fmt.Println("encrypt auth tag hex: ", hex.EncodeToString(authTagBytes))

	finalBytes, err := bson.Marshal(w3pCiperStruct)
	if err != nil {
		return nil, err
	}

	return finalBytes, nil
}

func AesDecryptBson(keyBytes []byte, finalBytes []byte) ([]byte, error) {
	//fmt.Println("---------------------------- decrypt -------------------------")
	//fmt.Println("decrypt key hex: ", hex.EncodeToString(keyBytes))
	w3pCiperStruct := &Web3PasswordSymmetricCipherBsonStruct{}
	err := bson.Unmarshal(finalBytes, w3pCiperStruct)
	if err != nil {
		return nil, err
	}
	cipherBodyBytes := w3pCiperStruct.CipherBytes
	nonceBytes := w3pCiperStruct.IvBytes
	authTagBytes := w3pCiperStruct.AuthTagBytes
	compressMode := w3pCiperStruct.CompressMode
	//fmt.Printf("before cipherBodyBytes type is %T\n", cipherBodyBytes)
	//fmt.Printf("before w3pCiperStruct.CipherBytes type is %T\n", w3pCiperStruct.CipherBytes)
	//fmt.Printf("authTagBytes type is %T\n", authTagBytes)
	//fmt.Printf("w3pCiperStruct.AuthTagBytes type is %T\n", w3pCiperStruct.AuthTagBytes)

	//fmt.Println("decrypt cipher body len: ", len(cipherBodyBytes))
	//fmt.Println("decrypt cipher body hex: ", hex.EncodeToString(cipherBodyBytes))
	//fmt.Println("decrypt iv len: ", len(nonceBytes))
	//fmt.Println("decrypt iv hex: ", hex.EncodeToString(nonceBytes))
	//fmt.Println("decrypt auth tag len: ", len(authTagBytes))
	//fmt.Println("decrypt auth tag hex: ", hex.EncodeToString(authTagBytes))

	//cipherBodyBytes, _ = hex.DecodeString("1349e079ff352f1e3d02d3cbe33592b0ebe01bf3ecef83c2039c789dbfb68fafd383f5c4de8297251dda95a82110764ceed5b6d005e2a6435ec51b6fa19b325b76853cf4859cef60553563fca0b72794089a03513eba1d91383632c91f99d7d4077a4a618a60892c2826fca5f572ff8c")
	//nonceBytes, _ = hex.DecodeString("5bd11fb58d8e759e2caf56a7201d3cdc")
	//authTagBytes, _ = hex.DecodeString("3ccdfa5c26aae6a34e3bdd3f4c1348f0")

	// why need this ???
	cipherBodyBytes, _ = hex.DecodeString(hex.EncodeToString(cipherBodyBytes))
	//fmt.Printf("after cipherBodyBytes type is %T\n", cipherBodyBytes)
	nonceBytes, _ = hex.DecodeString(hex.EncodeToString(nonceBytes))
	authTagBytes, _ = hex.DecodeString(hex.EncodeToString(authTagBytes))
	//fmt.Printf("after authTagBytes type is %T\n", authTagBytes)
	//fmt.Println("2222222222")
	fmt.Println("decrypt cipher body len: ", len(cipherBodyBytes))
	fmt.Println("decrypt cipher body hex: ", hex.EncodeToString(cipherBodyBytes))
	//fmt.Println("decrypt iv len: ", len(nonceBytes))
	//fmt.Println("decrypt iv hex: ", hex.EncodeToString(nonceBytes))
	//fmt.Println("decrypt auth tag len: ", len(authTagBytes))
	//fmt.Println("decrypt auth tag hex: ", hex.EncodeToString(authTagBytes))

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, err
	}

	noneSize := 16
	aesgcm, err := cipher.NewGCMWithNonceSize(block, noneSize)

	if err != nil {
		return nil, err
	}

	//newCipherBodyBytes := cipherBodyBytes[:len(cipherBodyBytes)]
	//newAuthTagBytes := authTagBytes[:len(authTagBytes)]
	//cipherBytes := append(newCipherBodyBytes[:], newAuthTagBytes[:]...)

	cipherBytes := append(cipherBodyBytes[:], authTagBytes[:]...)
	//fmt.Printf("after cipherBytes type is %T\n", cipherBytes)
	//fmt.Println("decrypt cipherBytes len: ", len(cipherBytes))
	//fmt.Println("decrypt cipherBytes hex: ", hex.EncodeToString(cipherBytes))
	//cipherBytes, _ = hex.DecodeString(hex.EncodeToString(cipherBytes))
	//nonceBytes, _ = hex.DecodeString(hex.EncodeToString(nonceBytes))

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
