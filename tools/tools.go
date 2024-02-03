/*
Copyright (C) 2024 Web3Password PTE. LTD.(Singapore UEN: 202333030C) - All Rights Reserved

Web3Password PTE. LTD.(Singapore UEN: 202333030C) holds the copyright of this file.

Unauthorized copying or redistribution of this file in binary forms via any medium is strictly prohibited.

For more information, please refer to https://www.web3password.com/web3password_license.txt
*/

package tools

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"

	"log"
	"math/big"
	"os"
	"regexp"
	"strings"
)

func Verify() {
	//dataStr := `{\"addr\":\"0xB61312F74ce16Ccb678597FBA751d6253944347d\",\"timestamp\":1691469927,\"id\":\"75b8ec23-677d-457b-a3e7-4b9607d68e99\",\"credential\":\"password-data-from-niumc-1691469927\",\"nonce\":\"ee646d5f-0d32-46bb-be47-76bf7e8cebb6\"}`
	//sigStr := "5a9bffb58f03d16d7b4ec74fbeb1151f5740a535a7ca119f94e377f6daa601d448125980b950d4801126db17f2da2ee6a4aaa4a5528a927cc617bac1822420e21b"
	//addrStr := "0xB61312F74ce16Ccb678597FBA751d6253944347d"
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	message := []byte("Hello, Ethereum!")

	hash := crypto.Keccak256Hash(message)
	signature, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Original Message:", string(message))
	fmt.Println("Hash:", hash.Hex())
	fmt.Println("Signature:", signature)

	// Verify the signature
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("Error casting public key to ECDSA")
	}

	r, s := big.Int{}, big.Int{}
	sigLen := len(signature)
	r.SetBytes(signature[:(sigLen / 2)])
	s.SetBytes(signature[(sigLen / 2):])

	valid := ecdsa.Verify(publicKeyECDSA, hash.Bytes(), &r, &s)
	if valid {
		fmt.Println("Signature verified successfully")
	} else {
		fmt.Println("Signature verification failed")
	}

}

func BizVerifySignature(sigStr string, dataBytes []byte, addrStr string) error {
	if len([]rune(sigStr)) < 2 || len(dataBytes) == 0 {
		return fmt.Errorf("invalid signstr or data length not equal")
	}

	signature, _ := hex.DecodeString(sigStr[2:])
	dataHash := crypto.Keccak256Hash(dataBytes)

	if len(signature) != 65 {
		return fmt.Errorf("invalid signature length: %d", len(signature))
	}

	if signature[64] != 27 && signature[64] != 28 {
		return fmt.Errorf("invalid recovery id: %d not equal 27 or 28", signature[64])
	}

	signature[64] -= 27
	pubKeyRaw, err := crypto.Ecrecover(dataHash.Bytes(), signature)
	if err != nil {
		return fmt.Errorf("Ecrecover failed %s", err.Error())
	}

	pubKey, err := crypto.UnmarshalPubkey(pubKeyRaw)
	if err != nil {
		return fmt.Errorf("UnmarshalPubkey failed: %s", err.Error())
	}

	recoveredAddr := crypto.PubkeyToAddress(*pubKey)
	if strings.ToLower(addrStr) != strings.ToLower(recoveredAddr.String()) {
		msg := fmt.Sprintf("rawAddr: %s, recoveryAddr: %s\n", strings.ToLower(addrStr), strings.ToLower(recoveredAddr.String()))
		return fmt.Errorf("signature error " + msg)
	}
	return nil
}

func IsValidAddress(address string) bool {
	re := regexp.MustCompile("^0x[0-9a-fA-F]{40}$")
	return re.MatchString(address)
}

func CheckHash(data []byte, hash string) bool {
	hashObj := sha256.New()
	hashObj.Write(data)
	hashByte := hashObj.Sum(nil)
	hashStr := hex.EncodeToString(hashByte)
	return strings.ToLower(hash) == strings.ToLower(hashStr)
}

func GetHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return uuid.NewString()
	}
	return hostname
}
func CompareHash(data []byte, hash string) (isEqual bool, serverHash string) {
	hashObj := sha256.New()
	hashObj.Write(data)
	hashByte := hashObj.Sum(nil)
	hashStr := hex.EncodeToString(hashByte)
	return strings.ToLower(hash) == strings.ToLower(hashStr), hashStr
}

// TLSClientConfig load tls client config
func TLSClientConfig(ca, crt, key string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(crt, key)
	if err != nil {
		return nil, err
	}
	caCert, err := os.ReadFile(ca)
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caCertPool,
		InsecureSkipVerify: false,
	}, nil
}

// TLSServerConfig load tls client config
func TLSServerConfig(ca, crt, key string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(crt, key)
	if err != nil {
		return nil, err
	}
	caCert, err := os.ReadFile(ca)
	if err != nil {
		return nil, err
	}
	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(caCert); !ok {
		return nil, fmt.Errorf("AppendCertsFromPEM fail")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert, // NOTE: this is optional!
		ClientCAs:    certPool,
	}, nil

}
