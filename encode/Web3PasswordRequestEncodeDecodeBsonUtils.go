/*
Copyright (C) 2024 Web3Password PTE. LTD.(Singapore UEN: 202333030C) - All Rights Reserved

Web3Password PTE. LTD.(Singapore UEN: 202333030C) holds the copyright of this file.

Unauthorized copying or redistribution of this file in binary forms via any medium is strictly prohibited.

For more information, please refer to https://www.web3password.com/web3password_license.txt
*/

package encode

import (
	"encoding/binary"
	"errors"
	"gopkg.in/mgo.v2/bson"
)

var MaxRequestBodyLength = 100 * 1024 * 1024
var RequestVersion = "01"

/*
Request binary encoding format
big endian
version(2byte, Version number, fixed length, fixed as a string: 01)
+ dataLength(4 bytes, fixed length, integer, follow dataBinary lenth)
+ dataBinary(data byte stream data，bson structure)
*/
type Web3PasswordRequestBsonStruct struct {
	//VersionStr   string `bson:"versionStr,omitempty"`
	SignatureStr string `bson:"signature"`
	ParamsStr    string `bson:"params"`
	AppendData   []byte `bson:"data,omitempty"`
}

func Web3PasswordRequestBsonEncode(signatureStr string, paramsStr string, appendDataBytes []byte) ([]byte, error) {
	w3pReqStruct := &Web3PasswordRequestBsonStruct{
		SignatureStr: signatureStr,
		ParamsStr:    paramsStr,
		AppendData:   appendDataBytes,
	}

	dataBytes, err := bson.Marshal(w3pReqStruct)
	if err != nil {
		return nil, err
	}

	versionBytes := []byte(RequestVersion)

	dataLength := len(dataBytes)
	dataLengthBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(dataLengthBytes, uint32(dataLength))

	finalBytes := append(versionBytes, dataLengthBytes...)
	finalBytes = append(finalBytes, dataBytes...)

	return finalBytes, nil
}

func Web3PasswordRequestBsonDecode(finalBuffer []byte) (*Web3PasswordRequestBsonStruct, error) {
	w3pReqStruct := &Web3PasswordRequestBsonStruct{}

	start := 0
	versionBytes := finalBuffer[start : start+2]
	_ = string(versionBytes)

	start = start + 2
	dataLength1 := binary.BigEndian.Uint32(finalBuffer[start : start+4])
	dataLength := int(dataLength1)
	totalLength := dataLength + 2 + 4
	if totalLength < 1 || totalLength != len(finalBuffer) || totalLength > MaxRequestBodyLength {
		return nil, errors.New("totalLength is not legal")
	}

	start = start + 4
	dataBytes := finalBuffer[start : start+dataLength]
	err := bson.Unmarshal(dataBytes, w3pReqStruct)
	if err != nil {
		return nil, errors.New("data frame is not legal")
	}

	return w3pReqStruct, nil
}
