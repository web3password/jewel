/*
Copyright (C) 2024 Web3Password PTE. LTD.(Singapore UEN: 202333030C) - All Rights Reserved

Web3Password PTE. LTD.(Singapore UEN: 202333030C) holds the copyright of this file.

Unauthorized copying or redistribution of this file in binary forms via any medium is strictly prohibited.

For more information, please refer to https://www.web3password.com/web3password_license.txt
*/

package rabbitmq

type Config struct {
	Addr      string    `json:"addr"`
	EnableTLS bool      `json:"enable_tls"`
	TLSConfig ClientTLS `json:"tls_config"`
}

type ClientTLS struct {
	Ca  string `json:"ca"`
	Crt string `json:"crt"`
	Key string `json:"key"`
}

type RunTimeConfig struct {
	Host      string    `json:"host"`
	Scheme    string    `json:"scheme"`
	EnableTLS bool      `json:"enable_tls"`
	TLSConfig ClientTLS `json:"tls_config"`
}
