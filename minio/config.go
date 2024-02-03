/*
Copyright (C) 2024 Web3Password PTE. LTD.(Singapore UEN: 202333030C) - All Rights Reserved

Web3Password PTE. LTD.(Singapore UEN: 202333030C) holds the copyright of this file.

Unauthorized copying or redistribution of this file in binary forms via any medium is strictly prohibited.

For more information, please refer to https://www.web3password.com/web3password_license.txt
*/

package minio

type S3Config struct {
	Endpoints       []string `yaml:"endpoints"`
	AccessKeyId     string   `yaml:"access_key_id"`
	SecretAccessKey string   `yaml:"secret_access_key"`
	UseSsl          bool     `yaml:"use_ssl"`
	Bucket          string   `yaml:"bucket"`
}
