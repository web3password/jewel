/*
Copyright (C) 2024 Web3Password PTE. LTD.(Singapore UEN: 202333030C) - All Rights Reserved

Web3Password PTE. LTD.(Singapore UEN: 202333030C) holds the copyright of this file.

Unauthorized copying or redistribution of this file in binary forms via any medium is strictly prohibited.

For more information, please refer to https://www.web3password.com/web3password_license.txt
*/

package minio

import (
	"bytes"
	"fmt"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/web3password/jewel/tools"
	"golang.org/x/exp/rand"
	"golang.org/x/net/context"
	"io"
	"time"
)

type MinioRepo struct {
	config S3Config
}

func NewMinioRepo(config S3Config) *MinioRepo {
	return &MinioRepo{
		config: config,
	}
}

func (r *MinioRepo) GetClient() (*minio.Client, error) {
	s3Conf := r.config
	endpoints := s3Conf.Endpoints

	rand.Seed(uint64(time.Now().UnixNano()))
	rand.Shuffle(len(endpoints), func(i, j int) {
		endpoints[i], endpoints[j] = endpoints[j], endpoints[i]
	})

	for _, endpoint := range endpoints {
		// Initialize minio client
		client, err := minio.New(endpoint, &minio.Options{
			Creds:  credentials.NewStaticV4(s3Conf.AccessKeyId, s3Conf.SecretAccessKey, ""),
			Secure: s3Conf.UseSsl,
		})
		if err != nil {
			fmt.Printf("time: %s, endpoint: %s, new minio client error: %v. Try using next node.\n", tools.GetDatetimeMilSec(), endpoint, err)
			continue
		} else {
			// check if minio server is online or not
			fmt.Printf("Deubug, time: %s, endpoint: %s, before health check.\n", tools.GetDatetimeMilSec(), endpoint)
			cancel, err := client.HealthCheck(1 * time.Second)
			if err == nil {
				defer cancel()
			}
			if client.IsOnline() {
				fmt.Printf("Deubug, time: %s, endpoint: %s, after health check. The current node will be used.\n", tools.GetDatetimeMilSec(), endpoint)
				return client, nil
			} else {
				fmt.Printf("time: %s, endpoint: %s, minio client is offline. Try using next node.Try using next node.\n", tools.GetDatetimeMilSec(), endpoint)
				// minio server not online, use next endpoint
				continue
			}
		}
	}
	fmt.Printf("Error, time:%s, no minio node is online", tools.GetDatetimeMilSec())
	return nil, fmt.Errorf("error, time:%s, no minio node is online", tools.GetDatetimeMilSec())
}

func (r *MinioRepo) SaveObject(ctx context.Context, bucketName, filename string, data []byte) (*minio.UploadInfo, error) {
	client, err := r.GetClient()
	if err != nil {
		return nil, fmt.Errorf("get minio client error")
	}
	uploadInfo, err := client.PutObject(ctx, bucketName, filename, bytes.NewReader(data), int64(len(data)), minio.PutObjectOptions{})
	return &uploadInfo, err
}

func (r *MinioRepo) ReadObject(ctx context.Context, bucket string, objectName string) ([]byte, error) {
	client, err := r.GetClient()
	if err != nil {
		return nil, err
	}
	reader, err := client.GetObject(ctx, bucket, objectName, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("minio GetObject error, objectName: %r, err: %r", objectName, err)
	}

	fileContent, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("minio GetObject ReadAll error, objectName: %r, err: %r", objectName, err)
	}

	err = reader.Close()
	if err != nil {
		return nil, fmt.Errorf("minio Close local file error, objectName: %r, err: %r", objectName, err)
	}
	return fileContent, nil
}

func (r *MinioRepo) ReadObjectLocal(ctx context.Context, bucket, objectName, filePath string) error {
	client, err := r.GetClient()
	if err != nil {
		return fmt.Errorf("get minio client error")
	}
	return client.FGetObject(ctx, bucket, objectName, filePath, minio.GetObjectOptions{})
}

func (r *MinioRepo) StatObject(ctx context.Context, bucket string, objectName string) (*minio.ObjectInfo, error) {
	client, err := r.GetClient()
	if err != nil {
		return nil, fmt.Errorf("get minio client error")
	}
	objectInfo, err := client.StatObject(ctx, bucket, objectName, minio.StatObjectOptions{})
	if err != nil {
		return nil, err
	}
	return &objectInfo, nil
}

func (r *MinioRepo) RemoveObject(ctx context.Context, bucket string, objectName string) error {
	client, err := r.GetClient()
	if err != nil {
		return fmt.Errorf("get minio client error")
	}
	err = client.RemoveObject(ctx, bucket, objectName, minio.RemoveObjectOptions{
		ForceDelete: true,
	})
	return err
}
