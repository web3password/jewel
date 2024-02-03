/*
Copyright (C) 2024 Web3Password PTE. LTD.(Singapore UEN: 202333030C) - All Rights Reserved

Web3Password PTE. LTD.(Singapore UEN: 202333030C) holds the copyright of this file.

Unauthorized copying or redistribution of this file in binary forms via any medium is strictly prohibited.

For more information, please refer to https://www.web3password.com/web3password_license.txt
*/

package kvrocks

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/go-redis/redis/v8"
	"github.com/web3password/jewel/tools"
	"os"
)

// https://kvrocks.apache.org/docs/supported-commands
type RocksRepo struct {
	Rdb *redis.Client
}

func NewHaKvrocksRepo(addr, password, tlsCa, tlsCrt, tlsKey string, enableTls bool) (*RocksRepo, error) {
	var rdb *redis.Client
	repo := &RocksRepo{}
	if enableTls {
		tlsConfig, err := tools.TLSClientConfig(tlsCa, tlsCrt, tlsKey)
		if err != nil {
			return nil, err
		}
		rdb = redis.NewClient(&redis.Options{
			Addr:      addr,
			Password:  password,
			TLSConfig: tlsConfig,
		})
	} else {
		rdb = redis.NewClient(&redis.Options{
			Addr:     addr,
			Password: password,
		})
	}

	if err := rdb.Ping(context.Background()).Err(); err != nil {
		return nil, err
	}
	repo.Rdb = rdb

	return repo, nil
}

func NewRocksRepo(addr string) *RocksRepo {
	rdb := redis.NewClient(&redis.Options{
		Addr: addr,
	})

	return &RocksRepo{
		Rdb: rdb,
	}
}

func NewRocksRepoViaTls(addr, caFile, certFile, keyFile string) *RocksRepo {
	// Load client certificate and key
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		panic("Error loading client certificate, error: " + err.Error())
	}

	// Load root CA certificate
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		panic("Error loading root CA certificate, error: " + err.Error())
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create a new Redis client with TLS
	rdb := redis.NewClient(&redis.Options{
		Addr: addr,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: false,
			Certificates:       []tls.Certificate{cert},
			RootCAs:            caCertPool,
		},
	})

	return &RocksRepo{
		Rdb: rdb,
	}
}

func (rocks *RocksRepo) Incr(key string) (int64, error) {
	ctx := context.Background()
	cmd := rocks.Rdb.Incr(ctx, key)
	if cmd.Err() != nil {
		return 0, cmd.Err()
	}
	return cmd.Val(), nil
}

func (rocks *RocksRepo) Set(key string, val interface{}) error {
	ctx := context.Background()
	err := rocks.Rdb.Set(ctx, key, val, 0).Err()
	if err != nil {
		return err
	}
	return nil
}

func (rocks *RocksRepo) Get(key string) (string, error) {
	ctx := context.Background()
	val, err := rocks.Rdb.Get(ctx, key).Result()
	if err != nil {
		return "", err
	}
	return val, nil
}

func (rocks *RocksRepo) Del(key string) (int64, error) {
	ctx := context.Background()
	val, err := rocks.Rdb.Del(ctx, key).Result()
	if err != nil {
		return val, err
	}
	return val, nil
}

func (rocks *RocksRepo) MGet(keys ...string) ([]interface{}, error) {
	ctx := context.Background()
	return rocks.Rdb.MGet(ctx, keys...).Result()
}

func (rocks *RocksRepo) HMSet(address string, addrMap interface{}) (bool, error) {
	ctx := context.Background()
	result, err := rocks.Rdb.HMSet(ctx, address, addrMap).Result()
	if err != nil {
		return false, err
	}

	return result, nil
}

func (rocks *RocksRepo) HMGet(address string, id []string) ([]interface{}, error) {
	ctx := context.Background()
	result, err := rocks.Rdb.HMGet(ctx, address, id...).Result()
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (rocks *RocksRepo) HGetAll(address string) (map[string]string, error) {
	ctx := context.Background()
	result, err := rocks.Rdb.HGetAll(ctx, address).Result()
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (rocks *RocksRepo) HDel(address string, addrMap string) (int64, error) {
	ctx := context.Background()
	result, err := rocks.Rdb.HDel(ctx, address, addrMap).Result()
	if err != nil {
		return result, err
	}

	return result, nil
}

func (rocks *RocksRepo) HKeys(address string) ([]string, error) {
	ctx := context.Background()
	val, err := rocks.Rdb.HKeys(ctx, address).Result()
	if err != nil {
		return nil, err
	}

	return val, nil
}

func (rocks *RocksRepo) HGet(address string, addrId string) (string, error) {
	ctx := context.Background()
	val, err := rocks.Rdb.HGet(ctx, address, addrId).Result()
	if err != nil {
		return "", err
	}

	return val, nil
}

func (rocks *RocksRepo) SMembers(primaryAddr string) ([]string, error) {
	ctx := context.Background()
	val, err := rocks.Rdb.SMembers(ctx, primaryAddr).Result()
	if err != nil {
		return nil, err
	}

	return val, nil
}

func (rocks *RocksRepo) SAdd(primaryAddr string, addrIndex string) (int64, error) {
	ctx := context.Background()
	val, err := rocks.Rdb.SAdd(ctx, primaryAddr, addrIndex).Result()
	if err != nil {
		return val, err
	}

	return val, nil
}

func (rocks *RocksRepo) SRem(primaryAddr string, addrIndex string) (int64, error) {
	ctx := context.Background()
	val, err := rocks.Rdb.SRem(ctx, primaryAddr, addrIndex).Result()
	if err != nil {
		return val, err
	}

	return val, nil
}

func (rocks *RocksRepo) SIsMember(primaryAddr string, addrIndex string) (bool, error) {
	ctx := context.Background()
	val, err := rocks.Rdb.SIsMember(ctx, primaryAddr, addrIndex).Result()
	if err != nil {
		return false, err
	}

	return val, nil
}

func (rocks *RocksRepo) SCan(primaryAddr string, count int64) ([]string, error) {
	ctx := context.Background()
	var cursor uint64
	var keys []string
	pattern := fmt.Sprintf("%s*", primaryAddr)
	for {
		var err error
		var scanKeys []string
		scanKeys, cursor, err = rocks.Rdb.Scan(ctx, cursor, pattern, count).Result()
		if err != nil {
			fmt.Println("Error scanning keys:", err)
			return nil, nil
		}

		keys = append(keys, scanKeys...)
		if cursor == 0 {
			break
		}
	}

	return keys, nil
}
