/*
Copyright (C) 2024 Web3Password PTE. LTD.(Singapore UEN: 202333030C) - All Rights Reserved

Web3Password PTE. LTD.(Singapore UEN: 202333030C) holds the copyright of this file.

Unauthorized copying or redistribution of this file in binary forms via any medium is strictly prohibited.

For more information, please refer to https://www.web3password.com/web3password_license.txt
*/
package kvrocks

import (
	"context"
	"fmt"
	"testing"
)

// go test or go test -v
// go test -run TestRocksRepo
func TestRocksRepo(t *testing.T) {
	addr := "127.0.0.1:6666"
	rocks := NewRocksRepo(addr)

	// Test Set and Get
	key := "testKey"
	value := "testValue"
	err := rocks.Set(key, value)
	if err != nil {
		t.Errorf("Error setting value: %v", err)
	}

	result, err := rocks.Get(key)
	if err != nil {
		t.Errorf("Error getting value: %v", err)
	}

	if result != value {
		t.Errorf("Expected value: %s, Got: %s", value, result)
	}

	// Test non-existent key
	nonExistentKey := "nonExistentKey"
	_, err = rocks.Get(nonExistentKey)
	if err == nil {
		t.Errorf("Expected error for non-existent key: %s", nonExistentKey)
	}
}

func TestRocksRepoViaTls(t *testing.T) {
	addr := "example.com:6379"
	certFile := "path/to/client.crt"
	keyFile := "path/to/client.key"
	caFile := "path/to/rootCA.pem"

	rocks := NewRocksRepoViaTls(addr, caFile, certFile, keyFile)

	// Ping the KVROCKS server to check the connection
	pong, err := rocks.Rdb.Ping(context.Background()).Result()
	if err != nil {
		fmt.Println("Error connecting to KVROCKS:", err)
		return
	}

	fmt.Println("Connected to KVROCKS:", pong)

	// Example: Set a key-value pair
	err = rocks.Rdb.Set(context.Background(), "example_key", "example_value", 0).Err()
	if err != nil {
		fmt.Println("Error setting key:", err)
		return
	}

	// Example: Get the value for a key
	value, err := rocks.Rdb.Get(context.Background(), "example_key").Result()
	if err != nil {
		fmt.Println("Error getting value:", err)
		return
	}

	fmt.Println("Value for 'example_key':", value)

	// Close the client connection when done
	if err := rocks.Rdb.Close(); err != nil {
		fmt.Println("Error closing connection:", err)
	}
}

func TestNewHaKvrocksRepo(t *testing.T) {
	addr := "example.com:6676"
	certFile := "path/to/client.crt"
	keyFile := "path/to/client.key"
	caFile := "path/to/rootCA.pem"
	password := ""
	enableTls := true

	rocks, err := NewHaKvrocksRepo(addr, password, caFile, certFile, keyFile, enableTls)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(rocks)

}
