/*
Copyright (C) 2024 Web3Password PTE. LTD.(Singapore UEN: 202333030C) - All Rights Reserved

Web3Password PTE. LTD.(Singapore UEN: 202333030C) holds the copyright of this file.

Unauthorized copying or redistribution of this file in binary forms via any medium is strictly prohibited.

For more information, please refer to https://www.web3password.com/web3password_license.txt
*/
package elasticsearch

import (
	"fmt"
	"log"
	"sync"
	"testing"
	"time"
)

func TestNewESClient(t *testing.T) {

}

func TestESClient_CreateIndex(t *testing.T) {
	//es, err := NewES()
	//if err != nil {
	//	log.Fatal(err)
	//}
	//indexName := "w3pindex"
	//es.CreateIndex(es.Client, indexName)
}

func TestES_IndexDocument(t *testing.T) {
	es, err := NewES()
	if err != nil {
		log.Fatal(err)
	}
	indexName := "w3pindex"
	data := []byte(`{
		"0xcbccd4d88cD498266F7F70Ab2F10fdf6B6B93606": [
			{
				"id": "1680166862000",
				"hash": "1a3f5abc86a419365b8be7f895471ff9abf3ea3ff9314ce18ac0f4d4580e0297"
			},
			{
				"id": "1680166862001",
				"hash": "2a3f5abc86a419365b8be7f895471ff9abf3ea3ff9314ce18ac0f4d4580e0298"
			},
			{
				"id": "1680166862002",
				"hash": "3a3f5abc86a419365b8be7f895471ff9abf3ea3ff9314ce18ac0f4d4580e0299"
			}
		]
	}`)

	numWorkers := 3500
	numWrites := 3500

	var wg sync.WaitGroup
	wg.Add(numWorkers)

	start := time.Now()

	for i := 0; i < numWorkers; i++ {
		fmt.Printf("numWorkers:%d \n", i)
		go func() {
			defer wg.Done()
			for j := 0; j < numWrites/numWorkers; j++ {
				fmt.Printf("numWrites:%d \n", j)
				es.IndexDocumentV2(es.Client, indexName, data)
			}
		}()
	}

	wg.Wait()

	elapsed := time.Since(start)
	log.Printf("done!, elapsed time：%s", elapsed)
}

//func TestES_IndexDocument(t *testing.T) {
//	es, err := NewES()
//	if err != nil {
//		log.Fatal(err)
//	}
//	indexName := "test-index"
//	es.CreateIndex(es.Client, indexName)
//
//	documentID := "1"
//	data := map[string]interface{}{
//		"title":   "Elasticsearch",
//		"content": "Elasticsearch",
//	}
//	es.IndexDocument(es.Client, indexName, documentID, data)
//
//	query := map[string]interface{}{
//		"query": map[string]interface{}{
//			"match": map[string]interface{}{
//				"title": "Elasticsearch",
//			},
//		},
//	}
//	searchResult := es.SearchDocuments(es.Client, indexName, query)
//	es.PrintSearchResult(searchResult)
//
//	//es.DeleteIndex(es.Client, indexName)
//}
