/*
Copyright (C) 2024 Web3Password PTE. LTD.(Singapore UEN: 202333030C) - All Rights Reserved

Web3Password PTE. LTD.(Singapore UEN: 202333030C) holds the copyright of this file.

Unauthorized copying or redistribution of this file in binary forms via any medium is strictly prohibited.

For more information, please refer to https://www.web3password.com/web3password_license.txt
*/
package elasticsearch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/elastic/go-elasticsearch/v7"
	"github.com/elastic/go-elasticsearch/v7/esapi"
	"log"
)

type ES struct {
	Client *elasticsearch.Client
}

func NewES() (*ES, error) {
	//cfg := elasticsearch.Config{
	//	Addresses: []string{"http://localhost:9200"},
	//}
	//esClient, err := elasticsearch.NewClient(cfg)
	esClient, err := elasticsearch.NewDefaultClient()
	if err != nil {
		log.Fatal(err)
	}

	return &ES{
		Client: esClient,
	}, nil
}

func (es *ES) CreateIndex(client *elasticsearch.Client, indexName string) {
	req := esapi.IndicesCreateRequest{
		Index: indexName,
	}

	res, err := req.Do(context.Background(), client)
	if err != nil {
		log.Fatal(err)
	}

	defer res.Body.Close()

	if res.IsError() {
		log.Printf("Error creating index: %s", res.Status())
	} else {
		log.Printf("Index created: %s", indexName)
	}
}

func (es *ES) DeleteIndex(client *elasticsearch.Client, indexName string) {
	req := esapi.IndicesDeleteRequest{
		Index: []string{indexName},
	}

	res, err := req.Do(context.Background(), client)
	if err != nil {
		log.Fatal(err)
	}

	defer res.Body.Close()

	if res.IsError() {
		log.Fatalf("Error deleting index: %s", res.Status())
	} else {
		log.Printf("Index deleted: %s", indexName)
	}
}

func (es *ES) IndexDocument(client *elasticsearch.Client, indexName, documentID string, data map[string]interface{}) {
	body, err := json.Marshal(data)
	if err != nil {
		log.Fatal(err)
	}

	req := esapi.IndexRequest{
		Index:      indexName,
		DocumentID: documentID,
		Body:       bytes.NewReader(body),
		Refresh:    "true",
	}

	res, err := req.Do(context.Background(), client)
	if err != nil {
		log.Fatal(err)
	}

	defer res.Body.Close()

	if res.IsError() {
		log.Fatalf("Error indexing document: %s", res.Status())
	} else {
		log.Printf("Document indexed: %s", documentID)
	}
}

func (es *ES) SearchDocuments(client *elasticsearch.Client, indexName string, query map[string]interface{}) map[string]interface{} {
	body, err := json.Marshal(query)
	if err != nil {
		log.Fatal(err)
	}
	req := esapi.SearchRequest{
		Index: []string{indexName},
		Body:  bytes.NewReader(body),
	}

	res, err := req.Do(context.Background(), client)
	if err != nil {
		log.Fatal(err)
	}

	defer res.Body.Close()

	if res.IsError() {
		log.Fatalf("Error searching documents: %s", res.Status())
	} else {
		var result map[string]interface{}
		if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
			log.Fatal(err)
		}
		return result
	}

	return nil
}

func (es *ES) PrintSearchResult(result map[string]interface{}) {
	if result != nil {
		fmt.Println("Search Result:")
		fmt.Println("----------------")
		encoded, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(encoded))
		fmt.Println("----------------")
	} else {
		fmt.Println("No search result.")
	}
}

func (es *ES) IndexDocumentV2(client *elasticsearch.Client, indexName string, data []byte) {
	//body, err := json.Marshal(data)
	//if err != nil {
	//	log.Fatal(err)
	//}

	//fmt.Printf("%+v", string(data))

	req := esapi.IndexRequest{
		Index: indexName,
		//DocumentID: documentID,
		Body:    bytes.NewReader(data),
		Refresh: "true",
	}

	//fmt.Printf("%+v", req)

	res, err := req.Do(context.Background(), client)
	if err != nil {
		log.Fatal(err)
	}

	defer res.Body.Close()

	if res.IsError() {
		log.Fatalf("Error indexing document: %s", res.Status())

	} else {
		//log.Printf("Document indexed: %s", documentID)
		//log.Printf("Document indexed: %#v", res)
	}
}
