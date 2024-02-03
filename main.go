/*
Copyright (C) 2024 Web3Password PTE. LTD.(Singapore UEN: 202333030C) - All Rights Reserved

Web3Password PTE. LTD.(Singapore UEN: 202333030C) holds the copyright of this file.

Unauthorized copying or redistribution of this file in binary forms via any medium is strictly prohibited.

For more information, please refer to https://www.web3password.com/web3password_license.txt
*/

package main

import (
	"flag"
	"fmt"
	"github.com/jaevor/go-nanoid"
	"github.com/web3password/jewel/kvrocks"
	"log"
	"strings"
	"sync"
	"time"
)

var flagNumWorkers int
var flagNumWrites int
var flagAddr string

func init() {
	flag.IntVar(&flagNumWorkers, "numWorkers", 100, "help message for flagname")
	flag.IntVar(&flagNumWrites, "numWrites", 100, "help message for flagname")
	flag.StringVar(&flagAddr, "addr", "45.12.135.114:6666", "help message for flagname")
}

func main() {
	flag.Parse()
	fmt.Printf("numWorkers:%d, numWrites:%d \n", flagNumWorkers, flagNumWrites)
	data := string(`"eyIweGNiY2NkNGQ4OGNENDk4MjY2RjdGNzBBYjJGMTBmZGY2QjZCOTM2MDYiOiBbIjE2ODAxNjY4NjIwMDEiLCAiMTY4MDE2Njg2MjAwMiIsICIxNjgwMTY2ODYyMDAzIl0sIjB4Y2JjY2Q0ZDg4Y0Q0OTgyNjZGN0Y3MEFiMkYxMGZkZjZCNkI5MzYwNyI6IFsiMTY4MDE2Njg2MjAwNCIsICIxNjgwMTY2ODYyMDA1IiwgIjE2ODAxNjY4NjIwMDYiXX0=eyIweGNiY2NkNGQ4OGNENDk4MjY2RjdGNzBBYjJGMTBmZGY2QjZCOTM2MDYiOiBbIjE2ODAxNjY4NjIwMDEiLCAiMTY4MDE2Njg2MjAwMiIsICIxNjgwMTY2ODYyMDAzIl0sIjB4Y2JjY2Q0ZDg4Y0Q0OTgyNjZGN0Y3MEFiMkYxMGZkZjZCNkI5MzYwNyI6IFsiMTY4MDE2Njg2MjAwNCIsICIxNjgwMTY2ODYyMDA1IiwgIjE2ODAxNjY4NjIwMDYiXX0=eyIweGNiY2NkNGQ4OGNENDk4MjY2RjdGNzBBYjJGMTBmZGY2QjZCOTM2MDYiOiBbIjE2ODAxNjY4NjIwMDEiLCAiMTY4MDE2Njg2MjAwMiIsICIxNjgwMTY2ODYyMDAzIl0sIjB4Y2JjY2Q0ZDg4Y0Q0OTgyNjZGN0Y3MEFiMkYxMGZkZjZCNkI5MzYwNyI6IFsiMTY4MDE2Njg2MjAwNCIsICIxNjgwMTY2ODYyMDA1IiwgIjE2ODAxNjY4NjIwMDYiXX0=eyIweGNiY2NkNGQ4OGNENDk4MjY2RjdGNzBBYjJGMTBmZGY2QjZCOTM2MDYiOiBbIjE2ODAxNjY4NjIwMDEiLCAiMTY4MDE2Njg2MjAwMiIsICIxNjgwMTY2ODYyMDAzIl0sIjB4Y2JjY2Q0ZDg4Y0Q0OTgyNjZGN0Y3MEFiMkYxMGZkZjZCNkI5MzYwNyI6IFsiMTY4MDE2Njg2MjAwNCIsICIxNjgwMTY2ODYyMDA1IiwgIjE2ODAxNjY4NjIwMDYiXX0=eyIweGNiY2NkNGQ4OGNENDk4MjY2RjdGNzBBYjJGMTBmZGY2QjZCOTM2MDYiOiBbIjE2ODAxNjY4NjIwMDEiLCAiMTY4MDE2Njg2MjAwMiIsICIxNjgwMTY2ODYyMDAzIl0sIjB4Y2JjY2Q0ZDg4Y0Q0OTgyNjZGN0Y3MEFiMkYxMGZkZjZCNkI5MzYwNyI6IFsiMTY4MDE2Njg2MjAwNCIsICIxNjgwMTY2ODYyMDA1IiwgIjE2ODAxNjY4NjIwMDYiXX0=eyIweGNiY2NkNGQ4OGNENDk4MjY2RjdGNzBBYjJGMTBmZGY2QjZCOTM2MDYiOiBbIjE2ODAxNjY4NjIwMDEiLCAiMTY4MDE2Njg2MjAwMiIsICIxNjgwMTY2ODYyMDAzIl0sIjB4Y2JjY2Q0ZDg4Y0Q0OTgyNjZGN0Y3MEFiMkYxMGZkZjZCNkI5MzYwNyI6IFsiMTY4MDE2Njg2MjAwNCIsICIxNjgwMTY2ODYyMDA1IiwgIjE2ODAxNjY4NjIwMDYiXX0=eyIweGNiY2NkNGQ4OGNENDk4MjY2RjdGNzBBYjJGMTBmZGY2QjZCOTM2MDYiOiBbIjE2ODAxNjY4NjIwMDEiLCAiMTY4MDE2Njg2MjAwMiIsICIxNjgwMTY2ODYyMDAzIl0sIjB4Y2JjY2Q0ZDg4Y0Q0OTgyNjZGN0Y3MEFiMkYxMGZkZjZCNkI5MzYwNyI6IFsiMTY4MDE2Njg2MjAwNCIsICIxNjgwMTY2ODYyMDA1IiwgIjE2ODAxNjY4NjIwMDYiXX0=eyIweGNiY2NkNGQ4OGNENDk4MjY2RjdGNzBBYjJGMTBmZGY2QjZCOTM2MDYiOiBbIjE2ODAxNjY4NjIwMDEiLCAiMTY4MDE2Njg2MjAwMiIsICIxNjgwMTY2ODYyMDAzIl0sIjB4Y2JjY2Q0ZDg4Y0Q0OTgyNjZGN0Y3MEFiMkYxMGZkZjZCNkI5MzYwNyI6IFsiMTY4MDE2Njg2MjAwNCIsICIxNjgwMTY2ODYyMDA1IiwgIjE2ODAxNjY4NjIwMDYiXX0=eyIweGNiY2NkNGQ4OGNENDk4MjY2RjdGNzBBYjJGMTBmZGY2QjZCOTM2MDYiOiBbIjE2ODAxNjY4NjIwMDEiLCAiMTY4MDE2Njg2MjAwMiIsICIxNjgwMTY2ODYyMDAzIl0sIjB4Y2JjY2Q0ZDg4Y0Q0OTgyNjZGN0Y3MEFiMkYxMGZkZjZCNkI5MzYwNyI6IFsiMTY4MDE2Njg2MjAwNCIsICIxNjgwMTY2ODYyMDA1IiwgIjE2ODAxNjY4NjIwMDYiXX0=eyIweGNiY2NkNGQ4OGNENDk4MjY2RjdGNzBBYjJGMTBmZGY2QjZCOTM2MDYiOiBbIjE2ODAxNjY4NjIwMDEiLCAiMTY4MDE2Njg2MjAwMiIsICIxNjgwMTY2ODYyMDAzIl0sIjB4Y2JjY2Q0ZDg4Y0Q0OTgyNjZGN0Y3MEFiMkYxMGZkZjZCNkI5MzYwNyI6IFsiMTY4MDE2Njg2MjAwNCIsICIxNjgwMTY2ODYyMDA1IiwgIjE2ODAxNjY4NjIwMDYiXX0=eyIweGNiY2NkNGQ4OGNENDk4MjY2RjdGNzBBYjJGMTBmZGY2QjZCOTM2MDYiOiBbIjE2ODAxNjY4NjIwMDEiLCAiMTY4MDE2Njg2MjAwMiIsICIxNjgwMTY2ODYyMDAzIl0sIjB4Y2JjY2Q0ZDg4Y0Q0OTgyNjZGN0Y3MEFiMkYxMGZkZjZCNkI5MzYwNyI6IFsiMTY4MDE2Njg2MjAwNCIsICIxNjgwMTY2ODYyMDA1IiwgIjE2ODAxNjY4NjIwMDYiXX0=eyIweGNiY2NkNGQ4OGNENDk4MjY2RjdGNzBBYjJGMTBmZGY2QjZCOTM2MDYiOiBbIjE2ODAxNjY4NjIwMDEiLCAiMTY4MDE2Njg2MjAwMiIsICIxNjgwMTY2ODYyMDAzIl0sIjB4Y2JjY2Q0ZDg4Y0Q0OTgyNjZGN0Y3MEFiMkYxMGZkZjZCNkI5MzYwNyI6IFsiMTY4MDE2Njg2MjAwNCIsICIxNjgwMTY2ODYyMDA1IiwgIjE2ODAxNjY4NjIwMDYiXX0=eyIweGNiY2NkNGQ4OGNENDk4MjY2RjdGNzBBYjJGMTBmZGY2QjZCOTM2MDYiOiBbIjE2ODAxNjY4NjIwMDEiLCAiMTY4MDE2Njg2MjAwMiIsICIxNjgwMTY2ODYyMDAzIl0sIjB4Y2JjY2Q0ZDg4Y0Q0OTgyNjZGN0Y3MEFiMkYxMGZkZjZCNkI5MzYwNyI6IFsiMTY4MDE2Njg2MjAwNCIsICIxNjgwMTY2ODYyMDA1IiwgIjE2ODAxNjY4NjIwMDYiXX0=eyIweGNiY2NkNGQ4OGNENDk4MjY2RjdGNzBBYjJGMTBmZGY2QjZCOTM2MDYiOiBbIjE2ODAxNjY4NjIwMDEiLCAiMTY4MDE2Njg2MjAwMiIsICIxNjgwMTY2ODYyMDAzIl0sIjB4Y2JjY2Q0ZDg4Y0Q0OTgyNjZGN0Y3MEFiMkYxMGZkZjZCNkI5MzYwNyI6IFsiMTY4MDE2Njg2MjAwNCIsICIxNjgwMTY2ODYyMDA1IiwgIjE2ODAxNjY4NjIwMDYiXX0=eyIweGNiY2NkNGQ4OGNENDk4MjY2RjdGNzBBYjJGMTBmZGY2QjZCOTM2MDYiOiBbIjE2ODAxNjY4NjIwMDEiLCAiMTY4MDE2Njg2MjAwMiIsICIxNjgwMTY2ODYyMDAzIl0sIjB4Y2JjY2Q0ZDg4Y0Q0OTgyNjZGN0Y3MEFiMkYxMGZkZjZCNkI5MzYwNyI6IFsiMTY4MDE2Njg2MjAwNCIsICIxNjgwMTY2ODYyMDA1IiwgIjE2ODAxNjY4NjIwMDYiXX0=eyIweGNiY=ey=eyIweGIweG2NEkNGQ4OGNENDY2Q0ZDg4Y0Q0OTgyNjZGN0Q0OTgyNjZGNMDYiXX0=eyIYiXX0="`)
	numWorkers := flagNumWorkers
	numWrites := flagNumWrites
	addr := flagAddr // kvrocks addr

	var wg sync.WaitGroup
	wg.Add(numWorkers)

	start := time.Now()
	rocks := kvrocks.NewRocksRepo(addr)
	for i := 0; i < numWorkers; i++ {
		//fmt.Printf("numWorkers:%d \n", i)
		go func() {
			primaryKey := GenNANOID(30)
			defer wg.Done()
			for j := 0; j < numWrites/numWorkers; j++ {
				//fmt.Printf("numWrites:%d \n", j)
				err := rocks.Set(primaryKey, data)
				if err != nil {
					fmt.Printf("SET Error: %+v \n", err)
				}
				//fmt.Printf("SET Resp: %+v \n", err)
			}
		}()
	}

	wg.Wait()

	elapsed := time.Since(start)
	log.Printf("done, elapsed time：%s", elapsed)
}

const customAlphabetStr = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz0123456789"
const LEN21 = 30

func GenNANOID(len int) string {
	id, err := nanoid.CustomASCII(customAlphabetStr, LEN21)
	if err != nil {
		return ""
	}

	idString := id()
	return strings.ToLower("0x" + idString)
}
