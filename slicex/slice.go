/*
Copyright (C) 2024 Web3Password PTE. LTD.(Singapore UEN: 202333030C) - All Rights Reserved

Web3Password PTE. LTD.(Singapore UEN: 202333030C) holds the copyright of this file.

Unauthorized copying or redistribution of this file in binary forms via any medium is strictly prohibited.

For more information, please refer to https://www.web3password.com/web3password_license.txt
*/
package slicex

func Unique[E comparable](s []E) []E {
	unique := make([]E, 0)
	m := make(map[E]struct{})
	for _, v := range s {
		if _, ok := m[v]; !ok {
			m[v] = struct{}{}
			unique = append(unique, v)
		}
	}
	return unique
}
