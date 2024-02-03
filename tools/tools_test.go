/*
Copyright (C) 2024 Web3Password PTE. LTD.(Singapore UEN: 202333030C) - All Rights Reserved

Web3Password PTE. LTD.(Singapore UEN: 202333030C) holds the copyright of this file.

Unauthorized copying or redistribution of this file in binary forms via any medium is strictly prohibited.

For more information, please refer to https://www.web3password.com/web3password_license.txt
*/
package tools

import (
	"encoding/json"
	"fmt"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestBizVerifySignature(t *testing.T) {
	//addr := "0x80630A724FBaFca032bbC0bF28C75Af26BDB1F34"
	//signature := "0xeaf3d1fdaa9a4a00f8252a11e55ad5698b0123b6e247a2a09e6ac24b6008e35b29fdc1e67f012c5a838a811011052d7d23b9d3545b655451816792d3454cf9221b"
	//params := `{\"addr\":\"0x80630A724FBaFca032bbC0bF28C75Af26BDB1F34\",\"timestamp\":1691474900,\"id\":\"513f706f-e31a-4e88-aafd-23d8f137158e\",\"credential\":\"password-data-from-niumc-1691474900\",\"nonce\":\"c823c305-67af-46aa-aeb1-743241ad66a7\"}`
	//params := `{"addr":"0x80630A724FBaFca032bbC0bF28C75Af26BDB1F34","timestamp":1691474900,"id":"513f706f-e31a-4e88-aafd-23d8f137158e","credential":"password-data-from-niumc-1691474900","nonce":"c823c305-67af-46aa-aeb1-743241ad66a7"}`
	//signature = "0x46b82b3ca7aeecdb69dc9bc90d1704e7cfe994895e887c51a4ba4659c7c7203c55cf7609dafffd3e5452380b7205bbd8fcf1d5339c3de8c7a2a30a6281cd92ac1c"
	//params = `{"addr":"0xa5bdcbfb8293d07f1d0244947563ce35375664d6","nonce":"a0bc80bf-86b9-4b54-a1d9-dfbda1ad7481","timestamp":1691241053,"token":"getAllCredentialTimestamp"}`
	//addr = "0xa5bdcbfb8293d07f1d0244947563ce35375664d6"
	//addr := "0x42Cd3b00D1707051034eC7F93FaDEe69C59b4a48"
	//signature := `0x08b46c76baf25ff0c02db88f246b404e7208ae6c5629afae3c0916365d08e0e85a6528cd1654f3d29330e0099700b7e28c29f5e134c54eb3a9b239f61366e6d11b`
	//params := `{"addr":"0x42Cd3b00D1707051034eC7F93FaDEe69C59b4a48","timestamp":1691564774,"nonce":"1bab1d8f-680d-43c7-943f-faff6c42e678","id":"897eb631-5550-464d-8526-6f2f667f643e","credential":"{\"cn\":\"cp\",\"ct\":\"sjau50KFH4MoRaIugv7NKeJz0WDZc4V6ea0Bo1AP3SOpRJx4hp4ECPauCc7+QSgJEI+yzFT61eplQrY8EUAnd3qjxAnqb7sBWdvmKqwaZzsv4u0Nd06kqZ+ho0udmnliq/SCv0iZDLggxoI+09F+jImAqwifNQ/M1j5TBURR5tyr4pVmYs2dy4z7PNaDnswX2wQ/84eU+FL0d30+DhsguSSL0hp2b0BeBZqdzylTcGLEHPVKVe8wkY6RlEV68KzDH8Qp5RNVLFJojN44saqZu+CVdT4uWE4IcnhmDSFO4lCp\",\"iv\":\"y2/VSrgwwik0IEZb\",\"tg\":\"ZigOfh4FMCMAWXvY8/iB1Q==\",\"id\":\"803\"}"}`
	//params := `{\"addr\":\"0x42Cd3b00D1707051034eC7F93FaDEe69C59b4a48\",\"timestamp\":1691565129,\"nonce\":\"6966dd9d-9424-48e2-8e2d-76564f35f7e6\",\"token\":\"userInfo\"}`
	//params := `{"credential":"{\"cn\":\"cp\",\"ct\":\"sjau50KFH4MoRaIugv7NKeJz0WDZc4V6ea0Bo1AP3SOpRJx4hp4ECPauCc7+QSgJEI+yzFT61eplQrY8EUAnd3qjxAnqb7sBWdvmKqwaZzsv4u0Nd06kqZ+ho0udmnliq/SCv0iZDLggxoI+09F+jImAqwifNQ/M1j5TBURR5tyr4pVmYs2dy4z7PNaDnswX2wQ/84eU+FL0d30+DhsguSSL0hp2b0BeBZqdzylTcGLEHPVKVe8wkY6RlEV68KzDH8Qp5RNVLFJojN44saqZu+CVdT4uWE4IcnhmDSFO4lCp\",\"iv\":\"y2/VSrgwwik0IEZb\",\"tg\":\"ZigOfh4FMCMAWXvY8/iB1Q==\",\"id\":\"803\"}","addr":"0x42Cd3b00D1707051034eC7F93FaDEe69C59b4a48","timestamp":1691564774,"nonce":"1bab1d8f-680d-43c7-943f-faff6c42e678","id":"897eb631-5550-464d-8526-6f2f667f643e"}`
	//params := `{\"addr\":\"0x42Cd3b00D1707051034eC7F93FaDEe69C59b4a48\",\"timestamp\":1691567275,\"nonce\":\"29677a4e-261d-4ab1-aa9d-146b50c653d8\",\"id\":\"4d7d4f6a-23e0-4d3a-8254-924983c33e5c\",\"credential\":\"JTdCJTIyY24lMjI6JTIyY3AlMjIsJTIyY3QlMjI6JTIyK1FqTkxVR2hwM25yaVN2eUthVC83THJUeTlTcUxaRUN6dVhWbWR3NFRGR1o4K3ovRC9iSFpneVMyYnZaYTR0MkxxQXFDUlZielJyRFZQckE1bWhkQlNLOXFzOFRSUjJaQ2RjbElBN0FzcVFwMUE1YkdBTWU2YjQ3TDE0a1hEZ0o3MS9XRFZxZ3BGNk9pbWlYaTZWQ1BFRFNkL2c5dExTUEJaNGM5NXBDdDlUUHVxVWFZRVJ4YUJNWitUQlNtOHlRcFpVeVZsTFprbGorbWxxdWYrMmt5QVVnZTJNRHZRNGxHdldCZGZqbklSdm1ZQldYSU9ydE8raEFkcDkwNDFJdFBXbmEzblB3dVRmbGt4cEtLMHNidXBHOUZQclN5bzJVRWpuamIxWGcxRjA9JTIyLCUyMml2JTIyOiUyMmYrUWZ5aFhIZjQwS3lBd0QlMjIsJTIydGclMjI6JTIydlR2bk9nTkZCRWtQN1FhNWNrbHA1Zz09JTIyLCUyMmlkJTIyOiUyMjM5MCUyMiU3RA==\"}`
	//params := `{\"addr\":\"0x42Cd3b00D1707051034eC7F93FaDEe69C59b4a48\",\"timestamp\":1691564774,\"nonce\":\"1bab1d8f-680d-43c7-943f-faff6c42e678\",\"id\":\"897eb631-5550-464d-8526-6f2f667f643e\",\"credential\":\"{\\\"cn\\\":\\\"cp\\\",\\\"ct\\\":\\\"sjau50KFH4MoRaIugv7NKeJz0WDZc4V6ea0Bo1AP3SOpRJx4hp4ECPauCc7+QSgJEI+yzFT61eplQrY8EUAnd3qjxAnqb7sBWdvmKqwaZzsv4u0Nd06kqZ+ho0udmnliq/SCv0iZDLggxoI+09F+jImAqwifNQ/M1j5TBURR5tyr4pVmYs2dy4z7PNaDnswX2wQ/84eU+FL0d30+DhsguSSL0hp2b0BeBZqdzylTcGLEHPVKVe8wkY6RlEV68KzDH8Qp5RNVLFJojN44saqZu+CVdT4uWE4IcnhmDSFO4lCp\\\",\\\"iv\\\":\\\"y2/VSrgwwik0IEZb\\\",\\\"tg\\\":\\\"ZigOfh4FMCMAWXvY8/iB1Q==\\\",\\\"id\\\":\\\"803\\\"}\"}`
	//params := `{"addr":"0x42Cd3b00D1707051034eC7F93FaDEe69C59b4a48","timestamp":1691564774,"nonce":"1bab1d8f-680d-43c7-943f-faff6c42e678","id":"897eb631-5550-464d-8526-6f2f667f643e","credential":"{\\"cn\\":\\"cp\\",\\"ct\\":\\"sjau50KFH4MoRaIugv7NKeJz0WDZc4V6ea0Bo1AP3SOpRJx4hp4ECPauCc7+QSgJEI+yzFT61eplQrY8EUAnd3qjxAnqb7sBWdvmKqwaZzsv4u0Nd06kqZ+ho0udmnliq/SCv0iZDLggxoI+09F+jImAqwifNQ/M1j5TBURR5tyr4pVmYs2dy4z7PNaDnswX2wQ/84eU+FL0d30+DhsguSSL0hp2b0BeBZqdzylTcGLEHPVKVe8wkY6RlEV68KzDH8Qp5RNVLFJojN44saqZu+CVdT4uWE4IcnhmDSFO4lCp\\",\\"iv\\":\\"y2/VSrgwwik0IEZb\\",\\"tg\\":\\"ZigOfh4FMCMAWXvY8/iB1Q==\\",\\"id\\":\\"803\\"}"}`
	//addr := "0xe8935da65b358aff6943a2394032759575dbdef5"
	//signature := "0xb026db77509764355c349df45fd403e10a811f3b886dcd35469bf979f54003d5569e22afe0752ccf7cc9439639fb62c7fe7f8d725edf12a9b925103d5d59d4701c"
	//params := `{\"addr\":\"0xe8935da65b358aff6943a2394032759575dbdef5\",\"credential\":\"{\\\"cn\\\":\\\"cp\\\",\\\"ct\\\":\\\"RwYDM8hQCm9BciNNpdKS2npVio8sUm45A0jSOYib9fPXx7ii6ea/JaJzFIG8dExuBpkf66iREUpBJ1Y6Lgtqn/g1z9/tDHBuGZcWua6R7dhhBBFsnSQAGXabt/nf+23DphudBnXLKn0apyEFjia/mLBmdxF4ltKM3adZNZ1IkZtZZZXCjt3dChtNHUXJkdqZenwoj4OPCE1wB57+Vq7Ed2ms5OsCrh4iEMG+Scaf4POVsvzaRLG3V8W4++9vJz6SofEavXBRMz34zK7i65hD9FrW9m6IHLrfX14xH8Oin0Lx1zGgY4nsV7nIKL+7tddaAQZK\\\",\\\"id\\\":\\\"706\\\",\\\"iv\\\":\\\"SLudyCgEXn+6maO8\\\",\\\"tg\\\":\\\"IfWfiocDE+Mga3bzyDK/6g\\u003d\\u003d\\\"}\",\"id\":\"9d135864-06cb-4f05-81e2-00a3ae6e48a3\",\"nonce\":\"6ed5b8c9-b855-4b61-a4af-491e5d7936df\",\"timestamp\":1691560947}`
	//params := `{"addr":"0xe8935da65b358aff6943a2394032759575dbdef5","credential":"{\\"cn\\":\\"cp\\",\\"ct\\":\\"RwYDM8hQCm9BciNNpdKS2npVio8sUm45A0jSOYib9fPXx7ii6ea/JaJzFIG8dExuBpkf66iREUpBJ1Y6Lgtqn/g1z9/tDHBuGZcWua6R7dhhBBFsnSQAGXabt/nf+23DphudBnXLKn0apyEFjia/mLBmdxF4ltKM3adZNZ1IkZtZZZXCjt3dChtNHUXJkdqZenwoj4OPCE1wB57+Vq7Ed2ms5OsCrh4iEMG+Scaf4POVsvzaRLG3V8W4++9vJz6SofEavXBRMz34zK7i65hD9FrW9m6IHLrfX14xH8Oin0Lx1zGgY4nsV7nIKL+7tddaAQZK\\",\\"id\\":\\"706\\",\\"iv\\":\\"SLudyCgEXn+6maO8\\",\\"tg\\":\\"IfWfiocDE+Mga3bzyDK/6g=="}","id":"9d135864-06cb-4f05-81e2-00a3ae6e48a3","nonce":"6ed5b8c9-b855-4b61-a4af-491e5d7936df","timestamp":1691560947}`
	//params := `{"addr":"0x42Cd3b00D1707051034eC7F93FaDEe69C59b4a48","timestamp":1691564774,"nonce":"1bab1d8f-680d-43c7-943f-faff6c42e678","id":"897eb631-5550-464d-8526-6f2f667f643e","credential":"{\"cn\":\"cp\",\"ct\":\"sjau50KFH4MoRaIugv7NKeJz0WDZc4V6ea0Bo1AP3SOpRJx4hp4ECPauCc7+QSgJEI+yzFT61eplQrY8EUAnd3qjxAnqb7sBWdvmKqwaZzsv4u0Nd06kqZ+ho0udmnliq/SCv0iZDLggxoI+09F+jImAqwifNQ/M1j5TBURR5tyr4pVmYs2dy4z7PNaDnswX2wQ/84eU+FL0d30+DhsguSSL0hp2b0BeBZqdzylTcGLEHPVKVe8wkY6RlEV68KzDH8Qp5RNVLFJojN44saqZu+CVdT4uWE4IcnhmDSFO4lCp\",\"iv\":\"y2/VSrgwwik0IEZb\",\"tg\":\"ZigOfh4FMCMAWXvY8/iB1Q==\",\"id\":\"803\"}"}`
	//addr := "0xe8935da65b358aff6943a2394032759575dbdef5"
	//signature := "0xfe138ac49ec705ca0cc315c0243e09114d0e08f3eb383ac08b73d4274efb943326039005726f59215be4115248a97bc2191f7eff8b1b4b6c5900cc586b688ad21c"
	//decodedStr := `{"addr":"0xe8935da65b358aff6943a2394032759575dbdef5","credential":"{\"cn\":\"cp\",\"ct\":\"kx+dUnq0x2W89ZO6kyHLhiwCQU845bsskJ1rj7oY7qnXDbT90PcOTl7nQfKxsqLqDVgU0nxXiCyw6PRYyo9OmzGHA2wzjEVZMWa76G8cIc+G3H8XwGybvNodl9hyir1nnYXhbqc6DVGTT2Kkx7miE0gcM9SV6RC9DA//nLfbYYyhDfe8JsoV2E041ym4ar1oS+gyKQIIKg4h5L4xIWvPboNrTdVJ35bIJWQbn5PJU+ic+noQZjC/5egOShBl5nu5pDn6nWzjJ57uDwxtLVxmfd6hJN21gUKp/2FQPsP4NTRvSV3pAriibKoU9u9FF9jokRX9\",\"id\":\"145\",\"iv\":\"f01AnB2E3z/oLIUk\",\"tg\":\"kR05NS1jUVJ0CF543X3NTA\u003d\u003d\"}","id":"4ad5d9ce-b4e5-4570-b617-c8f01379ff9d","nonce":"ae4aaaa1-6e4f-4734-ab39-63c0b358b11f","timestamp":1691568670}`
	addr := "0xe8935da65b358aff6943a2394032759575dbdef5"
	signature := "0x64188ffb33e0ac4b6107a8a7ec887e14575b5ce35f4c595aaa4384151787955802f18df19816c8231e4d5bd79fea8d9901f8df1b3b6b752893b2671515d508211c"
	params := `{\"addr\":\"0xe8935da65b358aff6943a2394032759575dbdef5\",\"credential\":\"eyJjbiI6ImNwIiwiY3QiOiJoVkRObzhyL1RBZm41b3l4OXVlVmYxTVNielA2Y2ZqTTlENzdZNmVvZDFOTWpGeE11ck9yd2w1YWhlRTlaa0tNME1iV0Mvc1NNU08xT2pFYnBVMEh3Rkd5RU5EK2pjMUVFekg2OEJackxrMnBaampFSHhNZDQxNFZGdzlkNHpJSFhMS2kvTDNyWGN6UFFlM0hZUWxMYkVFTnRQQkFod0FNUEtMTWNOemNBc2xPU3hRY081cHc0RlF1QzVHU20xcDgrKzFZeTBlKzYwSlJBVWl6WlNtU3oxUTZrbzRIeWt0SXZhdUx5MnNJcW9WYVpxSFNqS3pXc3Zrd3lkeHhSaERsQnlxaEIrQ2dBWDZPdzhac09SU0ZEczF1ekxJbktHY3d3bkxpZCs1ZXFhWHBzclQ5dUJCeGZOYnh2dWsrTFdMVHdVaWtNQT09IiwiaWQiOiI1MzYiLCJpdiI6ImdrYm9VMGUxT2JFWnhqQnEiLCJ0ZyI6InRrR2tMaE5hYTV3aTd2NGw4L0hZSEE9PSJ9\",\"id\":\"fb8b1779-69c4-4b31-9e8e-295e24c1aa1e\",\"nonce\":\"9f0ebfd9-7964-423e-b355-2d14bd3d7a34\",\"timestamp\":1691569320}`
	decodedStr := strings.Replace(params, `\"`, `"`, -1)
	//decodedStr := `{"addr":"0x42Cd3b00D1707051034eC7F93FaDEe69C59b4a48","timestamp":1691565129,"nonce":"6966dd9d-9424-48e2-8e2d-76564f35f7e6","token":"userInfo"}`
	//decodedStr := `{"nonce":"29677a4e-261d-4ab1-aa9d-146b50c653d8","id":"4d7d4f6a-23e0-4d3a-8254-924983c33e5c","credential":"JTdCJTIyY24lMjI6JTIyY3AlMjIsJTIyY3QlMjI6JTIyK1FqTkxVR2hwM25yaVN2eUthVC83THJUeTlTcUxaRUN6dVhWbWR3NFRGR1o4K3ovRC9iSFpneVMyYnZaYTR0MkxxQXFDUlZielJyRFZQckE1bWhkQlNLOXFzOFRSUjJaQ2RjbElBN0FzcVFwMUE1YkdBTWU2YjQ3TDE0a1hEZ0o3MS9XRFZxZ3BGNk9pbWlYaTZWQ1BFRFNkL2c5dExTUEJaNGM5NXBDdDlUUHVxVWFZRVJ4YUJNWitUQlNtOHlRcFpVeVZsTFprbGorbWxxdWYrMmt5QVVnZTJNRHZRNGxHdldCZGZqbklSdm1ZQldYSU9ydE8raEFkcDkwNDFJdFBXbmEzblB3dVRmbGt4cEtLMHNidXBHOUZQclN5bzJVRWpuamIxWGcxRjA9JTIyLCUyMml2JTIyOiUyMmYrUWZ5aFhIZjQwS3lBd0QlMjIsJTIydGclMjI6JTIydlR2bk9nTkZCRWtQN1FhNWNrbHA1Zz09JTIyLCUyMmlkJTIyOiUyMjM5MCUyMiU3RA==","addr":"0x42Cd3b00D1707051034eC7F93FaDEe69C59b4a48","timestamp":1691567275}`

	fmt.Println("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
	fmt.Println(decodedStr)
	fmt.Println("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
	//err := json.Unmarshal([]byte(params), &data)
	//if err != nil {
	//	fmt.Println("Error:", err)
	//	return
	//}

	//params := `{"id":"2bdc0f1a-9eee-4421-b5ed-80b68bf8ae04","nonce":"d26c8370-0b68-4d9d-83b2-2fb766bb55ea","timestamp":1691559867,"addr":"0xe8935da65b358aff6943a2394032759575dbdef5","credential":"{"cn":"cp","ct":"v0s7Sg4nNQ3bIBdAesaPzb9amhKgyMGF0GXqBfipc9Gk/BDVr/yllitph1S+XafqT7EnUn2vwKLpfDPIWPVOshh0e4iLUKSex2KBIirfPkEd63ol9dc/eZODtFtEC9suZ0dCVxRfkuVSbn38eSU9Qwp2Nv+/8IIu0grUguQYFN9q0FNnROd8iTqXyw7VfzUQDBz3Bn747K8x949jNpvmEGqkbvWh+jXFO8jEKTePPgo8Pp0xjqiMB/CA/6EzQGvOljwlqHGvD6ghBbuRGyBKXFe3fLlqAmBSE9RMC3JxK0upHQblm/2sEIBbyUTD2t7s9Zn/sQ==","id":"204","iv":"RzXMqng0DQebsvvW","tg":"EJXylNJF3UahIgR5qtMKrw=="}"}`

	//params := `{"id":"2bdc0f1a-9eee-4421-b5ed-80b68bf8ae04","nonce":"d26c8370-0b68-4d9d-83b2-2fb766bb55ea","timestamp":1691559867,"addr":"0xe8935da65b358aff6943a2394032759575dbdef5","credential":"{\"cn\":\"cp\",\"ct\":\"v0s7Sg4nNQ3bIBdAesaPzb9amhKgyMGF0GXqBfipc9Gk/BDVr/yllitph1S+XafqT7EnUn2vwKLpfDPIWPVOshh0e4iLUKSex2KBIirfPkEd63ol9dc/eZODtFtEC9suZ0dCVxRfkuVSbn38eSU9Qwp2Nv+/8IIu0grUguQYFN9q0FNnROd8iTqXyw7VfzUQDBz3Bn747K8x949jNpvmEGqkbvWh+jXFO8jEKTePPgo8Pp0xjqiMB/CA/6EzQGvOljwlqHGvD6ghBbuRGyBKXFe3fLlqAmBSE9RMC3JxK0upHQblm/2sEIBbyUTD2t7s9Zn/sQ==\",\"id\":\"204\",\"iv\":\"RzXMqng0DQebsvvW\",\"tg\":\"EJXylNJF3UahIgR5qtMKrw==\"}"}`
	//fmt.Printf("paramsStr: %s \n", data)
	//params := `{"addr":"0xe8935da65b358aff6943a2394032759575dbdef5","credential":"{\"cn\":\"cp\",\"ct\":\"v0s7Sg4nNQ3bIBdAesaPzb9amhKgyMGF0GXqBfipc9Gk/BDVr/yllitph1S+XafqT7EnUn2vwKLpfDPIWPVOshh0e4iLUKSex2KBIirfPkEd63ol9dc/eZODtFtEC9suZ0dCVxRfkuVSbn38eSU9Qwp2Nv+/8IIu0grUguQYFN9q0FNnROd8iTqXyw7VfzUQDBz3Bn747K8x949jNpvmEGqkbvWh+jXFO8jEKTePPgo8Pp0xjqiMB/CA/6EzQGvOljwlqHGvD6ghBbuRGyBKXFe3fLlqAmBSE9RMC3JxK0upHQblm/2sEIBbyUTD2t7s9Zn/sQ==\",\"id\":\"204\",\"iv\":\"RzXMqng0DQebsvvW\",\"tg\":\"EJXylNJF3UahIgR5qtMKrw==\"}","id":"2bdc0f1a-9eee-4421-b5ed-80b68bf8ae04","nonce":"d26c8370-0b68-4d9d-83b2-2fb766bb55ea","timestamp":1691559867}`
	//params := `{"addr":"0xe8935da65b358aff6943a2394032759575dbdef5","credential":"{"cn":"cp","ct":"RwYDM8hQCm9BciNNpdKS2npVio8sUm45A0jSOYib9fPXx7ii6ea/JaJzFIG8dExuBpkf66iREUpBJ1Y6Lgtqn/g1z9/tDHBuGZcWua6R7dhhBBFsnSQAGXabt/nf+23DphudBnXLKn0apyEFjia/mLBmdxF4ltKM3adZNZ1IkZtZZZXCjt3dChtNHUXJkdqZenwoj4OPCE1wB57+Vq7Ed2ms5OsCrh4iEMG+Scaf4POVsvzaRLG3V8W4++9vJz6SofEavXBRMz34zK7i65hD9FrW9m6IHLrfX14xH8Oin0Lx1zGgY4nsV7nIKL+7tddaAQZK","id":"706","iv":"SLudyCgEXn+6maO8","tg":"IfWfiocDE+Mga3bzyDK/6g\u003d\u003d"}","id":"9d135864-06cb-4f05-81e2-00a3ae6e48a3","nonce":"6ed5b8c9-b855-4b61-a4af-491e5d7936df","timestamp":1691560947}`
	err := BizVerifySignature(signature, []byte(decodedStr), addr)
	if err != nil {
		assert.Errorf(t, err, "BizVerifySignature Failed")
	}

	//err = BizVerifySignature(signature, params, addr)
	//if err != nil {
	//	assert.Errorf(t, err, "BizVerifySignature Failed")
	//}

	//params = `{"addr":"0xB79A052289E20B250157106c5646eEB402d80E5f","timestamp":1689327921,"id":"171f7dfd-495b-4a8c-ab65-6366aa99df48","credential":"password-data-from-stamhe-1689327921140","nonce":"random-string-from-stamhe-test-1689327921140"}`
	//signature = "fb9b8ae9a5ce9f8095017069daf20959fc8e506116648d84f4f7abce312204b45c28f278905f34e3d8fbb74a9723029e4323f3bf8067d7c5b03cd089c6bbf5a11c"
	//addr = "0xB79A052289E20B250157106c5646eEB402d80E5f"
	//
	//err = BizVerifySignature(signature, params, addr)
	//if err != nil {
	//	assert.Errorf(t, err, "BizVerifySignature Failed")
	//}
}

func TestVerify(t *testing.T) {
	//Verify()
	fmt.Printf("========TestVerify=======\n")
	//input := `{"params":"{\"addr\":\"0xe8935da65b358aff6943a2394032759575dbdef5\",\"nonce\":\"7e78f25b-c0e3-4b64-9e58-78cae16b4688\",\"timestamp\":1691473140,\"token\":\"getAllCredentialTimestamp\"}","signature":"0x71a056db83c9c80d7b8a1ffc6b7cdc723b855144a83aafb6c712201816e4d5e55472ffae548dae4a9401eb72d0cab89e02e1a53737e86816ea2b8d50c84ab2b11b"}`

	//input := `{"signature":"0x1f2938d490b50d9797e668409cc40155c8ff0864106d3c091b564cc86ad6ceb322f1d7a9568fb682ad44e6d4c28707176c17158d6af10a8bcd82c2de93591c961b","params":"{\"addr\":\"0x3b0f70187B0699Ce39eb0Fdac93228f909E09823\",\"timestamp\":1691551719,\"nonce\":\"47746895-85ea-46b9-952f-6e2ac6e5c060\",\"id\":\"8b338ac6-3db0-447b-a2d7-c37b9f88ca1b\",\"credential\":\"{\\\"cn\\\":\\\"cp\\\",\\\"ct\\\":\\\"l+0covIpe5CW0dvZut0KaQlx6ymAzyi2Q+v5G2cC91Yi41hn1+gZaRFYCJyDs1tEscRaZgl1fWgkShbIVrZw8YrfU28l1GMzuO991mjPGYQhXTgUmD1HYjFnyWCrfnbHGl80tpglpZ1W42E/VBf4Pd0Hr/IbDKFIocKZ4Isd+yk2tMK6ELM497eSQ9I78dOOxGAlSGPZ8UCBwCgyavCeZv1sGdGXBi2aJ0MkqVBlycGoyWHtsGn/ison6WM2KWWouKQVIvX/ydPcWPFVVgtTMKdpXZLk8fIIbK7XIUkDmh0=\\\",\\\"iv\\\":\\\"ubEpEf+m83qLLq4e\\\",\\\"tg\\\":\\\"9ldFn9gjIsnHZAlDtkt6fA==\\\",\\\"id\\\":\\\"769\\\"}\"}"}`
	//input := `{"signature":"0x1f2938d490b50d9797e668409cc40155c8ff0864106d3c091b564cc86ad6ceb322f1d7a9568fb682ad44e6d4c28707176c17158d6af10a8bcd82c2de93591c961b","params":"{\"addr\":\"0x3b0f70187B0699Ce39eb0Fdac93228f909E09823\",\"timestamp\":1691551719,\"nonce\":\"47746895-85ea-46b9-952f-6e2ac6e5c060\",\"id\":\"8b338ac6-3db0-447b-a2d7-c37b9f88ca1b\",\"credential\":\"{\\\"cn\\\":\\\"cp\\\",\\\"ct\\\":\\\"l+0covIpe5CW0dvZut0KaQlx6ymAzyi2Q+v5G2cC91Yi41hn1+gZaRFYCJyDs1tEscRaZgl1fWgkShbIVrZw8YrfU28l1GMzuO991mjPGYQhXTgUmD1HYjFnyWCrfnbHGl80tpglpZ1W42E/VBf4Pd0Hr/IbDKFIocKZ4Isd+yk2tMK6ELM497eSQ9I78dOOxGAlSGPZ8UCBwCgyavCeZv1sGdGXBi2aJ0MkqVBlycGoyWHtsGn/ison6WM2KWWouKQVIvX/ydPcWPFVVgtTMKdpXZLk8fIIbK7XIUkDmh0=\\\",\\\"iv\\\":\\\"ubEpEf+m83qLLq4e\\\",\\\"tg\\\":\\\"9ldFn9gjIsnHZAlDtkt6fA==\\\",\\\"id\\\":\\\"769\\\"}\"}"}`
	//input := `{"params":"{\"addr\":\"0xe8935da65b358aff6943a2394032759575dbdef5\",\"credential\":\"{\\\"cn\\\":\\\"cp\\\",\\\"ct\\\":\\\"v0s7Sg4nNQ3bIBdAesaPzb9amhKgyMGF0GXqBfipc9Gk/BDVr/yllitph1S+XafqT7EnUn2vwKLpfDPIWPVOshh0e4iLUKSex2KBIirfPkEd63ol9dc/eZODtFtEC9suZ0dCVxRfkuVSbn38eSU9Qwp2Nv+/8IIu0grUguQYFN9q0FNnROd8iTqXyw7VfzUQDBz3Bn747K8x949jNpvmEGqkbvWh+jXFO8jEKTePPgo8Pp0xjqiMB/CA/6EzQGvOljwlqHGvD6ghBbuRGyBKXFe3fLlqAmBSE9RMC3JxK0upHQblm/2sEIBbyUTD2t7s9Zn/sQ\\u003d\\u003d\\\",\\\"id\\\":\\\"204\\\",\\\"iv\\\":\\\"RzXMqng0DQebsvvW\\\",\\\"tg\\\":\\\"EJXylNJF3UahIgR5qtMKrw\\u003d\\u003d\\\"}\",\"id\":\"2bdc0f1a-9eee-4421-b5ed-80b68bf8ae04\",\"nonce\":\"d26c8370-0b68-4d9d-83b2-2fb766bb55ea\",\"timestamp\":1691559867}","signature":"0xbfd136b472f52c825fd7a3abf8a292a370143d6058aabc6e089719dc087ada0e5ca67b6703ad05cc204b4b115e211abd14f8ee9a7f344e3d63371ef0f71e9ab71b"}`
	//input := `{"credential":"{\"cn\":\"cp\",\"ct\":\"v0s7Sg4nNQ3bIBdAesaPzb9amhKgyMGF0GXqBfipc9Gk/BDVr/yllitph1S+XafqT7EnUn2vwKLpfDPIWPVOshh0e4iLUKSex2KBIirfPkEd63ol9dc/eZODtFtEC9suZ0dCVxRfkuVSbn38eSU9Qwp2Nv+/8IIu0grUguQYFN9q0FNnROd8iTqXyw7VfzUQDBz3Bn747K8x949jNpvmEGqkbvWh+jXFO8jEKTePPgo8Pp0xjqiMB/CA/6EzQGvOljwlqHGvD6ghBbuRGyBKXFe3fLlqAmBSE9RMC3JxK0upHQblm/2sEIBbyUTD2t7s9Zn/sQ==\",\"id\":\"204\",\"iv\":\"RzXMqng0DQebsvvW\",\"tg\":\"EJXylNJF3UahIgR5qtMKrw==\"}","id":"2bdc0f1a-9eee-4421-b5ed-80b68bf8ae04","nonce":"d26c8370-0b68-4d9d-83b2-2fb766bb55ea","timestamp":1691559867,"addr":"0xe8935da65b358aff6943a2394032759575dbdef5"}`
	//input := `{"addr":"0xe8935da65b358aff6943a2394032759575dbdef5","credential":"{\"cn\":\"cp\",\"ct\":\"v0s7Sg4nNQ3bIBdAesaPzb9amhKgyMGF0GXqBfipc9Gk/BDVr/yllitph1S+XafqT7EnUn2vwKLpfDPIWPVOshh0e4iLUKSex2KBIirfPkEd63ol9dc/eZODtFtEC9suZ0dCVxRfkuVSbn38eSU9Qwp2Nv+/8IIu0grUguQYFN9q0FNnROd8iTqXyw7VfzUQDBz3Bn747K8x949jNpvmEGqkbvWh+jXFO8jEKTePPgo8Pp0xjqiMB/CA/6EzQGvOljwlqHGvD6ghBbuRGyBKXFe3fLlqAmBSE9RMC3JxK0upHQblm/2sEIBbyUTD2t7s9Zn/sQ==\",\"id\":\"204\",\"iv\":\"RzXMqng0DQebsvvW\",\"tg\":\"EJXylNJF3UahIgR5qtMKrw==\"}","id":"2bdc0f1a-9eee-4421-b5ed-80b68bf8ae04","nonce":"d26c8370-0b68-4d9d-83b2-2fb766bb55ea","timestamp":1691559867}`
	//input := ` {"params":"{\"addr\":\"0xe8935da65b358aff6943a2394032759575dbdef5\",\"credential\":\"{\\\"cn\\\":\\\"cp\\\",\\\"ct\\\":\\\"RwYDM8hQCm9BciNNpdKS2npVio8sUm45A0jSOYib9fPXx7ii6ea/JaJzFIG8dExuBpkf66iREUpBJ1Y6Lgtqn/g1z9/tDHBuGZcWua6R7dhhBBFsnSQAGXabt/nf+23DphudBnXLKn0apyEFjia/mLBmdxF4ltKM3adZNZ1IkZtZZZXCjt3dChtNHUXJkdqZenwoj4OPCE1wB57+Vq7Ed2ms5OsCrh4iEMG+Scaf4POVsvzaRLG3V8W4++9vJz6SofEavXBRMz34zK7i65hD9FrW9m6IHLrfX14xH8Oin0Lx1zGgY4nsV7nIKL+7tddaAQZK\\\",\\\"id\\\":\\\"706\\\",\\\"iv\\\":\\\"SLudyCgEXn+6maO8\\\",\\\"tg\\\":\\\"IfWfiocDE+Mga3bzyDK/6g\\u003d\\u003d\\\"}\",\"id\":\"9d135864-06cb-4f05-81e2-00a3ae6e48a3\",\"nonce\":\"6ed5b8c9-b855-4b61-a4af-491e5d7936df\",\"timestamp\":1691560947}","signature":"0xb026db77509764355c349df45fd403e10a811f3b886dcd35469bf979f54003d5569e22afe0752ccf7cc9439639fb62c7fe7f8d725edf12a9b925103d5d59d4701c"}`
	//input := `{"signature":"0x31a52e3a3b6e8b0b7658b795e899d1e71b71b10cafa122501cf52266aa699454556b872e3e4cd11bb6003ebbb40ec1235a0055d560fba433115065d4cde36c061c","params":"{\"addr\":\"0x42Cd3b00D1707051034eC7F93FaDEe69C59b4a48\",\"timestamp\":1691565129,\"nonce\":\"6966dd9d-9424-48e2-8e2d-76564f35f7e6\",\"token\":\"userInfo\"}"}`
	//input := `{"signature":"0x08b46c76baf25ff0c02db88f246b404e7208ae6c5629afae3c0916365d08e0e85a6528cd1654f3d29330e0099700b7e28c29f5e134c54eb3a9b239f61366e6d11b","params":"{\"addr\":\"0x42Cd3b00D1707051034eC7F93FaDEe69C59b4a48\",\"timestamp\":1691564774,\"nonce\":\"1bab1d8f-680d-43c7-943f-faff6c42e678\",\"id\":\"897eb631-5550-464d-8526-6f2f667f643e\",\"credential\":\"{\\\"cn\\\":\\\"cp\\\",\\\"ct\\\":\\\"sjau50KFH4MoRaIugv7NKeJz0WDZc4V6ea0Bo1AP3SOpRJx4hp4ECPauCc7+QSgJEI+yzFT61eplQrY8EUAnd3qjxAnqb7sBWdvmKqwaZzsv4u0Nd06kqZ+ho0udmnliq/SCv0iZDLggxoI+09F+jImAqwifNQ/M1j5TBURR5tyr4pVmYs2dy4z7PNaDnswX2wQ/84eU+FL0d30+DhsguSSL0hp2b0BeBZqdzylTcGLEHPVKVe8wkY6RlEV68KzDH8Qp5RNVLFJojN44saqZu+CVdT4uWE4IcnhmDSFO4lCp\\\",\\\"iv\\\":\\\"y2/VSrgwwik0IEZb\\\",\\\"tg\\\":\\\"ZigOfh4FMCMAWXvY8/iB1Q==\\\",\\\"id\\\":\\\"803\\\"}\"}"}`
	//input := `{"signature":"0x08b46c76baf25ff0c02db88f246b404e7208ae6c5629afae3c0916365d08e0e85a6528cd1654f3d29330e0099700b7e28c29f5e134c54eb3a9b239f61366e6d11b","params":"{\"addr\":\"0x42Cd3b00D1707051034eC7F93FaDEe69C59b4a48\",\"timestamp\":1691564774,\"nonce\":\"1bab1d8f-680d-43c7-943f-faff6c42e678\",\"id\":\"897eb631-5550-464d-8526-6f2f667f643e\",\"credential\":\"{\\\"cn\\\":\\\"cp\\\",\\\"ct\\\":\\\"sjau50KFH4MoRaIugv7NKeJz0WDZc4V6ea0Bo1AP3SOpRJx4hp4ECPauCc7+QSgJEI+yzFT61eplQrY8EUAnd3qjxAnqb7sBWdvmKqwaZzsv4u0Nd06kqZ+ho0udmnliq/SCv0iZDLggxoI+09F+jImAqwifNQ/M1j5TBURR5tyr4pVmYs2dy4z7PNaDnswX2wQ/84eU+FL0d30+DhsguSSL0hp2b0BeBZqdzylTcGLEHPVKVe8wkY6RlEV68KzDH8Qp5RNVLFJojN44saqZu+CVdT4uWE4IcnhmDSFO4lCp\\\",\\\"iv\\\":\\\"y2/VSrgwwik0IEZb\\\",\\\"tg\\\":\\\"ZigOfh4FMCMAWXvY8/iB1Q==\\\",\\\"id\\\":\\\"803\\\"}\"}"}`
	input := `{"signature":"0xfe1502245aba1d98be631f56b916fb1b3c328d38cb588c0a4c47a7f4baf24835412666d3d9d13c98b682aa5c4566b257c54409656d1b8e928156b23293e02f031c","params":"{\"addr\":\"0x42Cd3b00D1707051034eC7F93FaDEe69C59b4a48\",\"timestamp\":1691567275,\"nonce\":\"29677a4e-261d-4ab1-aa9d-146b50c653d8\",\"id\":\"4d7d4f6a-23e0-4d3a-8254-924983c33e5c\",\"credential\":\"JTdCJTIyY24lMjI6JTIyY3AlMjIsJTIyY3QlMjI6JTIyK1FqTkxVR2hwM25yaVN2eUthVC83THJUeTlTcUxaRUN6dVhWbWR3NFRGR1o4K3ovRC9iSFpneVMyYnZaYTR0MkxxQXFDUlZielJyRFZQckE1bWhkQlNLOXFzOFRSUjJaQ2RjbElBN0FzcVFwMUE1YkdBTWU2YjQ3TDE0a1hEZ0o3MS9XRFZxZ3BGNk9pbWlYaTZWQ1BFRFNkL2c5dExTUEJaNGM5NXBDdDlUUHVxVWFZRVJ4YUJNWitUQlNtOHlRcFpVeVZsTFprbGorbWxxdWYrMmt5QVVnZTJNRHZRNGxHdldCZGZqbklSdm1ZQldYSU9ydE8raEFkcDkwNDFJdFBXbmEzblB3dVRmbGt4cEtLMHNidXBHOUZQclN5bzJVRWpuamIxWGcxRjA9JTIyLCUyMml2JTIyOiUyMmYrUWZ5aFhIZjQwS3lBd0QlMjIsJTIydGclMjI6JTIydlR2bk9nTkZCRWtQN1FhNWNrbHA1Zz09JTIyLCUyMmlkJTIyOiUyMjM5MCUyMiU3RA==\"}"}`
	fmt.Println(input)
	var data map[string]string
	err := json.Unmarshal([]byte(input), &data)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	signature := data["signature"]
	params := data["params"]

	var paramsData map[string]interface{}
	err = json.Unmarshal([]byte(params), &paramsData)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	paramsDataStr, _ := jsoniter.MarshalToString(paramsData)
	fmt.Println("#################################################")
	fmt.Println(paramsDataStr)
	fmt.Println("#################################################")
	outputData := map[string]interface{}{
		"signature": signature,
		"params":    paramsDataStr,
	}

	outputJSON, err := json.Marshal(outputData)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println(string(outputJSON))
}
