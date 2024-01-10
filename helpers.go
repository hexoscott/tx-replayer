package main

import (
	"math/big"
	"strconv"
	"strings"
)

func stringToInt(input string) (int64, error) {
	return strconv.ParseInt(trimHex(input), 16, 64)
}

func stringToBig(input string) *big.Int {
	result := new(big.Int)
	result.SetString(trimHex(input), 16)
	return result
}

func stringToUint(input string) (uint64, error) {
	return strconv.ParseUint(trimHex(input), 16, 64)
}

func trimHex(input string) string {
	if strings.HasPrefix(input, "0x") {
		return input[2:]
	}
	return input
}
