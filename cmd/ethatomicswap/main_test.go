// Copyright (c) 2018 BetterToken BVBA
// Use of this source code is governed by an MIT
// license that can be found at https://github.com/rivine/rivine/blob/master/LICENSE.
package main

import (
	"math/big"
	"strings"
	"testing"
)

func TestParseEthAsWei(t *testing.T) {
	bi := func(str string) *big.Int {
		i, ok := new(big.Int).SetString(str, 10)
		if !ok {
			t.Fatal("failed to turn " + str + " into a big.Int")
		}
		return i
	}
	testCases := []struct {
		Input          string
		ExpectedOutput *big.Int
	}{
		{"-0", nil},                    // nil isn't allowed
		{"0", nil},                     // nil isn't allowed
		{"-123", nil},                  // negative numbers aren't allowed
		{"0.0000000000000000001", nil}, // too precise
		{"1", big.NewInt(1000000000000000000)},
		{"1.1", big.NewInt(1100000000000000000)},
		{"1.123", big.NewInt(1123000000000000000)},
		{"0.001", big.NewInt(1000000000000000)},
		{"0.000000000000000001", big.NewInt(1)},
		{"123456789.987654321", bi("123456789987654321000000000")},
		{"0.00100", big.NewInt(1000000000000000)},
		{"0001", big.NewInt(1000000000000000000)},
		{"0001.100", big.NewInt(1100000000000000000)},
	}
	for idx, testCase := range testCases {
		x, err := parseEthAsWei(testCase.Input)
		if testCase.ExpectedOutput == nil {
			if err == nil {
				t.Error(idx, "expected fail parsing, but it didn't")
			}
			continue
		}
		if err != nil {
			t.Error(idx, "expected to parse, but it didn't", err)
			continue
		}
		if testCase.ExpectedOutput.Cmp(x) != 0 {
			t.Error(idx, testCase.ExpectedOutput.String(), "!=", x.String())
		}
		str := formatWeiAsEthString(x)
		strippedTestCase := strings.Trim(testCase.Input, "0")
		if strippedTestCase[0] == '.' {
			strippedTestCase = "0" + strippedTestCase
		}
		if str != strippedTestCase {
			t.Error(idx, str, "!=", strippedTestCase)
		}
	}
}
