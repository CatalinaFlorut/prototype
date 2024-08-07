/*
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"log"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"github.com/hyperledger/fabric-samples/asset-transfer-basic/chaincode-go/chaincode" // Adjust this import path to match where your ReportContract is actually located
)

func main() {
	// Assume that ReportContract is a struct defined in your second chaincode that handles the report processing.
	reportChaincode, err := contractapi.NewChaincode(&chaincode.SmartContract{})
	if err != nil {
		log.Panicf("Error creating report management chaincode: %v", err)
	}

	if err := reportChaincode.Start(); err != nil {
		log.Panicf("Error starting report management chaincode: %v", err)
	}
}
