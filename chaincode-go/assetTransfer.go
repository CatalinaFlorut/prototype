/*
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"log"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"github.com/hyperledger/fabric-samples/asset-transfer-basic/chaincode-go/chaincode" // Adjusted to match your incident management chaincode path
)

func main() {
	incidentChaincode, err := contractapi.NewChaincode(&chaincode.SmartContract{})
	if err != nil {
		log.Panicf("Error creating incident management chaincode: %v", err)
	}

	if err := incidentChaincode.Start(); err != nil {
		log.Panicf("Error starting incident management chaincode: %v", err)
	}
}
