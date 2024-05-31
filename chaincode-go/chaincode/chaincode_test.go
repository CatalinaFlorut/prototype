package chaincode_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"github.com/hyperledger/fabric-protos-go/ledger/queryresult"
	"github.com/hyperledger/fabric-samples/incident-transfer-basic/chaincode-go/chaincode"
	"github.com/hyperledger/fabric-samples/incident-transfer-basic/chaincode-go/chaincode/mocks"
	"github.com/stretchr/testify/require"
)

// Custom interfaces for abstracting HF API for easier mocking
type transactionContext interface {
	contractapi.TransactionContextInterface
}

type chaincodeStub interface {
	shim.ChaincodeStubInterface
}

type stateQueryIterator interface {
	shim.StateQueryIteratorInterface
}

func TestInitLedger(t *testing.T) {

	//Creates a mock instance of a chaincode stub. This object
	//simulates the interface through which the chaincode interacts with the ledger
	chaincodeStub := &mocks.ChaincodeStub{}
	//Creates a mock instance of a transaction context, which provides context for the chaincode execution
	transactionContext := &mocks.TransactionContext{}
	//Configures the mock transaction context to return the mock chaincode stub
	transactionContext.GetStubReturns(chaincodeStub)

	//Creates an instance of the SmartContract struct, which contains the InitLedger function being tested.
	incidentManagement := chaincode.SmartContract{}
	// Calls the InitLedger function with the mock transaction context
	err := incidentManagement.InitLedger(transactionContext)
	//Asses if no error occured during execution
	require.NoError(t, err)

	//Configures the mock chaincode stub to return an error when PutState is called.
	chaincodeStub.PutStateReturns(fmt.Errorf("failed inserting key"))
	err = incidentManagement.InitLedger(transactionContext)
	//Asses that the error returned by InitLedger matches the expected error message
	require.EqualError(t, err, "failed to put to world state. failed inserting key")
}

// function for testing CreateIncident
func TestCreateIncident(t *testing.T) {
	chaincodeStub := &mocks.ChaincodeStub{}
	transactionContext := &mocks.TransactionContext{}
	transactionContext.GetStubReturns(chaincodeStub)

	incidentManagement := chaincode.SmartContract{}
	// Test creating a new incident  with no error
	err := incidentManagement.CreateIncident(transactionContext, []string{"ITSystemPeer1"}, "Unauthorized access detected", "ITTeamPeer", "High", "Security")
	require.NoError(t, err, "Creating an incident should not result in an error")

	// Simulate a scenario where the state cannot be retrieved due to an error in the chaincode stub
	// Configures the mock chaincode stub to return an error when GetStateReturns is called.
	chaincodeStub.GetStateReturns(nil, fmt.Errorf("unable to retrieve state"))
	err = incidentManagement.CreateIncident(transactionContext, []string{"ITSystemPeer2"}, "Hardware failure", "ITTeamPeer", "Medium", "Technical")
	require.EqualError(t, err, "failed to get the incident counter: unable to retrieve state", "Expected an error when unable to retrieve state")

	// Reset stub to simulate a successful state retrieval for subsequent tests
	chaincodeStub.GetStateReturns([]byte("1"), nil)

}

// function for testing DeleteIncident
func TestDeleteIncident(t *testing.T) {
	chaincodeStub := &mocks.ChaincodeStub{}
	transactionContext := &mocks.TransactionContext{}
	transactionContext.GetStubReturns(chaincodeStub)

	incident := &chaincode.Incident{ID: "incident1"}
	bytes, err := json.Marshal(incident)
	require.NoError(t, err)

	// Set up the initial state before deletion
	chaincodeStub.GetStateReturns([]byte("existing incident data"), nil) // Simulate incident exists
	incidentManagement := chaincode.SmartContract{}

	// Simulate incident does not exist
	chaincodeStub.GetStateReturns(bytes, nil)
	err = incidentManagement.DeleteIncident(transactionContext, "incident1")
	require.EqualError(t, err, "the incident incident1 does not exist", "Expected an error when incident does not exist")

	// Simulate error in retrieving state
	chaincodeStub.GetStateReturns(nil, fmt.Errorf("unable to retrieve incident"))
	err = incidentManagement.DeleteIncident(transactionContext, "incident1")
	require.EqualError(t, err, "failed to read from world state: unable to retrieve incident", "Expected an error when unable to retrieve state")
}

// function for testing GetAllIncidents
func TestGetAllIncidents(t *testing.T) {
	incident := &chaincode.SmartContract{IncidentId: "incident1"}
	bytes, err := json.Marshal(incident)
	require.NoError(t, err)

	chaincodeStub := &mocks.ChaincodeStub{}
	transactionContext := &mocks.TransactionContext{}
	transactionContext.GetStubReturns(chaincodeStub)

	// Simulate iteration
	iterator := &mocks.StateQueryIterator{}
	chaincodeStub.GetStateByRangeReturns(iterator, nil) // Mock setup for iterator

	iterator.HasNextReturnsOnCall(0, true)
	iterator.NextReturns(&queryresult.KV{Key: "incident1", Value: bytes}, nil)
	iterator.HasNextReturnsOnCall(1, false) // Indicate end of data

	incidentManagement := &chaincode.SmartContract{}
	incidents, err := incidentManagement.GetAllIncidents(transactionContext)
	require.NoError(t, err)
	require.Len(t, incidents, 1, "Expected one incident to be returned")
	require.Equal(t, "incident1", incidents[0].IncidentId, "Expected incident ID to match")

	// Simulate failure during iteration
	iterator.HasNextReturns(true) // Reset to simulate another fetch attempt
	iterator.NextReturns(nil, fmt.Errorf("failed retrieving next item"))
	incidents, err = incidentManagement.GetAllIncidents(transactionContext)
	require.EqualError(t, err, "failed retrieving next item", "Expected an error when iteration fails")
	require.Nil(t, incidents, "Expected no incidents to be returned on error")
}

// function for testing ResolveIncident
func TestResolveIncident(t *testing.T) {
	// Setup mock chaincode stub and transaction context
	chaincodeStub := &mocks.ChaincodeStub{}
	transactionContext := &mocks.TransactionContext{}
	transactionContext.GetStubReturns(chaincodeStub)

	// Prepare an incident to resolve
	existingIncident := chaincode.Incident{
		IncidentId: "incident1",
		Status:     "In Review",
	}
	bytes, _ := json.Marshal(existingIncident)
	chaincodeStub.GetStateReturns(bytes, nil)

	// Try to resolve the incident
	incidentManagement := chaincode.SmartContract{}
	err := incidentManagement.ResolveIncident(transactionContext, "incident1", "Resolved description", "Impact description", "Recovery steps")
	require.NoError(t, err)

	// Verify that PutState was called with the updated incident
	chaincodeStub.PutStateCalls(func(key string, value []byte) error {
		var incident chaincode.Incident
		json.Unmarshal(value, &incident)
		require.Equal(t, "Resolved", incident.Status, "Incident status should be updated to 'Resolved'")
		return nil
	})

	// Simulate an error in retrieving the incident
	chaincodeStub.GetStateReturns(nil, fmt.Errorf("unable to retrieve incident"))
	err = incidentManagement.ResolveIncident(transactionContext, "incident1", "Resolved description", "Impact description", "Recovery steps")
	require.EqualError(t, err, "failed to read from world state: unable to retrieve incident")
}

// function for testing ReviewIncident
func TestReviewIncident(t *testing.T) {
	// Setup mock chaincode stub and transaction context
	chaincodeStub := &mocks.ChaincodeStub{}
	transactionContext := &mocks.TransactionContext{}
	transactionContext.GetStubReturns(chaincodeStub)

	// Prepare an incident to review
	existingIncident := chaincode.Incident{IncidentId: "incident1", Status: "Open"}
	bytes, _ := json.Marshal(existingIncident)
	chaincodeStub.GetStateReturns(bytes, nil)

	// Attempt to mark the incident as "In Review"
	incidentManagement := chaincode.SmartContract{}
	err := incidentManagement.ReviewIncident(transactionContext, "incident1")
	require.NoError(t, err)

	// Verify PutState was called with "In Review" status
	chaincodeStub.PutStateCalls(func(key string, value []byte) error {
		var incident chaincode.Incident
		json.Unmarshal(value, &incident)
		require.Equal(t, "In Review", incident.Status, "Incident status should be 'In Review'")
		return nil
	})
}

// function for testing ReadIncident
func TestReadIncident(t *testing.T) {
	// Setup mock chaincode stub and transaction context
	chaincodeStub := &mocks.ChaincodeStub{}
	transactionContext := &mocks.TransactionContext{}
	transactionContext.GetStubReturns(chaincodeStub)

	// Prepare an incident to read
	incident := chaincode.Incident{IncidentId: "incident1", Description: "Test incident"}
	bytes, _ := json.Marshal(incident)
	chaincodeStub.GetStateReturns(bytes, nil)

	// Attempt to read the incident
	incidentManagement := chaincode.SmartContract{}
	readIncident, err := incidentManagement.ReadIncident(transactionContext, "incident1")
	require.NoError(t, err)
	require.Equal(t, "Test incident", readIncident.Description, "The read incident should match the prepared incident")

	// Simulate an incident that does not exist
	chaincodeStub.GetStateReturns(nil, nil)
	_, err = incidentManagement.ReadIncident(transactionContext, "incident2")
	require.EqualError(t, err, "the incident incident2 does not exist")
}

// function for testing IncidentExits
func TestIncidentExists(t *testing.T) {
	// Setup mock chaincode stub and transaction context
	chaincodeStub := &mocks.ChaincodeStub{}
	transactionContext := &mocks.TransactionContext{}
	transactionContext.GetStubReturns(chaincodeStub)

	// Simulate an existing incident
	chaincodeStub.GetStateReturns([]byte("incident data"), nil)
	incidentManagement := chaincode.SmartContract{}
	exists, err := incidentManagement.IncidentExists(transactionContext, "incident1")
	require.NoError(t, err)
	require.True(t, exists, "Incident should exist")

	// Simulate a non-existent incident
	chaincodeStub.GetStateReturns(nil, nil)
	exists, err = incidentManagement.IncidentExists(transactionContext, "nonexistent")
	require.NoError(t, err)
	require.False(t, exists, "Incident should not exist")
}

// function for testing TestGetAllIncidentsByAffectedSystem (checks that incidents are correctly filtered by affected system)
func TestGetAllIncidentsByAffectedSystem(t *testing.T) {
	chaincodeStub := &mocks.ChaincodeStub{}
	transactionContext := &mocks.TransactionContext{}
	transactionContext.GetStubReturns(chaincodeStub)

	// Prepare mock data for incidents
	incident1 := chaincode.Incident{
		IncidentId:      "INC1001",
		AffectedSystems: []string{"ITSystemPeer1"},
		Issuer:          "ITSystemPeer2",
		SeverityLevel:   "High",
		Type:            "Security",
		DetectedTime:    time.Now(),
	}
	incident2 := chaincode.Incident{
		IncidentId:      "INC1002",
		AffectedSystems: []string{"ITSystemPeer2"},
		Issuer:          "ITTeamPeer",
		SeverityLevel:   "Medium",
		Type:            "Technical",
		DetectedTime:    time.Now(),
	}
	bytes1, _ := json.Marshal(incident1)
	bytes2, _ := json.Marshal(incident2)

	iterator := &mocks.StateQueryIterator{}
	chaincodeStub.GetStateByRangeReturns(iterator, nil) // Mock setup for iterator

	iterator.HasNextReturnsOnCall(0, true)
	iterator.NextReturnsOnCall(0, &queryresult.KV{Key: "INC1001", Value: bytes1}, nil)
	iterator.HasNextReturnsOnCall(1, true)
	iterator.NextReturnsOnCall(1, &queryresult.KV{Key: "INC1002", Value: bytes2}, nil)
	iterator.HasNextReturnsOnCall(2, false) // End of data simulation

	incidentManagement := &chaincode.SmartContract{}

	// Test filter by Affected System "ITSystemPeer1"
	incidents, err := incidentManagement.GetAllIncidentsByAffectedSystem(transactionContext, "ITSystemPeer1")
	require.NoError(t, err)
	require.Len(t, incidents, 1, "Expected one incident to be returned for ITSystemPeer1")
	require.Equal(t, "INC1001", incidents[0].IncidentId, "Expected incident ID to match INC1001")
}

// function for tetsing TestGetAllIncidentsByIssuer (checks that incidents are correctly filtered by issuer)
func TestGetAllIncidentsByIssuer(t *testing.T) {
	chaincodeStub := &mocks.ChaincodeStub{}
	transactionContext := &mocks.TransactionContext{}
	transactionContext.GetStubReturns(chaincodeStub)

	// Setup mock data for incidents
	incident1 := chaincode.Incident{
		IncidentId:      "INC1001",
		AffectedSystems: []string{"ITSystemPeer1"},
		Issuer:          "ITSystemPeer2",
		SeverityLevel:   "High",
		Type:            "Security",
		DetectedTime:    time.Now(),
	}
	incident2 := chaincode.Incident{
		IncidentId:      "INC1002",
		AffectedSystems: []string{"ITSystemPeer2"},
		Issuer:          "ITTeamPeer",
		SeverityLevel:   "Medium",
		Type:            "Technical",
		DetectedTime:    time.Now(),
	}
	bytes1, _ := json.Marshal(incident1)
	bytes2, _ := json.Marshal(incident2)

	iterator := &mocks.StateQueryIterator{}
	chaincodeStub.GetStateByRangeReturns(iterator, nil) // Mock setup for iterator

	iterator.HasNextReturnsOnCall(0, true)
	iterator.NextReturnsOnCall(0, &queryresult.KV{Key: "INC1001", Value: bytes1}, nil)
	iterator.HasNextReturnsOnCall(1, true)
	iterator.NextReturnsOnCall(1, &queryresult.KV{Key: "INC1002", Value: bytes2}, nil)
	iterator.HasNextReturnsOnCall(2, false) // End of data simulation

	incidentManagement := &chaincode.SmartContract{}

	// Test filter by Issuer "ITTeamPeer"
	incidents, err := incidentManagement.GetAllIncidentsByIssuer(transactionContext, "ITTeamPeer")
	require.NoError(t, err)
	require.Len(t, incidents, 1, "Expected one incident to be returned for ITTeamPeer")
	require.Equal(t, "INC1002", incidents[0].IncidentId, "Expected incident ID to match INC1002")
}

// function for testing TestGetAllIncidentsByType (checks that incidents are correctly filtered by type)
func TestGetAllIncidentsByType(t *testing.T) {
	chaincodeStub := &mocks.ChaincodeStub{}
	transactionContext := &mocks.TransactionContext{}
	transactionContext.GetStubReturns(chaincodeStub)

	// Setup mock data for incidents
	incident1 := chaincode.Incident{
		IncidentId:      "INC1001",
		AffectedSystems: []string{"ITSystemPeer1"},
		Issuer:          "ITSystemPeer2",
		SeverityLevel:   "High",
		Type:            "Security",
		DetectedTime:    time.Now(),
	}
	incident2 := chaincode.Incident{
		IncidentId:      "INC1002",
		AffectedSystems: []string{"ITSystemPeer2"},
		Issuer:          "ITTeamPeer",
		SeverityLevel:   "Medium",
		Type:            "Technical",
		DetectedTime:    time.Now(),
	}
	bytes1, _ := json.Marshal(incident1)
	bytes2, _ := json.Marshal(incident2)

	iterator := &mocks.StateQueryIterator{}
	chaincodeStub.GetStateByRangeReturns(iterator, nil) // Mock setup for iterator

	iterator.HasNextReturnsOnCall(0, true)
	iterator.NextReturnsOnCall(0, &queryresult.KV{Key: "INC1001", Value: bytes1}, nil)
	iterator.HasNextReturnsOnCall(1, true)
	iterator.NextReturnsOnCall(1, &queryresult.KV{Key: "INC1002", Value: bytes2}, nil)
	iterator.HasNextReturnsOnCall(2, false) // End of data simulation

	incidentManagement := &chaincode.SmartContract{}

	// Test filter by Type "Security"
	incidents, err := incidentManagement.GetAllIncidentsByType(transactionContext, "Security")
	require.NoError(t, err)
	require.Len(t, incidents, 1, "Expected one incident to be returned for Type Security")
	require.Equal(t, "INC1001", incidents[0].IncidentId, "Expected incident ID to match INC1001")
}

// function for testing TestGetAllIncidentsBySeverity (checks that incidents are correctly filtered by severity)
func TestGetAllIncidentsBySeverity(t *testing.T) {
	chaincodeStub := &mocks.ChaincodeStub{}
	transactionContext := &mocks.TransactionContext{}
	transactionContext.GetStubReturns(chaincodeStub)

	// Prepare mock data for incidents
	incident1 := chaincode.Incident{
		IncidentId:      "INC1001",
		AffectedSystems: []string{"ITSystemPeer1"},
		Issuer:          "ITSystemPeer2",
		SeverityLevel:   "High",
		Type:            "Security",
		DetectedTime:    time.Now(),
	}
	incident2 := chaincode.Incident{
		IncidentId:      "INC1002",
		AffectedSystems: []string{"ITSystemPeer2"},
		Issuer:          "ITTeamPeer",
		SeverityLevel:   "Medium",
		Type:            "Technical",
		DetectedTime:    time.Now(),
	}
	bytes1, _ := json.Marshal(incident1)
	bytes2, _ := json.Marshal(incident2)

	iterator := &mocks.StateQueryIterator{}
	chaincodeStub.GetStateByRangeReturns(iterator, nil) // Mock setup for iterator

	iterator.HasNextReturnsOnCall(0, true)
	iterator.NextReturnsOnCall(0, &queryresult.KV{Key: "INC1001", Value: bytes1}, nil)
	iterator.HasNextReturnsOnCall(1, true)
	iterator.NextReturnsOnCall(1, &queryresult.KV{Key: "INC1002", Value: bytes2}, nil)
	iterator.HasNextReturnsOnCall(2, false) // End of data simulation

	incidentManagement := &chaincode.SmartContract{}

	// Test filter by Severity "High"
	incidents, err := incidentManagement.GetAllIncidentsBySeverity(transactionContext, "High")
	require.NoError(t, err)
	require.Len(t, incidents, 1, "Expected one incident to be returned for Severity High")
	require.Equal(t, "INC1001", incidents[0].IncidentId, "Expected incident ID to match INC1001")
}
