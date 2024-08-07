package chaincode_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/hyperledger/fabric-samples/asset-transfer-basic/chaincode-go/chaincode"
	"github.com/hyperledger/fabric-samples/asset-transfer-basic/chaincode-go/chaincode/mocks"
	"github.com/stretchr/testify/require"
)

// Define a structure for the report for simplicity in this example
type Report struct {
	ReportID   string               `json:"reportId"`
	CreatedAt  time.Time            `json:"createdAt"`
	ReportType string               `json:"reportType"`
	Incidents  []chaincode.Incident `json:"incidents"`
}

// TestCreateReport tests the report creation functionality in Chaincode 2
func TestCreateReport(t *testing.T) {
	stub := &mocks.ChaincodeStub{}
	ctx := &mocks.TransactionContext{}
	ctx.GetStubReturns(stub)

	c := chaincode.ReportContract{}

	// Prepare a sample incident to include in the report
	incident := chaincode.Incident{
		IncidentId:    "INC001",
		Description:   "Sample Incident",
		SeverityLevel: "Critical",
		Status:        "Resolved",
		Type:          "Security",
		DetectedTime:  time.Now(),
	}
	incidents := []chaincode.Incident{incident}
	incidentData, _ := json.Marshal(incidents)

	// Test the CreateReport function
	reportID := "Report_001"
	stub.PutStateReturns(nil) // Simulate successful state update

	result, err := c.CreateCriticalIncidentsReport(ctx, string(incidentData))
	require.NoError(t, err, "Creating a report should not produce an error")

	// Validate the stored report data
	require.Contains(t, result, reportID, "The result should contain the correct report ID")

	// Check that the data was stored correctly
	stub.PutStateCalls(func(key string, value []byte) error {
		var storedReport Report
		json.Unmarshal(value, &storedReport)
		require.Equal(t, reportID, storedReport.ReportID, "Stored report ID should match the generated ID")
		require.Len(t, storedReport.Incidents, 1, "Stored report should contain one incident")
		return nil
	})

	// Test error handling for storage failure
	stub.PutStateReturns(fmt.Errorf("failed to store report"))
	_, err = c.CreateCriticalIncidentsReport(ctx, string(incidentData))
	require.Error(t, err, "Expected an error when storing the report fails")
}
